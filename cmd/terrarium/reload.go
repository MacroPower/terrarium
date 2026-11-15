//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/dnsproxy"
	"go.jacobcolvin.com/terrarium/eventstore"
	"go.jacobcolvin.com/terrarium/firewall"
	"go.jacobcolvin.com/terrarium/sysctl"
)

var (
	// ErrNotRoot indicates a root-only operation was attempted by a
	// non-root user.
	ErrNotRoot = fmt.Errorf("must be run as root")

	// ErrDaemonNotRunning indicates the PID file references a process
	// that is no longer alive.
	ErrDaemonNotRunning = fmt.Errorf("daemon not running")

	// ErrReloadRejected means that a reload of the daemon stopped
	// before it installed a CA certificate or replaced a running part.
	// The daemon still runs the rules, the DNS proxy, and the Envoy of
	// the previous config. The trust store still holds the CA
	// certificate of that Envoy.
	ErrReloadRejected = errors.New("reload rejected")

	// ErrReloadNFLogGroupChanged is returned by
	// [validateStartupOnlyStatsChanges] when the new config requests a
	// different nflog group than the running reader is bound to.
	ErrReloadNFLogGroupChanged = errors.New("stats.firewall.nflogGroup change requires restart")
)

// DaemonReload triggers a live configuration reload of the running
// terrarium daemon. It pre-validates the config at usr.ConfigPath so
// obviously broken YAML never reaches the daemon, then sends SIGHUP
// to the PID recorded in pidFile. The daemon re-reads the config
// independently on receipt of SIGHUP; DaemonReload only polls to
// confirm the daemon stayed alive after the signal.
//
// The daemon exits when a reload stops after it started to replace the
// installed CA certificate, the running rules, the DNS proxy, or
// Envoy. DaemonReload returns an error when the daemon exits during
// the 5 seconds of the poll. A reload that waits longer for the new
// Envoy can end the daemon after DaemonReload returned nil.
func DaemonReload(ctx context.Context, usr *config.User, pidFile string) error {
	if os.Getuid() != 0 {
		return ErrNotRoot
	}

	// Pre-validate config before signaling the daemon.
	data, err := os.ReadFile(usr.ConfigPath)
	if err != nil {
		return fmt.Errorf("reading config: %w", err)
	}

	_, err = config.ParseConfig(ctx, data)
	if err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}

	// Read PID file and verify the daemon is alive.
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		return fmt.Errorf("reading PID file: %w", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil {
		return fmt.Errorf("parsing PID file: %w", err)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDaemonNotRunning, err)
	}

	// Signal 0 checks if the process exists without sending a real signal.
	err = proc.Signal(syscall.Signal(0))
	if err != nil {
		return fmt.Errorf("%w (pid %d): %w", ErrDaemonNotRunning, pid, err)
	}

	slog.InfoContext(ctx, "sending SIGHUP to terrarium daemon", slog.Int("pid", pid))

	err = proc.Signal(syscall.SIGHUP)
	if err != nil {
		return fmt.Errorf("sending SIGHUP: %w", err)
	}

	// Poll to confirm the daemon is still alive after reload.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)

		err = proc.Signal(syscall.Signal(0))
		if err != nil {
			return fmt.Errorf("daemon exited during reload (pid %d): %w", pid, err)
		}
	}

	slog.InfoContext(ctx, "daemon reload signaled successfully")

	return nil
}

// reloadInputs holds what [prepareReload] reads and creates for one
// reload before [replaceInfrastructure] replaces a running part.
type reloadInputs struct {
	cfg *config.Config

	// The connection that applies the firewall rules.
	conn *nftables.Conn

	// The connection that the DNS proxy updates the FQDN sets through.
	// It is separate from conn to avoid batching conflicts with the
	// rule setup.
	dnsConn *nftables.Conn

	// The upstream DNS server from /etc/resolv.conf.
	upstream string
}

// reloadInfrastructure re-reads the config and replaces the installed
// CA certificate, the nftables rules, the DNS proxy, and Envoy of inf.
// The SIGHUP handler of the daemon calls it.
//
// The reload has two phases, which [runReloadPhases] runs in order.
// The error tells the caller which phase stopped the reload:
//
//   - [prepareReload] reads and validates the new config. An error
//     from that phase wraps [ErrReloadRejected]. The daemon still
//     runs the rules, the DNS proxy, and the Envoy that it ran before
//     the reload, and the trust store still holds the CA certificate
//     of that Envoy, so the caller keeps running.
//   - [replaceInfrastructure] installs the new CA certificate and
//     replaces the running parts. Every other error comes from that
//     phase. The daemon is then between the two configs, so the
//     caller must shut down. The nftables rules or the guard table
//     keep the VM fail-closed.
//
// After an error from [replaceInfrastructure], reloadInfrastructure
// removes the Envoy bootstrap that [prepareReload] generated. See
// [removeEnvoyBootstrap] for the reason.
//
// After each return, every part that inf names runs.
func reloadInfrastructure(ctx context.Context, usr *config.User, uids firewall.UIDs, inf *infra) error {
	slog.InfoContext(ctx, "reloading terrarium configuration")

	err := runReloadPhases(
		func() (*reloadInputs, error) {
			return prepareReload(ctx, usr, uids, inf.boundStats)
		},
		func(in *reloadInputs) error {
			return replaceInfrastructure(ctx, usr, uids, inf, in)
		},
		func() {
			err := removeEnvoyBootstrap(usr.EnvoyConfigPath)
			if err != nil {
				slog.ErrorContext(ctx, "discarding the configs of the incomplete reload", slog.Any("err", err))
			}
		},
	)
	if err != nil {
		return err
	}

	slog.InfoContext(ctx, "terrarium configuration reloaded successfully")

	return nil
}

// runReloadPhases runs the two phases of a reload. It calls prepare
// and passes the inputs that prepare returns to replace.
//
// The error names the phase that stopped the reload:
//
//   - An error from prepare wraps [ErrReloadRejected], and
//     runReloadPhases does not call replace.
//   - runReloadPhases returns an error from replace as it is. That
//     error never wraps [ErrReloadRejected], so the caller does not
//     keep a daemon that runs between two configs.
//
// runReloadPhases calls discard only after an error from replace. The
// daemon then exits, and discard removes what prepare generated, so
// the next start of the daemon does not reuse it. After an error from
// prepare, the daemon keeps running, and the next reload generates
// the configs again.
func runReloadPhases(
	prepare func() (*reloadInputs, error), replace func(*reloadInputs) error, discard func(),
) error {
	in, err := prepare()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrReloadRejected, err)
	}

	err = replace(in)
	if err != nil {
		discard()

		return err
	}

	return nil
}

// removeEnvoyBootstrap removes the generated Envoy bootstrap at path.
// A bootstrap that does not exist is not an error.
//
// [setupInfrastructure] generates the configs only when the bootstrap
// does not exist. The daemon therefore removes the bootstrap that it
// generated when it exits because it cannot run the generated
// configs. The next start of the daemon then generates the configs
// from the config file as it is at that time. A corrected config
// file therefore takes effect. With the bootstrap in place, every
// restart loads the bootstrap of the config that the daemon cannot
// run.
func removeEnvoyBootstrap(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing envoy bootstrap: %w", err)
	}

	return nil
}

// prepareReload generates the configs from the config file, validates
// the new config against bound, and reads the upstream DNS server. It
// does not install the CA certificate and it replaces no running
// part. When prepareReload returns an error, the daemon runs
// unchanged and the trust store still holds the CA certificate that
// signed the certificates of the running Envoy.
//
// The steps that depend only on the config file run first. A reload
// that those steps reject reads nothing else from the host, and it
// does not change the mode of a directory.
//
// It does write files. [Generate] replaces the Envoy bootstrap, the
// CA certificate in usr.CADir, and the certificates in usr.CertsDir.
// The running Envoy keeps the bootstrap and the certificates that it
// loaded at its start.
func prepareReload(
	ctx context.Context, usr *config.User, uids firewall.UIDs, bound boundStats,
) (*reloadInputs, error) {
	cfg, err := Generate(ctx, usr, uids.VMMode)
	if err != nil {
		return nil, fmt.Errorf("generating configs: %w", err)
	}

	// Reject startup-only changes the running process cannot adopt.
	// Validate before ApplyRules so the firewall is never updated
	// to emit on a group the running reader is not bound to.
	err = validateStartupOnlyStatsChanges(ctx, bound, cfg)
	if err != nil {
		return nil, err
	}

	// Re-read upstream DNS from resolv.conf.
	resolvData, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}

	err = ensurePathTraversable(usr.EnvoyConfigPath)
	if err != nil {
		return nil, fmt.Errorf("making envoy config path traversable: %w", err)
	}

	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("creating nftables connection: %w", err)
	}

	dnsConn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("creating DNS proxy nftables connection: %w", err)
	}

	return &reloadInputs{
		cfg:      cfg,
		conn:     conn,
		dnsConn:  dnsConn,
		upstream: ParseUpstreamDNS(string(resolvData)),
	}, nil
}

// replaceInfrastructure installs the CA certificate that
// [prepareReload] generated and applies the nftables rules of in. It
// then replaces the DNS proxy and Envoy of inf with ones that run the
// config of in.
//
// It stops at the first step that does not succeed and returns the
// error of that step. The daemon is then between the two configs. The
// trust store can hold a CA certificate that did not sign the
// certificates of the running Envoy. The rules can be missing, and
// the DNS proxy or Envoy can have stopped without a replacement.
//
// Every part that inf names still runs. [replaceDNSProxy] and
// [replaceEnvoy] each clear a part from inf when they stop the part,
// and they store the replacement in inf when the replacement runs.
func replaceInfrastructure(
	ctx context.Context, usr *config.User, uids firewall.UIDs, inf *infra, in *reloadInputs,
) error {
	cfg := in.cfg

	// Install the CA cert if MITM certs were generated. Until this
	// function replaces Envoy, the running Envoy serves certificates
	// of the previous CA. The install therefore belongs to the phase
	// whose errors shut the daemon down.
	caCertPath := usr.CADir + "/ca.pem"

	_, err := os.Stat(caCertPath)
	if err == nil {
		err = installCA(ctx, caCertPath)
		if err != nil {
			return fmt.Errorf("installing CA: %w", err)
		}

		if uids.VMMode {
			err = copyFile(caCertPath, caContainerTrustPath)
			if err != nil {
				return fmt.Errorf("copying CA for container trust: %w", err)
			}
		}
	}

	// Check IPv6 state.
	sys := sysctl.New()
	ipv6Disabled := verifyIPv6State(ctx, sys)

	if ipv6Disabled {
		disableIPv6(ctx, sys)
	}

	needsEnvoy := !cfg.IsEgressBlocked()
	envoySettings := cfg.EnvoyDefaults()

	// ApplyRules deletes the terrarium table before it applies the new
	// rules atomically, so the previous rules are gone when it returns
	// an error.
	err = firewall.ApplyRules(ctx, in.conn, cfg, uids)
	if err != nil {
		return fmt.Errorf("applying firewall rules: %w", err)
	}

	inf.conn = in.conn

	// Re-run policy routing (idempotent: delete-then-add / RouteReplace).
	if needsEnvoy {
		err = firewall.SetupPolicyRouting(ctx, sys)
		if err != nil {
			return fmt.Errorf("setting up policy routing: %w", err)
		}
	}

	// Forward routing is always needed in VM mode (idempotent sysctl write).
	err = firewall.SetupForwardRouting(sys)
	if err != nil {
		return fmt.Errorf("setting up forward routing: %w", err)
	}

	dnsOpts := []dnsproxy.Option{
		dnsproxy.WithFQDNSetFunc(func(ctx context.Context, setName string, ips []net.IP, ttl time.Duration) error {
			return firewall.UpdateFQDNSet(in.dnsConn, setName, ips, ttl)
		}),
		dnsproxy.WithVMMode(),
		// Reuse the existing eventstore handle; stats.path,
		// stats.socket, stats.enabled are startup-only.
		dnsproxy.WithEventStore(inf.eventStore),
		// Reuse the existing reverse cache so attribution state
		// survives reload. The cache is never recreated here.
		dnsproxy.WithReverseCache(inf.dnsCache),
	}

	warnStartupOnlyStatsChanges(ctx, inf.boundStats, cfg)

	// Apply any retention changes from the new config to the
	// existing store (lock-free swap on the writer goroutine).
	if inf.eventStore != nil {
		perSource := cfg.StatsRetentionPerSource()
		inf.eventStore.SetRetention(eventstore.Retention{
			MaxAge:  cfg.StatsRetentionMaxAge(),
			MaxRows: cfg.StatsRetentionMaxRows(),
			PerSource: eventstore.PerSourceCaps{
				Firewall: perSource.Firewall,
				DNS:      perSource.DNS,
				Envoy:    perSource.Envoy,
			},
		})
	}

	// Stop the old DNS proxy and start a new one.
	err = replaceDNSProxy(ctx, inf, func() (*dnsproxy.Proxy, error) {
		return dnsproxy.Start(ctx, cfg, net.JoinHostPort(in.upstream, "53"), "127.0.0.1:53", ipv6Disabled,
			dnsOpts...,
		)
	})
	if err != nil {
		return err
	}

	// Stop the old Envoy, and start a new one when the new config
	// needs Envoy.
	var start func() (*exec.Cmd, error)

	if needsEnvoy {
		start = func() (*exec.Cmd, error) {
			return startEnvoy(ctx, usr, envoySettings, cfg)
		}
	}

	err = replaceEnvoy(ctx, inf, envoySettings.DrainTimeout.Duration, start)
	if err != nil {
		return err
	}

	// Best-effort conntrack flush to clear stale DNAT entries.
	err = netlink.ConntrackTableFlush(netlink.ConntrackTable)
	if err != nil {
		slog.DebugContext(ctx, "flushing conntrack after reload", slog.Any("err", err))
	}

	return nil
}

// replaceDNSProxy stops the DNS proxy of inf and then calls start to
// start its replacement. The replacement listens on the address of
// the proxy that it replaces, so the stop comes first.
//
// When replaceDNSProxy returns, inf names the DNS proxy that runs.
// When start returns an error, replaceDNSProxy returns an error that
// wraps it. No DNS proxy runs then, so inf names none.
func replaceDNSProxy(ctx context.Context, inf *infra, start func() (*dnsproxy.Proxy, error)) error {
	stopDNSProxy(ctx, inf.dnsProxy)

	inf.dnsProxy = nil

	proxy, err := start()
	if err != nil {
		return fmt.Errorf("starting DNS proxy: %w", err)
	}

	inf.dnsProxy = proxy

	return nil
}

// replaceEnvoy stops the Envoy of inf and then calls start to start
// its replacement, which drains for up to drainTimeout when the
// daemon stops it. A nil start means that the new config does not
// need Envoy, so replaceEnvoy only stops the Envoy of inf.
//
// When replaceEnvoy returns, inf names the Envoy that runs. When
// start returns an error, replaceEnvoy returns that error and no
// Envoy runs, so inf names none.
func replaceEnvoy(
	ctx context.Context, inf *infra, drainTimeout time.Duration, start func() (*exec.Cmd, error),
) error {
	stopEnvoy(ctx, inf.envoyCmd, inf.drainTimeout)

	inf.envoyCmd = nil
	inf.drainTimeout = drainTimeout

	if start == nil {
		return nil
	}

	cmd, err := start()
	if err != nil {
		return err
	}

	inf.envoyCmd = cmd

	return nil
}

// validateStartupOnlyStatsChanges returns an error when the new
// config requests a value for a startup-only stats field that the
// running process cannot rebind without dropping events. Only
// `stats.firewall.nflogGroup` is fatal here; path, socket, and
// enabled keep the warn-and-continue semantics in
// [warnStartupOnlyStatsChanges] because they bind to the eventstore
// handle and gRPC ALS UDS, which the running process cannot rebind.
//
// Called before [firewall.ApplyRules] so a rejected reload never
// updates the running rules. The reader continues consuming on the
// originally-bound group; restart to adopt a new value.
func validateStartupOnlyStatsChanges(_ context.Context, bound boundStats, cfg *config.Config) error {
	if bound.enabled && bound.nflogGroup != cfg.StatsFirewallNFLogGroup() {
		return fmt.Errorf("%w: bound=%d requested=%d",
			ErrReloadNFLogGroupChanged,
			bound.nflogGroup, cfg.StatsFirewallNFLogGroup())
	}

	return nil
}

// warnStartupOnlyStatsChanges logs a warning when the new YAML
// changes a stats field the running process cannot adopt without a
// restart: the SQLite path, the gRPC ALS UDS, or whether stats is
// enabled at all. Retention values are runtime-mutable and are not
// flagged here. The nflog group is enforced fatally by
// [validateStartupOnlyStatsChanges] before this runs.
func warnStartupOnlyStatsChanges(ctx context.Context, bound boundStats, cfg *config.Config) {
	newEnabled := cfg.StatsEnabled()
	if bound.enabled != newEnabled {
		slog.WarnContext(ctx,
			"reload: stats.enabled change ignored (restart required)",
			slog.Bool("bound", bound.enabled),
			slog.Bool("requested", newEnabled))
	}

	newPath := cfg.StatsPath(config.StatsDBDefault())
	if bound.enabled && bound.path != newPath {
		slog.WarnContext(ctx,
			"reload: stats.path change ignored (restart required)",
			slog.String("bound", bound.path),
			slog.String("requested", newPath))
	}

	newSocket := cfg.StatsSocket(config.DefaultStatsSocket)
	if bound.enabled && bound.socket != newSocket {
		slog.WarnContext(ctx,
			"reload: stats.socket change ignored (restart required)",
			slog.String("bound", bound.socket),
			slog.String("requested", newSocket))
	}
}

// writePIDFile writes the current process ID to the given path.
func writePIDFile(path string) error {
	data := strconv.Itoa(os.Getpid())

	err := os.WriteFile(path, []byte(data), 0o644) //nolint:gosec // G306: PID files are world-readable.
	if err != nil {
		return fmt.Errorf("writing PID file: %w", err)
	}

	return nil
}
