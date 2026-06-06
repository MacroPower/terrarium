package main

import (
	"context"
	"fmt"
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

	// ErrReloadNFLogGroupChanged is returned by
	// [validateStartupOnlyStatsChanges] when the new config requests a
	// different nflog group than the running reader is bound to.
	ErrReloadNFLogGroupChanged = fmt.Errorf("reload: stats.firewall.nflogGroup change requires restart")
)

// DaemonReload triggers a live configuration reload of the running
// terrarium daemon. It pre-validates the config at usr.ConfigPath so
// obviously broken YAML never reaches the daemon, then sends SIGHUP
// to the PID recorded in pidFile. The daemon re-reads the config
// independently on receipt of SIGHUP; DaemonReload only polls to
// confirm the daemon stayed alive after the signal.
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

// reloadInfrastructure re-reads the config and reapplies all
// infrastructure components: nftables rules, DNS proxy, and Envoy.
// It is called from the daemon's SIGHUP handler. On failure, the
// guard table keeps the VM safe; the user fixes the config and
// sends another SIGHUP.
func reloadInfrastructure(ctx context.Context, usr *config.User, uids firewall.UIDs, inf *infra) {
	slog.InfoContext(ctx, "reloading terrarium configuration")

	// Re-read upstream DNS from resolv.conf.
	resolvData, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		slog.ErrorContext(ctx, "reload: reading /etc/resolv.conf", slog.Any("err", err))

		return
	}

	upstream := ParseUpstreamDNS(string(resolvData))

	cfg, err := Generate(ctx, usr, uids.VMMode)
	if err != nil {
		slog.ErrorContext(ctx, "reload: generating configs", slog.Any("err", err))

		return
	}

	err = ensurePathTraversable(usr.EnvoyConfigPath)
	if err != nil {
		slog.ErrorContext(ctx, "reload: making envoy config path traversable", slog.Any("err", err))

		return
	}

	// Install CA cert if MITM certs were generated.
	caCertPath := usr.CADir + "/ca.pem"

	_, statErr := os.Stat(caCertPath)
	if statErr == nil {
		err = installCA(ctx, caCertPath)
		if err != nil {
			slog.ErrorContext(ctx, "reload: installing CA", slog.Any("err", err))

			return
		}

		if uids.VMMode {
			err = copyFile(caCertPath, "/etc/terrarium/ca.pem")
			if err != nil {
				slog.ErrorContext(ctx, "reload: copying CA for container trust", slog.Any("err", err))

				return
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

	// Reject startup-only changes the running process cannot adopt.
	// Validate before ApplyRules so the firewall is never updated
	// to emit on a group the running reader is not bound to.
	err = validateStartupOnlyStatsChanges(ctx, inf.boundStats, cfg)
	if err != nil {
		slog.ErrorContext(ctx, "reload: rejected", slog.Any("err", err))

		return
	}

	// Apply nftables rules atomically.
	conn, err := nftables.New()
	if err != nil {
		slog.ErrorContext(ctx, "reload: creating nftables connection", slog.Any("err", err))

		return
	}

	err = firewall.ApplyRules(ctx, conn, cfg, uids)
	if err != nil {
		slog.ErrorContext(ctx, "reload: applying firewall rules", slog.Any("err", err))

		return
	}

	// Re-run policy routing (idempotent: delete-then-add / RouteReplace).
	if needsEnvoy {
		err = firewall.SetupPolicyRouting(ctx, sys)
		if err != nil {
			slog.ErrorContext(ctx, "reload: setting up policy routing", slog.Any("err", err))

			return
		}
	}

	// Forward routing is always needed in VM mode (idempotent sysctl write).
	err = firewall.SetupForwardRouting(sys)
	if err != nil {
		slog.ErrorContext(ctx, "reload: setting up forward routing", slog.Any("err", err))

		return
	}

	// Stop old DNS proxy and start a new one.
	stopDNSProxy(ctx, inf.dnsProxy)

	dnsConn, err := nftables.New()
	if err != nil {
		slog.ErrorContext(ctx, "reload: creating DNS proxy nftables connection", slog.Any("err", err))

		return
	}

	dnsOpts := []dnsproxy.Option{
		dnsproxy.WithFQDNSetFunc(func(ctx context.Context, setName string, ips []net.IP, ttl time.Duration) error {
			return firewall.UpdateFQDNSet(dnsConn, setName, ips, ttl)
		}),
		dnsproxy.WithVMMode(),
		// Reuse the existing eventstore handle. stats.path,
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

	dnsProxy, err := dnsproxy.Start(ctx, cfg, net.JoinHostPort(upstream, "53"), "127.0.0.1:53", ipv6Disabled,
		dnsOpts...,
	)
	if err != nil {
		slog.ErrorContext(ctx, "reload: starting DNS proxy", slog.Any("err", err))

		return
	}

	// Stop old Envoy and start a new one if needed.
	stopEnvoy(ctx, inf.envoyCmd, inf.drainTimeout)

	var envoyCmd *exec.Cmd

	if needsEnvoy {
		envoyCmd, err = startEnvoy(ctx, usr, envoySettings, cfg)
		if err != nil {
			slog.ErrorContext(ctx, "reload: starting envoy", slog.Any("err", err))

			return
		}
	}

	// Best-effort conntrack flush to clear stale DNAT entries.
	err = netlink.ConntrackTableFlush(netlink.ConntrackTable)
	if err != nil {
		slog.DebugContext(ctx, "reload: flushing conntrack", slog.Any("err", err))
	}

	// Update infra in place.
	inf.envoyCmd = envoyCmd
	inf.dnsProxy = dnsProxy
	inf.conn = conn
	inf.drainTimeout = envoySettings.DrainTimeout.Duration

	slog.InfoContext(ctx, "terrarium configuration reloaded successfully")
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

	newSocket := cfg.StatsSocket()
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
