package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/nftables"

	"go.jacobcolvin.com/terrarium/accesslog"
	"go.jacobcolvin.com/terrarium/certs"
	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/dnscache"
	"go.jacobcolvin.com/terrarium/dnsproxy"
	"go.jacobcolvin.com/terrarium/eventstore"
	"go.jacobcolvin.com/terrarium/firewall"
	"go.jacobcolvin.com/terrarium/nflog"
	"go.jacobcolvin.com/terrarium/sysctl"
)

// ExitError carries a child process exit code through the error
// return path so the CLI entrypoint can propagate it to [os.Exit].
type ExitError struct{ Code int }

// Error returns a human-readable representation of the exit status.
func (e *ExitError) Error() string {
	return fmt.Sprintf("exit status %d", e.Code)
}

var (
	// ErrNoCommand is returned when Init is called without a command to exec.
	ErrNoCommand = errors.New("no command specified")

	// ErrIPv6Unsecured is returned when IPv6 rules failed to load but IPv6
	// is still enabled on the host.
	ErrIPv6Unsecured = errors.New("IPv6 rules not loaded and IPv6 still enabled")

	// ErrEnvoyNotRunning is returned when the Envoy proxy process exits
	// or cannot be signaled after startup.
	ErrEnvoyNotRunning = errors.New("envoy process not running")
)

// ParseUpstreamDNS extracts the first usable nameserver IP from
// resolv.conf content. It skips 127.0.0.1 and ::1 because those are
// the DNS proxy's own listen addresses -- using them as upstream would
// create a forwarding loop. Other loopback addresses like 127.0.0.53
// (dnsmasq) are valid upstreams and are not skipped. It returns the
// empty string when no usable nameserver is found.
func ParseUpstreamDNS(resolvConf string) string {
	for line := range strings.SplitSeq(resolvConf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				addr := fields[1]
				if addr == "127.0.0.1" || addr == "::1" {
					continue
				}

				return addr
			}
		}
	}

	return ""
}

// infra holds the running infrastructure components started by
// [setupInfrastructure]. The caller owns cleanup via [shutdown].
type infra struct {
	envoyCmd      *exec.Cmd
	dnsProxy      *dnsproxy.Proxy
	eventStore    *eventstore.Store
	accessLog     *accesslog.Server
	conn          firewall.Conn
	dnsCache      *dnscache.Cache
	nflogReader   *nflog.Reader
	nflogCancel   context.CancelFunc
	heartbeatStop context.CancelFunc

	// boundStats records the stats config the [eventstore.Store]
	// and [accesslog.Server] were bound to at process start. Reload
	// diffs against it and warns on path/socket/enabled changes,
	// which require a process restart.
	boundStats boundStats

	drainTimeout time.Duration
}

// boundStats holds the startup-only fields of the stats config. path
// and socket name the on-disk database and gRPC ALS UDS, which a
// running process cannot rebind; enabled gates both. Buffer sizing is
// omitted because reload always restarts Envoy.
//
// nflogGroup is captured from [config.Config.StatsFirewallNFLogGroup]
// at bind time. A running reader cannot rebind the netlink socket
// without dropping events, so reload rejects the new config when this
// changes.
type boundStats struct {
	path       string
	socket     string
	nflogGroup uint16
	enabled    bool
}

// setupInfrastructure performs the shared initialization sequence:
// generate configs, apply nftables rules, start DNS proxy, and start
// Envoy. On success the caller owns cleanup via [shutdown]. On error,
// all resources are cleaned up before returning.
func setupInfrastructure(ctx context.Context, usr *config.User, uids firewall.UIDs) (*infra, error) {
	// Capture upstream DNS from resolv.conf.
	resolvData, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}

	upstream := ParseUpstreamDNS(string(resolvData))

	// Generate configs at runtime if not pre-baked. The parsed config
	// is returned so we can reuse it below without re-parsing.
	var cfg *config.Config

	_, err = os.Stat(usr.EnvoyConfigPath)
	if os.IsNotExist(err) {
		slog.InfoContext(ctx, "generating firewall configs")

		cfg, err = Generate(ctx, usr, uids.VMMode)
		if err != nil {
			return nil, fmt.Errorf("generating configs: %w", err)
		}

		// Ensure every directory in the config path is world-executable
		// so the envoy user (which runs as a different UID) can traverse
		// to the config file. This is needed because home directories
		// like /root are typically 0700.
		err = ensurePathTraversable(usr.EnvoyConfigPath)
		if err != nil {
			return nil, fmt.Errorf("making envoy config path traversable: %w", err)
		}
	}

	// Install CA cert into trust store if MITM certs were generated.
	caCertPath := usr.CADir + "/ca.pem"

	_, err = os.Stat(caCertPath)
	if err == nil {
		slog.InfoContext(ctx, "installing terrarium CA into trust store")

		err := installCA(ctx, caCertPath)
		if err != nil {
			return nil, err
		}

		// VM mode: copy CA to a well-known path so containerd and
		// containers can be configured to trust it. Containerd
		// registry access requires hosts.toml to reference this path;
		// application containers need it volume-mounted or built in.
		if uids.VMMode {
			err = copyFile(caCertPath, "/etc/terrarium/ca.pem")
			if err != nil {
				return nil, fmt.Errorf("copying CA for container trust: %w", err)
			}
		}
	}

	// Parse config if Generate() was not called (pre-baked configs).
	if cfg == nil {
		cfgData, err := os.ReadFile(usr.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("reading terrarium config: %w", err)
		}

		cfg, err = config.ParseConfig(ctx, cfgData)
		if err != nil {
			return nil, fmt.Errorf("parsing terrarium config: %w", err)
		}
	}

	envoySettings := cfg.EnvoyDefaults()

	needsEnvoy := !cfg.IsEgressBlocked()

	// Apply nftables firewall rules atomically via netlink.
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("creating nftables connection: %w", err)
	}

	// VM mode: verify boot-time tables exist before any rule swap.
	// Run before ApplyRules deletes and recreates the terrarium table.
	if uids.VMMode {
		firewall.CheckBootTables(ctx, conn)
	}

	// Open the event store before binding nflog or applying rules.
	// A failure here logs and disables ingestion. The data plane
	// never blocks on stats.
	store := openEventStore(ctx, cfg, usr, uids)

	var storeCleanedUp bool

	defer func() {
		if storeCleanedUp {
			return
		}

		closeErr := store.Close()
		if closeErr != nil {
			slog.DebugContext(ctx, "closing event store on init failure", slog.Any("err", closeErr))
		}
	}()

	// Reverse-attribution cache for nflog ingestion. Lives on
	// [*infra] so it survives reload (the recreated DNS proxy gets
	// the same cache reference).
	dnsCache := dnscache.New()

	var dnsCacheCleanedUp bool

	defer func() {
		if dnsCacheCleanedUp {
			return
		}

		dnsCache.Close()
	}()

	// Bind the nflog reader before ApplyRules so the kernel has a
	// netlink listener as soon as the new `log group N prefix`
	// rules go live. Without it, early packets are silently
	// dropped. Bind failure is fatal in daemon mode (vmMode=true)
	// and tolerated in init mode.
	nflogReader, nflogCancel, err := openNflog(ctx, cfg, store, dnsCache, uids.VMMode)
	if err != nil {
		return nil, fmt.Errorf("opening nflog reader: %w", err)
	}

	var nflogCleanedUp bool

	defer func() {
		if nflogCleanedUp {
			return
		}

		if nflogCancel != nil {
			nflogCancel()
		}

		if nflogReader != nil {
			closeErr := nflogReader.Close()
			if closeErr != nil {
				slog.DebugContext(ctx, "closing nflog reader on init failure", slog.Any("err", closeErr))
			}
		}
	}()

	slog.InfoContext(ctx, "applying nftables firewall rules")

	err = firewall.ApplyRules(ctx, conn, cfg, uids)
	if err != nil {
		return nil, fmt.Errorf("applying firewall rules: %w", err)
	}

	// Clean up firewall on error return so a restart in the same
	// network namespace starts with clean state.
	var firewallCleanedUp bool

	defer func() {
		if firewallCleanedUp {
			return
		}

		if needsEnvoy {
			firewall.CleanupPolicyRouting(ctx)
		}

		cleanupErr := firewall.Cleanup(ctx, conn)
		if cleanupErr != nil {
			slog.DebugContext(ctx, "cleaning up firewall on init failure", slog.Any("err", cleanupErr))
		}
	}()

	// Check IPv6 state. With nftables inet tables, IPv6 rules are
	// applied regardless of IPv6 stack availability (they simply
	// never match if IPv6 is disabled). Keep defense-in-depth:
	// disable IPv6 via sysctl if it appears unsupported.
	sys := sysctl.New()
	ipv6Disabled := verifyIPv6State(ctx, sys)
	if ipv6Disabled {
		slog.WarnContext(ctx, "IPv6 not available, disabling")
		disableIPv6(ctx, sys)
	}

	// Set up policy routing for UDP TPROXY when Envoy is needed.
	if needsEnvoy {
		err := firewall.SetupPolicyRouting(ctx, sys)
		if err != nil {
			return nil, fmt.Errorf("setting up policy routing: %w", err)
		}
	}

	// VM mode: enable route_localnet for DNAT to 127.0.0.1 on
	// non-loopback interfaces (forwarded container traffic).
	if uids.VMMode {
		err := firewall.SetupForwardRouting(sys)
		if err != nil {
			return nil, fmt.Errorf("setting up forward routing: %w", err)
		}
	}

	// Create a separate nftables connection for the DNS proxy to
	// avoid batching conflicts with rule setup.
	dnsConn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("creating DNS proxy nftables connection: %w", err)
	}

	// Bind the gRPC ALS UDS before Envoy boots so its first stream
	// connect succeeds. A failure here logs and disables ingestion;
	// the bootstrap will be regenerated without an access logger.
	accessLogSrv := openAccessLog(ctx, cfg, store)

	var accessLogCleanedUp bool

	defer func() {
		if accessLogCleanedUp || accessLogSrv == nil {
			return
		}

		alsCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()

		accessLogSrv.Shutdown(alsCtx)
	}()

	// Start DNS proxy with nftables set update function.
	dnsOpts := []dnsproxy.Option{
		dnsproxy.WithFQDNSetFunc(func(ctx context.Context, setName string, ips []net.IP, ttl time.Duration) error {
			return firewall.UpdateFQDNSet(dnsConn, setName, ips, ttl)
		}),
		dnsproxy.WithEventStore(store),
		dnsproxy.WithReverseCache(dnsCache),
	}

	if uids.VMMode {
		dnsOpts = append(dnsOpts, dnsproxy.WithVMMode())
	}

	dnsProxy, err := dnsproxy.Start(ctx, cfg, net.JoinHostPort(upstream, "53"), "127.0.0.1:53", ipv6Disabled,
		dnsOpts...,
	)
	if err != nil {
		return nil, fmt.Errorf("starting DNS proxy: %w", err)
	}

	// Shut down DNS proxy on error return so goroutines and listeners
	// do not leak.
	var dnsProxyCleanedUp bool

	defer func() {
		if dnsProxyCleanedUp {
			return
		}

		shutdownErr := dnsProxy.Shutdown()
		if shutdownErr != nil {
			slog.DebugContext(ctx, "shutting down DNS proxy on init failure", slog.Any("err", shutdownErr))
		}
	}()

	// Start Envoy only when listeners are needed.
	var envoyCmd *exec.Cmd

	if needsEnvoy {
		envoyCmd, err = startEnvoy(ctx, usr, envoySettings, cfg)
		if err != nil {
			return nil, err
		}
	}

	// Setup succeeded; disable error-path cleanup defers.
	// From this point, cleanup is handled by the caller via shutdown.
	firewallCleanedUp = true
	dnsProxyCleanedUp = true
	accessLogCleanedUp = true
	storeCleanedUp = true
	dnsCacheCleanedUp = true
	nflogCleanedUp = true

	// Signal readiness by creating a file at the requested path.
	if usr.ReadyFile != "" {
		f, err := os.Create(usr.ReadyFile)
		if err != nil {
			return nil, fmt.Errorf("creating ready file: %w", err)
		}

		err = f.Close()
		if err != nil {
			return nil, fmt.Errorf("closing ready file: %w", err)
		}
	}

	inf := &infra{
		envoyCmd:     envoyCmd,
		dnsProxy:     dnsProxy,
		eventStore:   store,
		accessLog:    accessLogSrv,
		conn:         conn,
		dnsCache:     dnsCache,
		nflogReader:  nflogReader,
		nflogCancel:  nflogCancel,
		drainTimeout: envoySettings.DrainTimeout.Duration,
		boundStats: boundStats{
			enabled:    cfg.StatsEnabled(),
			path:       cfg.StatsPath(config.StatsDBDefault()),
			socket:     cfg.StatsSocket(),
			nflogGroup: cfg.StatsFirewallNFLogGroup(),
		},
	}

	// Heartbeat is peer-lifetime to the event store and dns cache:
	// reload does not restart it. The goroutine reads through the
	// same [*infra] reference, so reload-time component swaps are
	// picked up automatically on the next tick.
	inf.heartbeatStop = startHeartbeat(ctx, inf)

	return inf, nil
}

// openNflog binds the nfnetlink_log reader when stats and firewall
// logging are both enabled. Returns (nil, nil, nil) when either is
// disabled. On bind failure, returns an error in daemon mode
// (`vmMode=true`) so the system-wide host fails fast. In init mode it
// logs and returns (nil, nil, nil) so the per-container workload
// still starts when CAP_NET_ADMIN is flaky.
//
// The asymmetry has a side effect worth knowing about: the firewall's
// `log group N` directive does not consult the bind status, so an
// init-mode bind failure with stats enabled drops firewall events on
// the floor. The result is a startup warning and no event rows.
//
// The returned [context.CancelFunc] stops the goroutine running
// [Reader.Run].
func openNflog(
	ctx context.Context, cfg *config.Config, store *eventstore.Store,
	resolver nflog.Resolver, vmMode bool,
) (*nflog.Reader, context.CancelFunc, error) {
	if !cfg.StatsEnabled() || !cfg.FirewallLoggingEnabled() {
		return nil, nil, nil
	}

	group := cfg.StatsFirewallNFLogGroup()

	reader, err := nflog.New(group, store, resolver)
	if err != nil {
		if vmMode {
			return nil, nil, fmt.Errorf("binding nflog group %d: %w", group, err)
		}

		slog.WarnContext(ctx, "stats: opening nflog reader, firewall ingestion disabled",
			slog.Uint64("group", uint64(group)),
			slog.Any("err", err),
		)

		return nil, nil, nil
	}

	runCtx, cancel := context.WithCancel(ctx)

	go func() {
		runErr := reader.Run(runCtx)
		if runErr != nil {
			slog.WarnContext(runCtx, "nflog reader exited",
				slog.Uint64("group", uint64(group)),
				slog.Any("err", runErr),
			)
		}
	}()

	slog.InfoContext(ctx, "stats: nflog reader bound",
		slog.Uint64("group", uint64(group)),
	)

	return reader, cancel, nil
}

// openAccessLog binds the gRPC AccessLog UDS when stats is enabled.
// On failure it logs and returns nil so the rest of init proceeds;
// the data plane is never blocked by stats ingestion.
func openAccessLog(
	ctx context.Context, cfg *config.Config, store *eventstore.Store,
) *accesslog.Server {
	if !cfg.StatsEnabled() || store == nil {
		return nil
	}

	socket := cfg.StatsSocket()

	srv, err := accesslog.Start(ctx, socket, store)
	if err != nil {
		slog.WarnContext(ctx, "stats: opening accesslog socket, ingestion disabled",
			slog.String("socket", socket), slog.Any("err", err))

		return nil
	}

	slog.InfoContext(ctx, "stats: accesslog socket open",
		slog.String("socket", socket))

	return srv
}

// openEventStore opens the SQLite event store when stats is enabled.
// On failure it logs and returns nil so [Store] receivers behave as
// no-ops; the data plane is never blocked by stats ingestion. The
// caller owns the returned store via the infra struct.
func openEventStore(
	ctx context.Context, cfg *config.Config, usr *config.User, uids firewall.UIDs,
) *eventstore.Store {
	if !cfg.StatsEnabled() {
		return nil
	}

	path := cfg.StatsPath(config.StatsDBDefault())

	mode := eventstore.ModeInit
	if uids.VMMode {
		mode = eventstore.ModeDaemon
	}

	terrariumUID, err := parseUID(usr.UID)
	if err != nil {
		slog.WarnContext(ctx, "stats: parsing UID", slog.Any("err", err))
	}

	perSource := cfg.StatsRetentionPerSource()
	opts := []eventstore.Option{
		eventstore.WithMode(mode),
		eventstore.WithRetention(eventstore.Retention{
			MaxAge:  cfg.StatsRetentionMaxAge(),
			MaxRows: cfg.StatsRetentionMaxRows(),
			PerSource: eventstore.PerSourceCaps{
				Firewall: perSource.Firewall,
				DNS:      perSource.DNS,
				Envoy:    perSource.Envoy,
			},
		}),
	}

	if terrariumUID > 0 {
		opts = append(opts, eventstore.WithUID(int(terrariumUID)))
	}

	store, err := eventstore.Open(ctx, path, opts...)
	if err != nil {
		slog.WarnContext(ctx, "stats: opening event store, ingestion disabled",
			slog.String("path", path), slog.Any("err", err))

		return nil
	}

	slog.InfoContext(ctx, "stats: event store opened",
		slog.String("path", path), slog.String("instance", store.InstanceID()))

	return store
}

// Init performs the full terrarium initialization sequence for
// container mode: generates configs if needed, applies nftables
// firewall rules, starts the DNS proxy and Envoy, then drops
// privileges and execs the given command as a supervised child
// process. It returns an [*ExitError] carrying the child's exit
// code on normal termination. Use [Daemon] for VM-wide filtering
// without a supervised child process.
func Init(ctx context.Context, usr *config.User, args []string) error {
	if len(args) == 0 {
		return ErrNoCommand
	}

	terrariumUID, err := parseUID(usr.UID)
	if err != nil {
		return err
	}

	envoyUID, err := parseUID(usr.EnvoyUID)
	if err != nil {
		return err
	}

	uids := firewall.UIDs{
		Terrarium:   terrariumUID,
		Envoy:       envoyUID,
		Root:        0,
		ExcludeUIDs: toUint32s(usr.ExcludeDNSUIDs),
	}

	inf, err := setupInfrastructure(ctx, usr, uids)
	if err != nil {
		return err
	}

	// Prepare privilege drop.
	sys := sysctl.New()

	writeErr := sys.Write("0 "+usr.UID, "net", "ipv4", "ping_group_range")
	if writeErr != nil {
		slog.DebugContext(ctx, "setting ping group range", slog.Any("err", writeErr))
	}

	// Start user command as a supervised child process with dropped
	// privileges. It inherits PID 1's process group so terminal
	// signals (SIGINT, SIGWINCH) reach it naturally.
	userArgs := append([]string{
		"exec",
		"--reuid=" + usr.UID, "--regid=" + usr.GID, "--init-groups",
		"--no-new-privs", "--inh-caps=-all", "--bounding-set=-all", "--",
	}, args...)
	//nolint:gosec // G204: args from CLI flags and user input.
	userCmd := exec.CommandContext(ctx, "/proc/self/exe", userArgs...)
	userCmd.Stdin = os.Stdin
	userCmd.Stdout = os.Stdout
	userCmd.Stderr = os.Stderr

	// Register signal handler before starting the user command so
	// that a SIGTERM arriving between Start() and Notify() is
	// caught instead of triggering Go's default termination.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	err = userCmd.Start()
	if err != nil {
		signal.Stop(sigCh)

		return fmt.Errorf("starting user command: %w", err)
	}

	// Wait for user command exit or signal, whichever comes first.
	waitCh := make(chan error, 1)
	go func() { waitCh <- userCmd.Wait() }()

	var waitErr error

	select {
	case waitErr = <-waitCh:
		// User command exited on its own.
	case sig := <-sigCh:
		// Forward signal to the user command (not the process group --
		// the runtime sends SIGTERM to PID 1 specifically).
		slog.InfoContext(ctx, "received signal, forwarding to user command",
			slog.Any("signal", sig),
		)

		err := userCmd.Process.Signal(sig)
		if err != nil {
			slog.WarnContext(ctx, "forwarding signal to user command",
				slog.Any("signal", sig),
				slog.Any("err", err),
			)
		}

		waitErr = <-waitCh
	}

	shutdown(ctx, inf)

	// Reap any remaining zombie children (PID 1 responsibility).
	for {
		_, err := syscall.Wait4(-1, nil, syscall.WNOHANG, nil)
		if err != nil {
			break
		}
	}

	// Propagate the user command's exit code.
	exitCode := 0

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return fmt.Errorf("waiting for user command: %w", waitErr)
		}
	}

	return &ExitError{Code: exitCode}
}

// shutdown performs cleanup in order: Envoy first (with drain wait),
// then the gRPC access-log server so no late stream pushes events
// into a stale store, then DNS proxy, then nftables, then the nflog
// reader so it sees no further kernel events, then the heartbeat
// goroutine (one final snapshot before exit), and finally the event
// store so any pending batched writes flush. Stopping Envoy before
// DNS lets in-flight requests resolve during Envoy's drain period.
// A nil [*infra] is a no-op.
func shutdown(ctx context.Context, inf *infra) {
	if inf == nil {
		return
	}

	stopEnvoy(ctx, inf.envoyCmd, inf.drainTimeout)
	shutdownAccessLog(ctx, inf.accessLog)
	stopDNSProxy(ctx, inf.dnsProxy)

	// Remove policy routes before the nftables table so that
	// TPROXY rules are inactive when routes are removed.
	firewall.CleanupPolicyRouting(ctx)

	if inf.conn != nil {
		err := firewall.Cleanup(ctx, inf.conn)
		if err != nil {
			slog.DebugContext(ctx, "cleaning up firewall on shutdown", slog.Any("err", err))
		}
	}

	// Stop the nflog reader after the firewall is torn down so the
	// kernel emits no further events into a closing socket.
	if inf.nflogCancel != nil {
		inf.nflogCancel()
	}

	if inf.nflogReader != nil {
		err := inf.nflogReader.Close()
		if err != nil {
			slog.DebugContext(ctx, "closing nflog reader on shutdown", slog.Any("err", err))
		}
	}

	// Stop the heartbeat goroutine before closing the event store so
	// the final shutdown snapshot can still send through the writer
	// channel.
	if inf.heartbeatStop != nil {
		inf.heartbeatStop()
	}

	// Close the event store last so its writer goroutine has time to
	// drain queued events from in-flight DNS/Envoy emit calls.
	err := inf.eventStore.Close()
	if err != nil {
		slog.DebugContext(ctx, "closing event store on shutdown", slog.Any("err", err))
	}

	if inf.dnsCache != nil {
		inf.dnsCache.Close()
	}
}

// shutdownAccessLog gracefully stops the access-log server with a
// short deadline. The server should already be quiet because Envoy
// has exited by the time this runs.
func shutdownAccessLog(ctx context.Context, srv *accesslog.Server) {
	if srv == nil {
		return
	}

	alsCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	srv.Shutdown(alsCtx)
}

// stopEnvoy sends SIGTERM to the Envoy process and waits up to
// drainTimeout for it to exit gracefully. If the process has
// already exited or was never started, it returns immediately.
func stopEnvoy(ctx context.Context, cmd *exec.Cmd, drainTimeout time.Duration) {
	if cmd == nil || cmd.Process == nil {
		return
	}

	err := cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		slog.DebugContext(ctx, "stopping envoy", slog.Any("err", err))
		return
	}

	envoyDone := make(chan struct{})

	go func() {
		waitErr := cmd.Wait()
		if waitErr != nil {
			slog.DebugContext(ctx, "envoy exited", slog.Any("err", waitErr))
		}

		close(envoyDone)
	}()

	select {
	case <-envoyDone:
	case <-time.After(drainTimeout):
		slog.WarnContext(ctx, "envoy did not exit within drain timeout, proceeding")
	}
}

// stopDNSProxy shuts down the DNS proxy. If the proxy is nil,
// it returns immediately.
func stopDNSProxy(ctx context.Context, proxy *dnsproxy.Proxy) {
	if proxy == nil {
		return
	}

	err := proxy.Shutdown()
	if err != nil {
		slog.DebugContext(ctx, "stopping DNS proxy", slog.Any("err", err))
	}
}

// installCA copies terrarium CA certificate into the system trust
// store and appends it to the system CA bundle.
func installCA(ctx context.Context, caCertPath string) error {
	trustDest := "/usr/local/share/ca-certificates/terrarium-ca.crt"

	err := copyFile(caCertPath, trustDest)
	if err != nil {
		return fmt.Errorf("installing CA cert: %w", err)
	}

	err = certs.InstallToBundle(caCertPath)
	if err != nil {
		slog.WarnContext(ctx, "installing CA to bundle",
			slog.Any("err", err),
		)
	}

	return nil
}

// disableIPv6 attempts to disable IPv6 on all interfaces via procfs.
// Failures are logged but not returned because some kernels do not
// support the sysctl knobs.
func disableIPv6(ctx context.Context, sys *sysctl.Sysctl) {
	err := sys.Enable("net", "ipv6", "conf", "all", "disable_ipv6")
	if err != nil {
		slog.DebugContext(ctx, "disabling IPv6 on all interfaces", slog.Any("err", err))
	}

	err = sys.Enable("net", "ipv6", "conf", "default", "disable_ipv6")
	if err != nil {
		slog.DebugContext(ctx, "disabling IPv6 on default interface", slog.Any("err", err))
	}
}

// verifyIPv6State checks whether IPv6 is available. Returns true when
// IPv6 appears disabled (sysctl flag set to 1 or unreadable).
func verifyIPv6State(ctx context.Context, sys *sysctl.Sysctl) bool {
	val, err := sys.Read("net", "ipv6", "conf", "all", "disable_ipv6")
	if err != nil {
		slog.DebugContext(ctx, "reading IPv6 disable flag", slog.Any("err", err))

		return true
	}

	return val == "1"
}

// firstListenerPort returns the first Envoy listener port to wait on.
// In non-blocked modes, 15443 is always present (TLS passthrough).
// Falls back to [config.CatchAllProxyPort] as a final safety net.
func firstListenerPort(ctx context.Context, cfg *config.Config) int {
	ports := cfg.ResolvePorts(ctx)
	if slices.Contains(ports, 443) || cfg.IsEgressUnrestricted() {
		return 15443
	}

	if len(cfg.TCPForwards) > 0 {
		return config.ProxyPortBase + cfg.TCPForwards[0].Port
	}

	if len(ports) > 0 {
		return config.ProxyPortBase + ports[0]
	}

	return config.CatchAllProxyPort
}

// waitForListener polls a TCP address until it accepts connections or
// the timeout expires.
func waitForListener(ctx context.Context, addr string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := net.Dialer{Timeout: 100 * time.Millisecond}

	for {
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err == nil {
			err := conn.Close()
			if err != nil {
				slog.DebugContext(ctx, "closing connectivity check connection", slog.Any("err", err))
			}

			return nil
		}

		if ctx.Err() != nil {
			return fmt.Errorf("listener %s not ready after %v", addr, timeout)
		}

		time.Sleep(100 * time.Millisecond)
	}
}

// startEnvoy prepares the log files, starts the Envoy process, and
// waits for the first listener to become ready.
func startEnvoy(
	ctx context.Context, usr *config.User,
	settings config.EnvoySettings, cfg *config.Config,
) (*exec.Cmd, error) {
	envoyUID, err := parseUID(usr.EnvoyUID)
	if err != nil {
		return nil, err
	}

	envoyLogPath := cfg.EnvoyLogPath(usr.EnvoyLogPath)

	err = prepareEnvoyLogFile(envoyLogPath, int(envoyUID))
	if err != nil {
		return nil, err
	}

	//nolint:gosec // G204: args from config.User populated via CLI flags.
	// Envoy v1.37 added cgroup-aware CPU detection that uses
	// conservative floor rounding. In constrained containers
	// this can reduce worker threads to 1. Pin to 2 for
	// stable listener handling.
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "exec",
		"--reuid="+usr.EnvoyUID, "--regid="+usr.EnvoyUID, "--clear-groups",
		"--inh-caps=+cap_net_admin", "--ambient-caps=+cap_net_admin",
		"--", "envoy", "-c", usr.EnvoyConfigPath,
		"--log-level", cfg.EnvoyLogLevel(),
		"--log-path", envoyLogPath,
		"--concurrency", "2")
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("starting envoy: %w", err)
	}

	// Wait on the first available listener port.
	waitPort := firstListenerPort(ctx, cfg)

	err = waitForListener(ctx, fmt.Sprintf("127.0.0.1:%d", waitPort), settings.StartupTimeout.Duration)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnvoyNotRunning, err)
	}

	err = cmd.Process.Signal(syscall.Signal(0))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnvoyNotRunning, err)
	}

	return cmd, nil
}

// prepareEnvoyLogFile creates the log file's parent directory, ensures
// the path is traversable by unprivileged users, and pre-creates the
// file owned by the Envoy UID with world-readable permissions so the
// terrarium user can read it.
func prepareEnvoyLogFile(path string, ownerUID int) error {
	err := os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		return fmt.Errorf("creating log directory: %w", err)
	}

	//nolint:gosec // G302: world-readable so the terrarium user can read envoy logs.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("creating log file: %w", err)
	}

	closeErr := f.Close()
	if closeErr != nil {
		return fmt.Errorf("closing log file: %w", closeErr)
	}

	err = os.Chown(path, ownerUID, ownerUID)
	if err != nil {
		return fmt.Errorf("chown log file: %w", err)
	}

	err = ensurePathTraversable(path)
	if err != nil {
		return fmt.Errorf("making log path traversable: %w", err)
	}

	return nil
}

// parseUID parses a numeric string as a user or group ID and returns
// it as a uint32. It rejects empty strings, non-numeric input, and
// values outside the 32-bit unsigned range.
func parseUID(s string) (uint32, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parsing UID %q: %w", s, err)
	}

	return uint32(n), nil
}

func toUint32s(us []uint) []uint32 {
	out := make([]uint32, len(us))
	for i, u := range us {
		if u > math.MaxUint32 {
			panic(fmt.Sprintf("value %d at index %d overflows uint32", u, i))
		}

		out[i] = uint32(u)
	}

	return out
}

// ensurePathTraversable walks up from the given file path and sets the
// world-execute bit on each parent directory that lacks it. This allows
// unprivileged users (like the envoy process) to traverse into
// directories that may be restricted (e.g., /root with mode 0700).
// Only the execute bit is added; read and write permissions are not
// modified. Symlinks in the path are resolved before walking to
// ensure permission changes apply to the real directory tree.
func ensurePathTraversable(path string) error {
	resolved, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("resolving symlinks in %s: %w", path, err)
	}

	dir := resolved

	// Collect directories from the file's parent up to /.
	var dirs []string
	for dir != "/" && dir != "." {
		dirs = append(dirs, dir)
		dir = filepath.Dir(dir)
	}

	for _, d := range dirs {
		info, err := os.Stat(d)
		if err != nil {
			return fmt.Errorf("stat %s: %w", d, err)
		}

		perm := info.Mode().Perm()
		if perm&0o001 == 0 {
			slog.Warn("adding world-execute bit for path traversal",
				slog.String("dir", d),
				slog.String("old_mode", fmt.Sprintf("%04o", perm)),
			)
			//nolint:gosec // G302: intentionally adding world-execute for path traversal.
			err := os.Chmod(d, perm|0o001)
			if err != nil {
				return fmt.Errorf("chmod %s: %w", d, err)
			}
		}
	}

	return nil
}

// copyFile copies a file from src to dst, creating parent directories.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading %s: %w", src, err)
	}

	err = os.MkdirAll(filepath.Dir(dst), 0o755)
	if err != nil {
		return fmt.Errorf("creating dir for %s: %w", dst, err)
	}

	err = os.WriteFile(dst, data, 0o644) //nolint:gosec // G703: path from caller.
	if err != nil {
		return fmt.Errorf("writing %s: %w", dst, err)
	}

	return nil
}
