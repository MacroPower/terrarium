package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
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

	"go.jacobcolvin.com/terrarium/certs"
	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/dnsproxy"
	"go.jacobcolvin.com/terrarium/firewall"
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

// ParseUpstreamDNS extracts the first nameserver IP from resolv.conf
// content. It returns the empty string when no nameserver is found.
func ParseUpstreamDNS(resolvConf string) string {
	for line := range strings.SplitSeq(resolvConf, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1]
			}
		}
	}

	return ""
}

// infra holds the running infrastructure components started by
// [setupInfrastructure]. The caller owns cleanup via [shutdown].
type infra struct {
	envoyCmd     *exec.Cmd
	dnsProxy     *dnsproxy.Proxy
	conn         firewall.Conn
	drainTimeout time.Duration
}

// setupInfrastructure performs the shared initialization sequence:
// generate configs, apply nftables rules, start DNS proxy, rewrite
// resolv.conf, and start Envoy. On success the caller owns cleanup
// via [shutdown]. On error, all resources are cleaned up before
// returning.
func setupInfrastructure(ctx context.Context, usr *config.User, uids firewall.UIDs) (*infra, error) {
	// Capture upstream DNS before we replace resolv.conf.
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

		cfg, err = Generate(ctx, usr)
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

	// Create a separate nftables connection for the DNS proxy to
	// avoid batching conflicts with rule setup.
	dnsConn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("creating DNS proxy nftables connection: %w", err)
	}

	// Start DNS proxy with nftables set update function.
	dnsProxy, err := dnsproxy.Start(ctx, cfg, net.JoinHostPort(upstream, "53"), "127.0.0.1:53", ipv6Disabled,
		dnsproxy.WithFQDNSetFunc(func(ctx context.Context, setName string, ips []net.IP, ttl time.Duration) error {
			return firewall.UpdateFQDNSet(dnsConn, setName, ips, ttl)
		}),
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

	// Point system DNS to local resolver.
	// Write to a temp file first, then atomically rename into place so that
	// a failed write after unmount does not leave the system without DNS.
	tmpResolv, err := os.CreateTemp("/etc", ".resolv.conf.*")
	if err != nil {
		return nil, fmt.Errorf("creating temp resolv.conf: %w", err)
	}

	_, err = tmpResolv.WriteString("nameserver 127.0.0.1\nnameserver ::1\n")

	closeErr := tmpResolv.Close()

	if err != nil {
		removeErr := os.Remove(tmpResolv.Name())
		if removeErr != nil {
			slog.DebugContext(ctx, "removing temp resolv.conf", slog.Any("err", removeErr))
		}

		return nil, fmt.Errorf("writing temp resolv.conf: %w", err)
	}

	if closeErr != nil {
		removeErr := os.Remove(tmpResolv.Name())
		if removeErr != nil {
			slog.DebugContext(ctx, "removing temp resolv.conf", slog.Any("err", removeErr))
		}

		return nil, fmt.Errorf("closing temp resolv.conf: %w", closeErr)
	}

	umountErr := syscall.Unmount("/etc/resolv.conf", 0)
	if umountErr != nil {
		slog.DebugContext(ctx, "unmounting resolv.conf", slog.Any("err", umountErr))
	}

	err = os.Rename(tmpResolv.Name(), "/etc/resolv.conf")
	if err != nil {
		slog.ErrorContext(ctx, "atomic resolv.conf rename failed after unmount",
			slog.String("temp", tmpResolv.Name()),
			slog.Any("err", err),
		)

		return nil, fmt.Errorf("renaming resolv.conf: %w", err)
	}

	// os.CreateTemp creates files with 0o600. Make resolv.conf world-readable
	// so Envoy's getaddrinfo resolver (running as the envoy user) can read it.
	err = os.Chmod("/etc/resolv.conf", 0o644)
	if err != nil {
		return nil, fmt.Errorf("chmod resolv.conf: %w", err)
	}

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

	return &infra{
		envoyCmd:     envoyCmd,
		dnsProxy:     dnsProxy,
		conn:         conn,
		drainTimeout: envoySettings.DrainTimeout.Duration,
	}, nil
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
		Terrarium: terrariumUID,
		Envoy:     envoyUID,
		Root:      0,
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

	shutdown(ctx, inf.envoyCmd, inf.dnsProxy, inf.conn, inf.drainTimeout)

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

// shutdown performs the full cleanup sequence in the correct order:
// Envoy first (with drain wait), then DNS proxy, then nftables.
// Stopping Envoy before DNS ensures in-flight requests can still
// resolve during Envoy's drain period.
func shutdown(
	ctx context.Context, envoyCmd *exec.Cmd, dnsProxy *dnsproxy.Proxy,
	conn firewall.Conn, drainTimeout time.Duration,
) {
	// Stop Envoy first so DNS remains available during drain.
	stopEnvoy(ctx, envoyCmd, drainTimeout)
	stopDNSProxy(ctx, dnsProxy)

	// Remove policy routes before the nftables table so that
	// TPROXY rules are inactive when routes are removed.
	firewall.CleanupPolicyRouting(ctx)

	// Delete the nftables table so a restart in the same network
	// namespace does not fail on pre-existing resources.
	if conn != nil {
		err := firewall.Cleanup(ctx, conn)
		if err != nil {
			slog.DebugContext(ctx, "cleaning up firewall on shutdown", slog.Any("err", err))
		}
	}
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
	accessLogPath := cfg.EnvoyAccessLogPath(usr.EnvoyAccessLogPath)

	err = prepareEnvoyLogFile(envoyLogPath, int(envoyUID))
	if err != nil {
		return nil, err
	}

	err = prepareEnvoyLogFile(accessLogPath, int(envoyUID))
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
