package terrarium

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
	"strings"
	"syscall"
	"time"

	"github.com/google/nftables"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/dnsproxy"
	"go.jacobcolvin.com/terrarium/firewall"
)

// envoyDrainTimeout is the maximum time to wait for Envoy to exit
// after receiving SIGTERM before proceeding with shutdown.
const envoyDrainTimeout = 5 * time.Second

// ExitError carries a process exit code through the error return path
// so the CLI entrypoint can propagate it to [os.Exit].
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

// ParseUpstreamDNS extracts the first nameserver from resolv.conf content.
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

// Init performs the full terrarium initialization sequence: generates
// configs if needed, applies nftables firewall rules, starts the DNS
// proxy and Envoy, then drops privileges and runs the given command
// as a supervised child process. The context is threaded to all
// subprocesses, allowing cancellation to propagate. Returns an
// [*ExitError] carrying the child's exit code on normal termination.
func Init(ctx context.Context, usr config.User, args []string) error {
	if len(args) == 0 {
		return ErrNoCommand
	}

	setenvErr := os.Setenv("PATH", usr.HMBin+":"+os.Getenv("PATH"))
	if setenvErr != nil {
		slog.DebugContext(ctx, "setting PATH", slog.Any("err", setenvErr))
	}

	// Capture upstream DNS before we replace resolv.conf.
	resolvData, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}

	upstream := ParseUpstreamDNS(string(resolvData))

	// Generate configs at runtime if not pre-baked. The parsed config
	// is returned so we can reuse it below without re-parsing (ISSUE-71).
	var cfg *config.Config

	_, err = os.Stat("/etc/envoy-terrarium.yaml")
	if os.IsNotExist(err) {
		slog.InfoContext(ctx, "generating firewall configs")

		cfg, err = Generate(ctx, usr.ConfigPath)
		if err != nil {
			return fmt.Errorf("generating configs: %w", err)
		}
	}

	// Install CA cert into trust store if MITM certs were generated.
	caCertPath := CADir + "/ca.pem"

	_, err = os.Stat(caCertPath)
	if err == nil {
		slog.InfoContext(ctx, "installing terrarium CA into trust store")

		err := installCA(ctx, caCertPath)
		if err != nil {
			return err
		}
	}

	// Parse config if Generate() was not called (pre-baked configs).
	if cfg == nil {
		cfgData, err := os.ReadFile(usr.ConfigPath)
		if err != nil {
			return fmt.Errorf("reading terrarium config: %w", err)
		}

		cfg, err = config.ParseConfig(ctx, cfgData)
		if err != nil {
			return fmt.Errorf("parsing terrarium config: %w", err)
		}
	}

	needsEnvoy := len(cfg.ResolvePorts()) > 0 || len(cfg.TCPForwards) > 0

	// Apply nftables firewall rules atomically via netlink.
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	slog.InfoContext(ctx, "applying nftables firewall rules")

	uids := firewall.UIDs{
		Sandbox: uint32(
			mustAtoi(usr.UID),
		), //nolint:gosec // G115: UID values are small constants from CLI entrypoint.
		Envoy: uint32(
			mustAtoi(usr.EnvoyUID),
		), //nolint:gosec // G115: UID values are small constants from CLI entrypoint.
		Root: 0,
	}

	err = firewall.ApplyRules(ctx, conn, cfg, uids)
	if err != nil {
		return fmt.Errorf("applying firewall rules: %w", err)
	}

	// Clean up firewall on error return so a restart in the same
	// network namespace starts with clean state.
	var firewallCleanedUp bool

	defer func() {
		if firewallCleanedUp {
			return
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
	ipv6Disabled := verifyIPv6State(ctx)
	if ipv6Disabled {
		slog.WarnContext(ctx, "IPv6 not available, disabling")
		disableIPv6(ctx)
	}

	// Create a separate nftables connection for the DNS proxy to
	// avoid batching conflicts with rule setup.
	dnsConn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating DNS proxy nftables connection: %w", err)
	}

	// Start DNS proxy with nftables set update function.
	dnsProxy, err := dnsproxy.Start(ctx, cfg, net.JoinHostPort(upstream, "53"), "127.0.0.1:53", ipv6Disabled,
		dnsproxy.WithFQDNSetFunc(func(ctx context.Context, setName string, ips []net.IP, ttl time.Duration) error {
			return firewall.UpdateFQDNSet(dnsConn, setName, ips, ttl)
		}),
	)
	if err != nil {
		return fmt.Errorf("starting DNS proxy: %w", err)
	}

	// Shut down DNS proxy on error return so goroutines and listeners
	// do not leak (ISSUE-43).
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
	// a failed write after unmount does not leave the container without DNS.
	tmpResolv, err := os.CreateTemp("/etc", ".resolv.conf.*")
	if err != nil {
		return fmt.Errorf("creating temp resolv.conf: %w", err)
	}

	_, err = tmpResolv.WriteString("nameserver 127.0.0.1\nnameserver ::1\n")

	closeErr := tmpResolv.Close()

	if err != nil {
		removeErr := os.Remove(tmpResolv.Name())
		if removeErr != nil {
			slog.DebugContext(ctx, "removing temp resolv.conf", slog.Any("err", removeErr))
		}

		return fmt.Errorf("writing temp resolv.conf: %w", err)
	}

	if closeErr != nil {
		removeErr := os.Remove(tmpResolv.Name())
		if removeErr != nil {
			slog.DebugContext(ctx, "removing temp resolv.conf", slog.Any("err", removeErr))
		}

		return fmt.Errorf("closing temp resolv.conf: %w", closeErr)
	}

	umountErr := exec.CommandContext(ctx, "umount", "/etc/resolv.conf").Run()
	if umountErr != nil {
		slog.DebugContext(ctx, "unmounting resolv.conf", slog.Any("err", umountErr))
	}

	err = os.Rename(tmpResolv.Name(), "/etc/resolv.conf")
	if err != nil {
		slog.ErrorContext(ctx, "atomic resolv.conf rename failed after unmount",
			slog.String("temp", tmpResolv.Name()),
			slog.Any("err", err),
		)

		return fmt.Errorf("renaming resolv.conf: %w", err)
	}

	// Start Envoy only when listeners are needed.
	var envoyCmd *exec.Cmd

	if needsEnvoy {
		//nolint:gosec // G204: args from config.User populated with constants in CLI entrypoint.
		envoyCmd = exec.CommandContext(ctx, "setpriv",
			"--reuid="+usr.EnvoyUID, "--regid="+usr.EnvoyUID, "--clear-groups", "--no-new-privs",
			"--", "envoy", "-c", "/etc/envoy-terrarium.yaml", "--log-level", "warning")
		envoyCmd.Stdout = os.Stdout
		envoyCmd.Stderr = os.Stderr

		err := envoyCmd.Start()
		if err != nil {
			return fmt.Errorf("starting envoy: %w", err)
		}

		// Wait on the first available listener port.
		waitPort := firstListenerPort(cfg)

		err = waitForListener(ctx, fmt.Sprintf("127.0.0.1:%d", waitPort), 10*time.Second)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrEnvoyNotRunning, err)
		}

		err = envoyCmd.Process.Signal(syscall.Signal(0))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrEnvoyNotRunning, err)
		}
	}

	// Init setup succeeded; disable error-path cleanup defers.
	// From this point, cleanup is handled by the shutdown path below.
	firewallCleanedUp = true
	dnsProxyCleanedUp = true

	// Prepare privilege drop.
	writeErr := os.WriteFile(
		"/proc/sys/net/ipv4/ping_group_range",
		[]byte("0 "+usr.UID),
		0o644,
	)
	if writeErr != nil {
		slog.DebugContext(ctx, "setting ping group range", slog.Any("err", writeErr))
	}

	// Start user command as a supervised child process with dropped
	// privileges. It inherits PID 1's process group so terminal
	// signals (SIGINT, SIGWINCH) reach it naturally.
	userArgs := append([]string{
		"--reuid=" + usr.UID, "--regid=" + usr.GID, "--init-groups",
		"--no-new-privs", "--inh-caps=-all", "--bounding-set=-all", "--",
	}, args...)
	//nolint:gosec // G204: args from constants and user input.
	userCmd := exec.CommandContext(ctx, "setpriv", userArgs...)
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

	Shutdown(ctx, envoyCmd, dnsProxy, conn)

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

// Shutdown performs the full cleanup sequence in the correct order:
// Envoy first (with drain wait), then DNS proxy, then nftables.
// Stopping Envoy before DNS ensures in-flight requests can still
// resolve during Envoy's drain period (ISSUE-52).
func Shutdown(ctx context.Context, envoyCmd *exec.Cmd, dnsProxy *dnsproxy.Proxy, conn firewall.Conn) {
	// Stop Envoy first so DNS remains available during drain (ISSUE-52).
	if envoyCmd != nil && envoyCmd.Process != nil {
		err := envoyCmd.Process.Signal(syscall.SIGTERM)
		if err != nil {
			slog.DebugContext(ctx, "stopping envoy", slog.Any("err", err))
		} else {
			// Wait up to 5 seconds for Envoy to exit gracefully (ISSUE-51).
			envoyDone := make(chan struct{})

			go func() {
				waitErr := envoyCmd.Wait()
				if waitErr != nil {
					slog.DebugContext(ctx, "envoy exited", slog.Any("err", waitErr))
				}

				close(envoyDone)
			}()

			select {
			case <-envoyDone:
			case <-time.After(envoyDrainTimeout):
				slog.WarnContext(ctx, "envoy did not exit within drain timeout, proceeding")
			}
		}
	}

	// Stop DNS proxy after Envoy is down.
	if dnsProxy != nil {
		err := dnsProxy.Shutdown()
		if err != nil {
			slog.DebugContext(ctx, "stopping DNS proxy", slog.Any("err", err))
		}
	}

	// Delete the nftables table so a restart in the same network
	// namespace does not fail on pre-existing resources (ISSUE-53).
	if conn != nil {
		err := firewall.Cleanup(ctx, conn)
		if err != nil {
			slog.DebugContext(ctx, "cleaning up firewall on shutdown", slog.Any("err", err))
		}
	}
}

// installCA copies terrarium CA certificate into the system trust
// store and runs update-ca-certificates. Falls back to direct bundle
// injection when update-ca-certificates is unavailable.
func installCA(ctx context.Context, caCertPath string) error {
	trustDest := "/usr/local/share/ca-certificates/terrarium-ca.crt"

	err := copyFile(caCertPath, trustDest)
	if err != nil {
		return fmt.Errorf("installing CA cert: %w", err)
	}

	err = exec.CommandContext(ctx, "update-ca-certificates").Run()
	if err != nil {
		slog.WarnContext(ctx, "update-ca-certificates not available, appending to CA bundle",
			slog.Any("err", err),
		)

		err = installCAToBundle(caCertPath)
		if err != nil {
			slog.WarnContext(ctx, "installing CA to bundle",
				slog.Any("err", err),
			)
		}
	}

	return nil
}

// disableIPv6 attempts to disable IPv6 on all interfaces via sysctl.
// Failures are logged but not returned because some kernels do not
// support the sysctl knobs.
func disableIPv6(ctx context.Context) {
	err := exec.CommandContext(ctx, "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1").Run()
	if err != nil {
		slog.DebugContext(ctx, "disabling IPv6 on all interfaces", slog.Any("err", err))
	}

	err = exec.CommandContext(ctx, "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1").Run()
	if err != nil {
		slog.DebugContext(ctx, "disabling IPv6 on default interface", slog.Any("err", err))
	}
}

// verifyIPv6State checks whether IPv6 is available. Returns true when
// IPv6 appears disabled (sysctl flag set to 1 or unreadable).
func verifyIPv6State(ctx context.Context) bool {
	disabled, err := os.ReadFile(
		"/proc/sys/net/ipv6/conf/all/disable_ipv6",
	)
	if err != nil {
		slog.DebugContext(ctx, "reading IPv6 disable flag", slog.Any("err", err))

		return true
	}

	return strings.TrimSpace(string(disabled)) == "1"
}

// firstListenerPort returns the first Envoy listener port to wait on.
// Prefers 15443 when FQDN rules produce a port 443 listener, then
// checks TCPForwards, then falls back to the first resolved port.
func firstListenerPort(cfg *config.Config) int {
	ports := cfg.ResolvePorts()
	if slices.Contains(ports, 443) {
		return 15443
	}

	if len(cfg.TCPForwards) > 0 {
		return config.ProxyPortBase + cfg.TCPForwards[0].Port
	}

	if len(ports) > 0 {
		return config.ProxyPortBase + ports[0]
	}

	return 15443
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

// installCAToBundle appends a CA certificate to the system CA bundle and
// ensures SSL_CERT_FILE points to the updated bundle. This handles systems
// without update-ca-certificates (e.g. NixOS where the bundle is a
// read-only symlink into the nix store and SSL_CERT_FILE may point there).
func installCAToBundle(caCertPath string) error {
	caData, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("reading CA cert: %w", err)
	}

	// Collect candidate bundle paths: SSL_CERT_FILE first (what TLS
	// clients actually use), then well-known system paths.
	var candidates []string
	if env := os.Getenv("SSL_CERT_FILE"); env != "" {
		candidates = append(candidates, env)
	}

	if env := os.Getenv("NIX_SSL_CERT_FILE"); env != "" {
		candidates = append(candidates, env)
	}

	candidates = append(candidates,
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/ssl/certs/ca-bundle.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
	)

	// Deduplicate while preserving order.
	seen := make(map[string]bool)

	var bundles []string
	for _, c := range candidates {
		if c != "" && !seen[c] {
			seen[c] = true
			bundles = append(bundles, c)
		}
	}

	for _, bundle := range bundles {
		_, statErr := os.Stat(bundle) //nolint:gosec // G703: paths from hardcoded candidates.
		if statErr != nil {
			continue
		}

		err := appendToBundle(bundle, caData)
		if err != nil {
			slog.Warn("appending CA to bundle", //nolint:gosec // G706: bundle path from hardcoded candidates.
				slog.String("bundle", bundle),
				slog.Any("err", err),
			)

			continue
		}

		// Point SSL_CERT_FILE to the writable bundle so child
		// processes (running as uid 1000) pick it up.
		envErr := os.Setenv("SSL_CERT_FILE", bundle)
		if envErr != nil {
			slog.Debug("setting SSL_CERT_FILE", slog.Any("err", envErr))
		}

		return nil
	}

	return fmt.Errorf("no system CA bundle found")
}

// appendToBundle appends caData to the bundle file. If the file is a
// symlink (e.g. into the read-only nix store), it is replaced with a
// writable copy first.
func appendToBundle(bundle string, caData []byte) error {
	fi, err := os.Lstat(bundle) //nolint:gosec // G703: path from caller.
	if err != nil {
		return fmt.Errorf("stat %s: %w", bundle, err)
	}

	// Replace symlinks with a writable copy.
	if fi.Mode()&os.ModeSymlink != 0 {
		existing, err := os.ReadFile(bundle) //nolint:gosec // G703: path from caller.
		if err != nil {
			return fmt.Errorf("reading %s: %w", bundle, err)
		}

		err = os.Remove(bundle) //nolint:gosec // G703: path from caller.
		if err != nil {
			return fmt.Errorf("removing symlink %s: %w", bundle, err)
		}

		err = os.WriteFile(bundle, existing, 0o644) //nolint:gosec // G703: replacing symlink with writable copy.
		if err != nil {
			return fmt.Errorf("writing %s: %w", bundle, err)
		}
	}

	f, err := os.OpenFile(bundle, os.O_APPEND|os.O_WRONLY, 0o644) //nolint:gosec // G703: path from caller.
	if err != nil {
		return fmt.Errorf("opening %s: %w", bundle, err)
	}

	_, err = f.Write(append([]byte("\n"), caData...))
	if err != nil {
		closeErr := f.Close()
		if closeErr != nil {
			//nolint:gosec // G706: bundle path from caller.
			slog.Debug("closing bundle file after write error",
				slog.String("path", bundle),
				slog.Any("err", closeErr),
			)
		}

		return fmt.Errorf("appending to %s: %w", bundle, err)
	}

	err = f.Close()
	if err != nil {
		return fmt.Errorf("closing %s: %w", bundle, err)
	}

	return nil
}

func mustAtoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}

	return n
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
