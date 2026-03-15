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
func Init(ctx context.Context, usr *config.User, args []string) error {
	if len(args) == 0 {
		return ErrNoCommand
	}

	// Capture upstream DNS before we replace resolv.conf.
	resolvData, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("reading /etc/resolv.conf: %w", err)
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
			return fmt.Errorf("generating configs: %w", err)
		}
	}

	// Install CA cert into trust store if MITM certs were generated.
	caCertPath := usr.CADir + "/ca.pem"

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

	envoySettings := cfg.EnvoyDefaults()

	needsEnvoy := !cfg.IsEgressBlocked()

	// Apply nftables firewall rules atomically via netlink.
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("creating nftables connection: %w", err)
	}

	slog.InfoContext(ctx, "applying nftables firewall rules")

	uids := firewall.UIDs{
		//nolint:gosec // G115: UID values from CLI flags.
		Sandbox: uint32(mustAtoi(usr.UID)),
		//nolint:gosec // G115: UID values from CLI flags.
		Envoy: uint32(mustAtoi(usr.EnvoyUID)),
		Root:  0,
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
	sys := sysctl.New()
	ipv6Disabled := verifyIPv6State(ctx, sys)
	if ipv6Disabled {
		slog.WarnContext(ctx, "IPv6 not available, disabling")
		disableIPv6(ctx, sys)
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

		return fmt.Errorf("renaming resolv.conf: %w", err)
	}

	// Start Envoy only when listeners are needed.
	var envoyCmd *exec.Cmd

	if needsEnvoy {
		//nolint:gosec // G204: args from config.User populated via CLI flags.
		envoyCmd = exec.CommandContext(ctx, "setpriv",
			"--reuid="+usr.EnvoyUID, "--regid="+usr.EnvoyUID, "--clear-groups", "--no-new-privs",
			"--", "envoy", "-c", usr.EnvoyConfigPath, "--log-level", envoySettings.LogLevel)
		envoyCmd.Stdout = os.Stdout
		envoyCmd.Stderr = os.Stderr

		err := envoyCmd.Start()
		if err != nil {
			return fmt.Errorf("starting envoy: %w", err)
		}

		// Wait on the first available listener port.
		waitPort := firstListenerPort(cfg)

		err = waitForListener(ctx, fmt.Sprintf("127.0.0.1:%d", waitPort), envoySettings.StartupTimeout.Duration)
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
	writeErr := sys.Write("0 "+usr.UID, "net", "ipv4", "ping_group_range")
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
	//nolint:gosec // G204: args from CLI flags and user input.
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

	shutdown(ctx, envoyCmd, dnsProxy, conn, envoySettings.DrainTimeout.Duration)

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
	if envoyCmd != nil && envoyCmd.Process != nil {
		err := envoyCmd.Process.Signal(syscall.SIGTERM)
		if err != nil {
			slog.DebugContext(ctx, "stopping envoy", slog.Any("err", err))
		} else {
			// Wait for Envoy to exit gracefully.
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
			case <-time.After(drainTimeout):
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
	// namespace does not fail on pre-existing resources.
	if conn != nil {
		err := firewall.Cleanup(ctx, conn)
		if err != nil {
			slog.DebugContext(ctx, "cleaning up firewall on shutdown", slog.Any("err", err))
		}
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
func firstListenerPort(cfg *config.Config) int {
	ports := cfg.ResolvePorts()
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
