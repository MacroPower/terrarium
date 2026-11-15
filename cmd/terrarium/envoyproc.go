package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os/exec"
	"syscall"
	"time"
)

var (
	// ErrEnvoyNotRunning is returned when the Envoy proxy process exits
	// or cannot be signaled after startup.
	ErrEnvoyNotRunning = errors.New("envoy process not running")

	// ErrListenerNotReady means that a listener did not accept
	// connections before the startup timeout expired.
	ErrListenerNotReady = errors.New("listener not ready")

	// ErrListenAddressUnavailable means that the proxy cannot bind its
	// listen address, for example because another process holds the
	// port or because the host of the address is not an IP address.
	ErrListenAddressUnavailable = errors.New("listen address unavailable")
)

// listenerPollInterval is the pause between two connection attempts
// of [waitForListener].
const listenerPollInterval = 100 * time.Millisecond

// checkListenAddress binds the TCP address addr and releases it again.
// It returns [ErrListenAddressUnavailable] when the bind does not
// succeed.
//
// The host of addr must be an IP address, because Envoy does not bind
// a host name. For every other host, the check binds nothing and
// returns [ErrListenAddressUnavailable]. A host name can resolve to
// several addresses, and [waitForListener] connects to a listener on
// any of them.
//
// A caller runs it before it starts Envoy and waits with
// [waitForListener]. The wait then cannot connect to a listener that
// another process already holds. The check does not reserve addr, so
// a process that binds addr after the check and before Envoy still
// satisfies the wait.
//
// The check binds only the address family of addr, as Envoy does. It
// does not set SO_REUSEPORT, so it also finds a listener that shares
// its port, such as the Envoy of another proxy.
func checkListenAddress(ctx context.Context, addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %s: %w", ErrListenAddressUnavailable, addr, err)
	}

	// Without a family, Go binds a wildcard address for IPv4 and IPv6
	// together, and a listener of the other family blocks that bind.
	network := "tcp6"
	if ap.Addr().Is4() {
		network = "tcp4"
	}

	lc := net.ListenConfig{}

	ln, err := lc.Listen(ctx, network, addr)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrListenAddressUnavailable, err)
	}

	err = ln.Close()
	if err != nil {
		return fmt.Errorf("releasing listen address %s: %w", addr, err)
	}

	return nil
}

// waitForListener polls a TCP address until it accepts connections.
// A connection shows only that some process listens on addr. See
// [checkListenAddress] for a way to exclude a listener that exists
// before Envoy starts.
//
// It returns [ErrListenerNotReady] when the timeout expires first.
// When the caller cancels ctx first, it returns the context's error
// without waiting for the next poll. The caller can then tell a
// shutdown from a listener that never came up.
func waitForListener(ctx context.Context, addr string, timeout time.Duration) error {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := net.Dialer{Timeout: listenerPollInterval}

	for {
		conn, err := dialer.DialContext(waitCtx, "tcp", addr)
		if err == nil {
			err := conn.Close()
			if err != nil {
				slog.DebugContext(ctx, "closing connectivity check connection", slog.Any("err", err))
			}

			return nil
		}

		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return fmt.Errorf("waiting for listener %s: %w", addr, ctx.Err())
			}

			return fmt.Errorf("%w: %s after %v", ErrListenerNotReady, addr, timeout)

		case <-time.After(listenerPollInterval):
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
