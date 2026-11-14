package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
)

// listenerPollInterval is the pause between two connection attempts
// of [waitForListener].
const listenerPollInterval = 100 * time.Millisecond

// waitForListener polls a TCP address until it accepts connections.
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
