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

// ErrEnvoyNotRunning is returned when the Envoy proxy process exits
// or cannot be signaled after startup.
var ErrEnvoyNotRunning = errors.New("envoy process not running")

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
