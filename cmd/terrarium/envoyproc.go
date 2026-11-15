package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"syscall"
	"time"

	"go.jacobcolvin.com/terrarium/envoy"
)

var (
	// ErrEnvoyNotRunning is returned when the Envoy proxy process exits
	// or cannot be signaled after startup.
	ErrEnvoyNotRunning = errors.New("envoy process not running")

	// ErrListenerNotReady means that a listener did not accept
	// connections, or did not answer the probe request, before the
	// startup timeout expired.
	ErrListenerNotReady = errors.New("listener not ready")

	// ErrListenAddressUnavailable means that the proxy cannot serve its
	// listen address, for example because another process holds the
	// port or because the host of the address is not an IP address.
	ErrListenAddressUnavailable = errors.New("listen address unavailable")
)

const (
	// The pause between two attempts of [waitForListener] and of
	// [waitForProxyListener].
	listenerPollInterval = 100 * time.Millisecond

	// The time that [waitForProxyListener] allows for one probe
	// request.
	probeTimeout = time.Second
)

// checkListenAddress binds the TCP address addr and releases it again.
// It returns [ErrListenAddressUnavailable] when the bind does not
// succeed.
//
// The host of addr must be an IP address, because Envoy does not bind
// a host name. For every other host, the check binds nothing and
// returns [ErrListenAddressUnavailable]. A host name can resolve to
// several addresses, and a connection to it reaches a listener on any
// of them.
//
// A caller runs it before it starts Envoy, so the caller stops early
// when another process already listens on addr. The check does not
// reserve addr, so another process can still bind addr after the check
// and before Envoy. See [waitForProxyListener] for the wait that finds
// such a process.
//
// The check binds only the address family of addr, as Envoy does. It
// does not set SO_REUSEPORT, so it also finds a listener that sets the
// option. An Envoy listener that leaves enable_reuse_port unset sets
// the option on Linux.
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

// waitForProxyListener polls the proxy listener on addr until the
// Envoy of the caller answers the probe request. That Envoy loaded the
// bootstrap that holds token, and the caller started it with token in
// the environment variable [envoy.ProxyProbeTokenEnv].
//
// A connection to addr shows only that some process listens there.
// The probe is a plain HTTP request for [envoy.ProxyProbeHost] and the
// path "/" plus token. Only a front listener whose bootstrap holds
// token answers that path with status 200, and the body of its answer
// is the value of the variable. The answer therefore holds token only
// when the Envoy that the caller started with its own bootstrap serves
// addr.
//
// It returns [ErrListenAddressUnavailable] when a process answers the
// probe with another response, because that process serves addr. An
// Envoy that loaded the bootstrap of another proxy answers with status
// 404. An Envoy of another proxy that loaded the bootstrap of the
// caller answers with another body. Two proxies that write their
// bootstraps to one path can start such an Envoy. A process that
// accepts the connection and sends no HTTP response does not end the
// wait.
//
// It returns [ErrListenerNotReady] when the timeout expires first.
// When the caller cancels ctx first, it returns the context's error
// without waiting for the next poll.
func waitForProxyListener(ctx context.Context, addr, token string, timeout time.Duration) error {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := &http.Client{
		Timeout: probeTimeout,
		// A zero Transport ignores the proxy variables of the
		// environment, which can name this proxy.
		Transport: &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for {
		own, err := probeProxyListener(waitCtx, client, addr, token)

		switch {
		case err != nil:
			// No HTTP response yet. Envoy resets early connections
			// while its workers start.

		case own:
			return nil

		default:
			return fmt.Errorf("%w: %s: another process serves the address",
				ErrListenAddressUnavailable, addr)
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

// probeProxyListener sends one probe request for token to addr. It
// reports whether the response has status 200 and token as the body.
// It returns an error when it receives no complete HTTP response.
func probeProxyListener(ctx context.Context, client *http.Client, addr, token string) (bool, error) {
	// An IPv6 address with a zone, such as fe80::1%eth0, holds a
	// percent sign. A URL with the raw sign does not parse, and
	// [url.URL.String] escapes the sign.
	probeURL := url.URL{Scheme: "http", Host: addr, Path: "/" + token}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL.String(), http.NoBody)
	if err != nil {
		return false, fmt.Errorf("building probe request: %w", err)
	}

	req.Host = envoy.ProxyProbeHost

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("sending probe request: %w", err)
	}

	// One byte more than the token shows a longer body.
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(len(token))+1))

	closeErr := resp.Body.Close()
	if closeErr != nil {
		slog.DebugContext(ctx, "closing probe response", slog.Any("err", closeErr))
	}

	if err != nil {
		return false, fmt.Errorf("reading probe response: %w", err)
	}

	return resp.StatusCode == http.StatusOK && string(body) == token, nil
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
