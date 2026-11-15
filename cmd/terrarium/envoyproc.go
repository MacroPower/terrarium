package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"go.jacobcolvin.com/niceyaml"

	"go.jacobcolvin.com/terrarium/accesslog"
	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoy"
)

var (
	// ErrEnvoyNotRunning is returned when the Envoy proxy process exits
	// or does not become ready before the startup timeout expires.
	ErrEnvoyNotRunning = errors.New("envoy process not running")

	// ErrEnvoyExited means that the Envoy process exited before it
	// answered the ready request or the probe request.
	ErrEnvoyExited = errors.New("envoy exited before it was ready")

	// ErrListenerNotReady means that a listener did not answer the
	// probe request or the ready request before the startup timeout
	// expired.
	ErrListenerNotReady = errors.New("listener not ready")

	// ErrListenAddressUnavailable means that the proxy cannot serve its
	// listen address, for example because another process holds the
	// port or because the host of the address is not an IP address.
	ErrListenAddressUnavailable = errors.New("listen address unavailable")
)

const (
	// The pause between two attempts of [waitForEnvoy] and of
	// [waitForProxyListener].
	listenerPollInterval = 100 * time.Millisecond

	// The time that [waitForEnvoy] allows for one ready request, and
	// that [waitForProxyListener] allows for one probe request.
	probeTimeout = time.Second

	// The number of times that [startEnvoyWhenFree] starts a busy
	// binary again.
	busyStartRetries = 7

	// The pause of [startEnvoyWhenFree] before it starts a busy binary
	// again for the first time. Each later pause is twice as long as
	// the pause before it.
	busyStartPause = 10 * time.Millisecond

	// The name of the ready socket inside its directory.
	readySocketName = "ready.sock"

	// The URL of the ready request. The client of [waitForEnvoy] dials
	// the ready socket for every host, so the host of the URL names no
	// address.
	readyURL = "http://envoy/"
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

// newReadySocket creates a directory for the ready socket of one Envoy
// start inside parent and returns the path of the socket inside the
// new directory. It creates parent when parent does not exist. See
// [envoy.ReadyOverlay] for the listener that binds the socket.
//
// The directory has a random name and the mode 0o770. The user of the
// calling process owns it, and its group has the ID gid. That user and
// the members of that group can therefore create the socket, connect
// to it, and remove it. They do not need a capability that overrides
// file permissions. No other user can open the directory.
//
// The caller starts Envoy with the group ID gid, and it removes the
// directory with [removeReadySocket] after the wait for Envoy.
//
// It returns [accesslog.ErrSocketPathTooLong] when the path of parent
// leaves no room for the socket.
func newReadySocket(ctx context.Context, parent string, gid int) (string, error) {
	err := os.MkdirAll(parent, 0o755)
	if err != nil {
		return "", fmt.Errorf("creating ready socket directory: %w", err)
	}

	// The new directory has the mode 0o700.
	dir, err := os.MkdirTemp(parent, "ready-")
	if err != nil {
		return "", fmt.Errorf("creating ready socket directory: %w", err)
	}

	socket := filepath.Join(dir, readySocketName)

	err = accesslog.CheckSocketPath(socket)
	if err == nil {
		// The group changes before the mode gives the group access.
		err = os.Chown(dir, -1, gid)
	}

	if err == nil {
		err = os.Chmod(dir, 0o770)
	}

	if err != nil {
		removeErr := os.RemoveAll(dir)
		if removeErr != nil {
			slog.DebugContext(ctx, "removing ready socket directory", slog.Any("err", removeErr))
		}

		return "", fmt.Errorf("preparing ready socket %s: %w", socket, err)
	}

	return socket, nil
}

// removeReadySocket removes the directory that [newReadySocket] created
// for socket. Envoy keeps its ready listener, but no process can
// connect to a socket that has no path.
func removeReadySocket(ctx context.Context, socket string) {
	err := os.RemoveAll(filepath.Dir(socket))
	if err != nil {
		slog.WarnContext(ctx, "removing ready socket directory", slog.Any("err", err))
	}
}

// readyOverlayYAML returns the YAML of the [envoy.ReadyOverlay] for
// socket, which is the value of the --config-yaml flag of Envoy.
func readyOverlayYAML(socket string) (string, error) {
	var buf bytes.Buffer

	err := niceyaml.NewEncoder(&buf).Encode(envoy.BuildReadyOverlay(socket))
	if err != nil {
		return "", fmt.Errorf("marshaling ready overlay: %w", err)
	}

	return buf.String(), nil
}

// envoyProcess is an Envoy process that runs or has exited. One
// goroutine waits for the process from its start, so a caller can
// learn that the process exited without a wait of its own.
//
// Start instances with [startEnvoyProcess], and stop them with
// [stopEnvoy].
type envoyProcess struct {
	cmd *exec.Cmd

	// The channel closes after the process has exited. From then on,
	// cmd holds the process state and waitErr holds the result of the
	// wait.
	exited chan struct{}

	// The result of [exec.Cmd.Wait]. Read it only after exited closes.
	waitErr error
}

// startEnvoyProcess starts cmd and returns its [*envoyProcess]. The
// caller must not call [exec.Cmd.Wait] on cmd, because the returned
// process holds the one wait that cmd allows.
func startEnvoyProcess(ctx context.Context, cmd *exec.Cmd) (*envoyProcess, error) {
	err := cmd.Start()
	if err != nil {
		return nil, err //nolint:wrapcheck // the callers name the command.
	}

	proc := &envoyProcess{cmd: cmd, exited: make(chan struct{})}

	go func() {
		proc.waitErr = cmd.Wait()
		if proc.waitErr != nil {
			slog.DebugContext(ctx, "envoy exited", slog.Any("err", proc.waitErr))
		}

		close(proc.exited)
	}()

	return proc, nil
}

// startEnvoyWhenFree starts the command that newCmd returns, as
// [startEnvoyProcess] does. When the binary of the command is busy, it
// pauses and then starts a new command from newCmd. A command that did
// not start cannot start again, so newCmd must return a new command on
// every call.
//
// A binary is busy when a process holds it open for writing. The
// kernel does not execute such a binary, and the start returns
// [syscall.ETXTBSY]. A child process inherits the open descriptors of
// its parent and closes them only when it executes its own program. A
// child that starts during the install of a binary can therefore hold
// the binary open for writing for a moment after the install has
// closed it.
//
// The pauses double from 10 milliseconds, and they add up to less than
// 2 seconds. When the binary is still busy after the last pause,
// startEnvoyWhenFree returns the [syscall.ETXTBSY] error of the last
// start. It returns every other error of a start without a second
// start. When ctx ends during a pause, it returns the error of ctx.
func startEnvoyWhenFree(ctx context.Context, newCmd func() *exec.Cmd) (*envoyProcess, error) {
	pause := busyStartPause

	for range busyStartRetries {
		proc, err := startEnvoyProcess(ctx, newCmd())
		if !errors.Is(err, syscall.ETXTBSY) {
			return proc, err
		}

		slog.DebugContext(ctx, "envoy binary is busy, starting it again after a pause",
			slog.Duration("pause", pause),
			slog.Any("err", err))

		select {
		case <-time.After(pause):
		case <-ctx.Done():
			return nil, ctx.Err() //nolint:wrapcheck // the callers name the command.
		}

		pause *= 2
	}

	return startEnvoyProcess(ctx, newCmd())
}

// wait blocks until the process has exited, and returns the result of
// [exec.Cmd.Wait].
func (p *envoyProcess) wait() error {
	<-p.exited

	return p.waitErr
}

// startEnvoyAndWait starts cmd, which runs Envoy with the ready overlay
// for socket, and waits until that Envoy answers on socket. See
// [waitForEnvoy] for the wait.
//
// When Envoy does not answer, startEnvoyAndWait stops the process and
// returns [ErrEnvoyNotRunning]. The caller therefore never keeps an
// Envoy that did not become ready. When Envoy exits before it answers,
// the wait ends at that point, before the startup timeout expires. The
// error then also wraps [ErrEnvoyExited] and gives the exit status of
// Envoy.
func startEnvoyAndWait(
	ctx context.Context, cmd *exec.Cmd, socket string, settings config.EnvoySettings,
) (*envoyProcess, error) {
	proc, err := startEnvoyProcess(ctx, cmd)
	if err != nil {
		return nil, fmt.Errorf("starting envoy: %w", err)
	}

	err = waitForEnvoy(ctx, socket, proc.exited, settings.StartupTimeout.Duration)
	if err == nil {
		return proc, nil
	}

	stopEnvoy(ctx, proc, settings.DrainTimeout.Duration)

	if errors.Is(err, ErrEnvoyExited) {
		return nil, fmt.Errorf("%w: %w: %s", ErrEnvoyNotRunning, err, cmd.ProcessState)
	}

	return nil, fmt.Errorf("%w: %w", ErrEnvoyNotRunning, err)
}

// waitForEnvoy polls the ready socket at socket until the ready
// listener of Envoy answers a request with status 200. The answer
// shows that the listeners of that Envoy accept connections. See
// [envoy.ReadyOverlay] for the reason and for its limit.
//
// A connection to a TCP listener port shows only that some process
// listens there. The ready socket is in a directory that
// [newReadySocket] creates for one Envoy start. Only the user of the
// calling process and the group of that Envoy can open the directory.
// An answer on the socket therefore comes from the Envoy that the
// caller started with the overlay for socket. That Envoy never answers
// when it exits because another process holds one of its listener
// ports.
//
// The channel exited closes when the process of that Envoy has exited.
// A process that has exited never answers, so waitForEnvoy returns
// [ErrEnvoyExited] at that point and does not wait for the timeout. A
// nil channel never ends the wait.
//
// It returns [ErrListenerNotReady] when the timeout expires first.
// When the caller cancels ctx first, it returns the context's error
// without waiting for the next poll. The caller can then tell a
// shutdown from an Envoy that never became ready.
func waitForEnvoy(
	ctx context.Context, socket string, exited <-chan struct{}, timeout time.Duration,
) error {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := net.Dialer{}

	client := &http.Client{
		Timeout: probeTimeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", socket)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for {
		ready, err := requestReady(waitCtx, client)
		if err == nil && ready {
			return nil
		}

		// Without an answer, Envoy has not bound the socket, has not
		// started its workers, or has exited.
		select {
		case <-time.After(listenerPollInterval):
			continue

		case <-exited:
		case <-waitCtx.Done():
		}

		// A cancellation of ctx can also end the process, so the
		// cancellation comes before the exit.
		if ctx.Err() != nil {
			return fmt.Errorf("waiting for envoy on %s: %w", socket, ctx.Err())
		}

		select {
		case <-exited:
			return ErrEnvoyExited

		default:
			return fmt.Errorf("%w: %s after %v", ErrListenerNotReady, socket, timeout)
		}
	}
}

// requestReady sends one ready request through client. It reports
// whether the response has status 200. It returns an error when it
// receives no complete HTTP response.
func requestReady(ctx context.Context, client *http.Client) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, readyURL, http.NoBody)
	if err != nil {
		return false, fmt.Errorf("building ready request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("sending ready request: %w", err)
	}

	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	closeErr := resp.Body.Close()
	if closeErr != nil {
		slog.DebugContext(ctx, "closing ready response", slog.Any("err", closeErr))
	}

	if err != nil {
		return false, fmt.Errorf("reading ready response: %w", err)
	}

	return resp.StatusCode == http.StatusOK, nil
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
// The channel exited closes when the process of that Envoy has exited.
// A process that has exited never answers, so waitForProxyListener
// returns [ErrEnvoyExited] at that point and does not wait for the
// timeout. It reads the channel between two probe requests, so the
// answer of another process to the probe request that is in flight
// still returns [ErrListenAddressUnavailable]. A nil channel never
// ends the wait.
//
// It returns [ErrListenerNotReady] when the timeout expires first.
// When the caller cancels ctx first, it returns the context's error
// without waiting for the next poll. The caller can then tell a
// shutdown from an Envoy that never became ready.
func waitForProxyListener(
	ctx context.Context, addr, token string, exited <-chan struct{}, timeout time.Duration,
) error {
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
			// while its workers start, and it does not listen after
			// it has exited.

		case own:
			return nil

		default:
			return fmt.Errorf("%w: %s: another process serves the address",
				ErrListenAddressUnavailable, addr)
		}

		select {
		case <-time.After(listenerPollInterval):
			continue

		case <-exited:
		case <-waitCtx.Done():
		}

		// A cancellation of ctx can also end the process, so the
		// cancellation comes before the exit.
		if ctx.Err() != nil {
			return fmt.Errorf("waiting for listener %s: %w", addr, ctx.Err())
		}

		select {
		case <-exited:
			return fmt.Errorf("waiting for listener %s: %w", addr, ErrEnvoyExited)

		default:
			return fmt.Errorf("%w: %s after %v", ErrListenerNotReady, addr, timeout)
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

// stopEnvoy stops the Envoy process proc and waits for it, so the
// process has exited when stopEnvoy returns.
//
// It sends SIGTERM and waits up to drainTimeout for Envoy to exit.
// When Envoy still runs after drainTimeout, stopEnvoy sends SIGKILL
// and waits until the process exits. A caller that starts another
// Envoy after stopEnvoy therefore never starts it while the old Envoy
// still runs.
//
// It returns immediately when proc is nil or when the process has
// already exited.
func stopEnvoy(ctx context.Context, proc *envoyProcess, drainTimeout time.Duration) {
	if proc == nil {
		return
	}

	err := proc.cmd.Process.Signal(syscall.SIGTERM)
	if errors.Is(err, os.ErrProcessDone) {
		// The wait for the process has reaped it, so the wait ends
		// without a delay.
		<-proc.exited

		return
	}

	if err != nil {
		slog.DebugContext(ctx, "stopping envoy", slog.Any("err", err))

		return
	}

	select {
	case <-proc.exited:
		return

	case <-time.After(drainTimeout):
	}

	slog.WarnContext(ctx, "envoy did not exit within drain timeout, killing it",
		slog.Duration("drain_timeout", drainTimeout))

	// Kill reports [os.ErrProcessDone] when Envoy exited between the
	// timeout and the kill.
	err = proc.cmd.Process.Kill()
	if err != nil && !errors.Is(err, os.ErrProcessDone) {
		// Without the kill, Envoy can run forever, and so can the wait.
		slog.ErrorContext(ctx, "killing envoy", slog.Any("err", err))

		return
	}

	<-proc.exited
}
