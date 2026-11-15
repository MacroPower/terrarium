package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/accesslog"
	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoy"
)

func TestCheckListenAddress(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// err is an error that the check must wrap. Every case with
		// an err also requires [ErrListenAddressUnavailable].
		err error
		// held is the IP address that another listener holds on the
		// port. An empty value leaves the port free.
		held string
		// host is the host of the address to check.
		host string
		// linuxOnly marks a case that depends on the bind rules of
		// Linux.
		linuxOnly bool
	}{
		"free address": {
			host: loopbackIPv4,
		},
		"address in use": {
			held: loopbackIPv4,
			host: loopbackIPv4,
			err:  syscall.EADDRINUSE,
		},
		// Go sets SO_REUSEADDR on every listener. With that option
		// on both sockets, only Linux refuses a wildcard bind beside
		// a listener on a specific address.
		"wildcard over an address in use": {
			held:      loopbackIPv4,
			host:      "0.0.0.0",
			err:       syscall.EADDRINUSE,
			linuxOnly: true,
		},
		"IPv6 address in use": {
			held: loopbackIPv6,
			host: loopbackIPv6,
			err:  syscall.EADDRINUSE,
		},
		// Envoy binds an IPv4 wildcard for IPv4 alone, so an IPv6
		// listener on the port does not block it.
		"IPv4 wildcard beside an IPv6 listener": {
			held: loopbackIPv6,
			host: "0.0.0.0",
		},
		"address not on the host": {
			// The address is in TEST-NET-1 of RFC 5737.
			host: "192.0.2.1",
			err:  syscall.EADDRNOTAVAIL,
		},
		// The name resolves to a loopback address, so a bind of the
		// name succeeds. The check must refuse the name itself.
		"host name": {
			host: "localhost",
			err:  ErrListenAddressUnavailable,
		},
		"empty host": {
			err: ErrListenAddressUnavailable,
		},
	}

	// The kernel can give one port to two listeners that ask at
	// different times or for different address families. A case
	// that shared its port with another case would see the listener
	// of that case. The test therefore opens every listener here,
	// before a subtest runs. Each case reserves its port on the IPv4
	// loopback address, and all reservations stay open until every
	// case has a port.
	var (
		lc       net.ListenConfig
		reserved []net.Listener
	)

	ports := make(map[string]string, len(tests))
	skips := make(map[string]error, len(tests))

	for name, tt := range tests {
		ln, err := lc.Listen(t.Context(), "tcp4", net.JoinHostPort(loopbackIPv4, "0"))
		require.NoError(t, err)

		_, port, err := net.SplitHostPort(ln.Addr().String())
		require.NoError(t, err)

		ports[name] = port

		// The reservation is the held listener of a case that holds
		// the IPv4 loopback address.
		if tt.held == loopbackIPv4 {
			t.Cleanup(func() {
				assert.NoError(t, ln.Close())
			})

			continue
		}

		reserved = append(reserved, ln)

		if tt.held == "" {
			continue
		}

		skips[name] = loopbackError(t, tt.held)
		if skips[name] != nil {
			continue
		}

		held, err := lc.Listen(t.Context(), "tcp", net.JoinHostPort(tt.held, port))
		require.NoError(t, err)

		t.Cleanup(func() {
			assert.NoError(t, held.Close())
		})
	}

	for _, ln := range reserved {
		require.NoError(t, ln.Close())
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if tt.linuxOnly && runtime.GOOS != "linux" {
				t.Skip("needs the bind rules of Linux")
			}

			if skips[name] != nil {
				t.Skip(skips[name])
			}

			addr := net.JoinHostPort(tt.host, ports[name])

			err := checkListenAddress(t.Context(), addr)
			if tt.err == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrListenAddressUnavailable)
			require.ErrorIs(t, err, tt.err)
			require.ErrorContains(t, err, addr)
		})
	}
}

// readySocket returns the path of a ready socket in a directory that
// the test removes.
func readySocket(t *testing.T) string {
	t.Helper()

	socket, err := newReadySocket(t.Context(), shortTempDir(t), os.Getgid())
	require.NoError(t, err)

	return socket
}

// serveReadySocket answers every request on socket with status, as
// the ready listener of Envoy does with status 200.
func serveReadySocket(t *testing.T, socket string, status int) {
	t.Helper()

	lc := net.ListenConfig{}

	ln, err := lc.Listen(t.Context(), "unix", socket)
	require.NoError(t, err)

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		serveErr := srv.Serve(ln)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Logf("ready socket serve: %v", serveErr)
		}
	}()

	t.Cleanup(func() {
		assert.NoError(t, srv.Close())
	})
}

func TestNewReadySocket(t *testing.T) {
	t.Parallel()

	// The parent does not exist before the first call.
	parent := filepath.Join(shortTempDir(t), "run")

	first, err := newReadySocket(t.Context(), parent, os.Getgid())
	require.NoError(t, err)

	second, err := newReadySocket(t.Context(), parent, os.Getgid())
	require.NoError(t, err)

	// Every Envoy start gets a directory of its own inside the parent.
	// The socket of an earlier Envoy therefore never has the path of
	// the socket of a later one.
	assert.Equal(t, parent, filepath.Dir(filepath.Dir(first)))
	assert.Equal(t, parent, filepath.Dir(filepath.Dir(second)))
	assert.NotEqual(t, filepath.Dir(first), filepath.Dir(second))
	require.NoError(t, accesslog.CheckSocketPath(first))

	// The owner and the group have full access, and no other user has
	// any. The owner is the user of the test, and the group is the
	// group that the test passed.
	info, err := os.Stat(filepath.Dir(first))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o770), info.Mode().Perm())

	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	assert.Equal(t, os.Getuid(), int(stat.Uid))
	assert.Equal(t, os.Getgid(), int(stat.Gid))

	// The directory starts without the socket. Envoy creates it.
	assert.NoFileExists(t, first)

	removeReadySocket(t.Context(), first)
	assert.NoDirExists(t, filepath.Dir(first))
	assert.DirExists(t, filepath.Dir(second))
}

// otherGroup returns the ID of a group that is not the group of the
// test process and that the test process can give to a directory. It
// skips the test when the process has no such group, as in a user
// namespace that maps one group ID.
func otherGroup(t *testing.T) int {
	t.Helper()

	candidates, err := os.Getgroups()
	require.NoError(t, err)

	// Root can give a directory every group ID that the user namespace
	// maps.
	if os.Geteuid() == 0 {
		candidates = append(candidates, os.Getgid()+1)
	}

	probe := t.TempDir()

	for _, gid := range candidates {
		if gid == os.Getgid() {
			continue
		}

		if os.Chown(probe, -1, gid) == nil {
			return gid
		}
	}

	t.Skip("the test process cannot give a directory another group")

	return 0
}

// TestNewReadySocketGroup checks that the directory gets the group
// that the caller passes, which differs from the group of a new
// directory. Envoy runs with that group and creates the socket through
// the group access.
func TestNewReadySocketGroup(t *testing.T) {
	t.Parallel()

	gid := otherGroup(t)

	socket, err := newReadySocket(t.Context(), shortTempDir(t), gid)
	require.NoError(t, err)

	info, err := os.Stat(filepath.Dir(socket))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o770), info.Mode().Perm())

	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	assert.Equal(t, os.Getuid(), int(stat.Uid))
	assert.Equal(t, gid, int(stat.Gid))
}

func TestNewReadySocketErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// parent returns the parent directory for the call. The
		// path is below base, which exists.
		parent func(t *testing.T, base string) string
		// err is an error that the call must wrap.
		err error
		// msg is a text that the error must hold.
		msg string
	}{
		"parent leaves no room for the socket": {
			parent: func(_ *testing.T, base string) string {
				return filepath.Join(base, strings.Repeat("p", accesslog.MaxSocketPathLen))
			},
			err: accesslog.ErrSocketPathTooLong,
			msg: "preparing ready socket",
		},
		"parent below a regular file": {
			parent: func(t *testing.T, base string) string {
				t.Helper()

				file := filepath.Join(base, "file")
				require.NoError(t, os.WriteFile(file, nil, 0o600))

				return filepath.Join(file, "run")
			},
			msg: "creating ready socket directory",
		},
		"parent without write access": {
			parent: func(t *testing.T, base string) string {
				t.Helper()

				if os.Geteuid() == 0 {
					t.Skip("root can write to a directory of every mode")
				}

				parent := filepath.Join(base, "run")
				require.NoError(t, os.Mkdir(parent, 0o500))

				return parent
			},
			msg: "creating ready socket directory",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			parent := tt.parent(t, shortTempDir(t))

			socket, err := newReadySocket(t.Context(), parent, os.Getgid())
			require.Error(t, err)
			assert.Empty(t, socket)
			require.ErrorContains(t, err, tt.msg)

			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			}

			// The call leaves no directory of its own behind.
			leftover, err := filepath.Glob(filepath.Join(parent, "ready-*"))
			require.NoError(t, err)
			assert.Empty(t, leftover)
		})
	}
}

// TestReadyOverlayYAML checks the value of the --config-yaml flag that
// adds the ready listener to Envoy.
func TestReadyOverlayYAML(t *testing.T) {
	t.Parallel()

	const socket = "/run/terrarium/ready-1/ready.sock"

	overlay, err := readyOverlayYAML(socket)
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(overlay, "static_resources:\n"), "overlay:\n%s", overlay)
	assert.Contains(t, overlay, "name: ready\n")
	assert.Contains(t, overlay, "path: "+socket+"\n")
	assert.Contains(t, overlay, "status: 200\n")
}

func TestWaitForEnvoy(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err    error
		notErr error
		// status is the status of every answer on the socket. A zero
		// value leaves the socket without a server.
		status  int
		timeout time.Duration
		// silent opens a socket that accepts connections and sends no
		// response.
		silent   bool
		canceled bool
	}{
		"envoy answers": {
			status:  http.StatusOK,
			timeout: 15 * time.Second,
		},
		"answer with another status": {
			status:  http.StatusServiceUnavailable,
			timeout: 300 * time.Millisecond,
			err:     ErrListenerNotReady,
		},
		"socket sends no response": {
			silent:  true,
			timeout: 300 * time.Millisecond,
			err:     ErrListenerNotReady,
		},
		"no socket": {
			timeout: 150 * time.Millisecond,
			err:     ErrListenerNotReady,
		},
		"caller cancels": {
			canceled: true,
			timeout:  15 * time.Second,
			err:      context.Canceled,
			notErr:   ErrListenerNotReady,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			socket := readySocket(t)

			switch {
			case tt.status != 0:
				serveReadySocket(t, socket, tt.status)

			case tt.silent:
				lc := net.ListenConfig{}

				ln, err := lc.Listen(t.Context(), "unix", socket)
				require.NoError(t, err)

				t.Cleanup(func() {
					assert.NoError(t, ln.Close())
				})
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			if tt.canceled {
				cancel()
			}

			err := waitForEnvoy(ctx, socket, tt.timeout)
			if tt.err == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.err)

			if tt.notErr != nil {
				require.NotErrorIs(t, err, tt.notErr)
			}
		})
	}
}

// TestWaitForEnvoyLate checks that the wait continues while the ready
// socket does not exist, and ends when Envoy answers on it.
func TestWaitForEnvoyLate(t *testing.T) {
	t.Parallel()

	socket := readySocket(t)

	errCh := make(chan error, 1)

	go func() {
		errCh <- waitForEnvoy(t.Context(), socket, 15*time.Second)
	}()

	select {
	case err := <-errCh:
		t.Fatalf("wait ended without a socket: %v", err)

	case <-time.After(3 * listenerPollInterval):
	}

	serveReadySocket(t, socket, http.StatusOK)

	require.NoError(t, <-errCh)
}

// TestStartEnvoyAndWaitNotReady checks that a process that never
// answers on the ready socket does not count as a running Envoy, and
// that the caller does not keep the process.
func TestStartEnvoyAndWaitNotReady(t *testing.T) {
	t.Parallel()

	settings := config.EnvoySettings{
		StartupTimeout: config.Duration{Duration: 300 * time.Millisecond},
		DrainTimeout:   config.Duration{Duration: 15 * time.Second},
	}

	// The process stays alive, so a signal 0 to it succeeds.
	cmd := exec.CommandContext(t.Context(), "sleep", "60")

	err := startEnvoyAndWait(t.Context(), cmd, readySocket(t), settings)
	require.ErrorIs(t, err, ErrEnvoyNotRunning)
	require.ErrorIs(t, err, ErrListenerNotReady)

	require.NotNil(t, cmd.ProcessState, "the process must have been stopped and waited on")
	assert.False(t, cmd.ProcessState.Success())
}

// TestStartEnvoyAndWaitStartFails checks the error for a command that
// does not start.
func TestStartEnvoyAndWaitStartFails(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(t.Context(), filepath.Join(t.TempDir(), "missing"))

	err := startEnvoyAndWait(t.Context(), cmd, readySocket(t), config.EnvoySettings{})
	require.ErrorContains(t, err, "starting envoy")
	require.NotErrorIs(t, err, ErrEnvoyNotRunning)
}

func TestWaitForProxyListener(t *testing.T) {
	t.Parallel()

	const token = "0123456789abcdef0123456789abcdef"

	// answer returns a handler that answers the probe request for
	// token with status and body. As Envoy does, it answers a request
	// for another path of the probe host with status 404, and a
	// request for another host with status 403.
	answer := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Host != envoy.ProxyProbeHost:
				w.WriteHeader(http.StatusForbidden)

			case r.URL.Path != "/"+token:
				w.WriteHeader(http.StatusNotFound)

			default:
				w.WriteHeader(status)

				_, err := w.Write([]byte(body))
				assert.NoError(t, err)
			}
		}
	}

	tests := map[string]struct {
		// handler serves the address. A nil handler leaves the
		// address without a listener.
		handler http.HandlerFunc
		err     error
		notErr  error
		timeout time.Duration
		// silent opens a listener that accepts connections and sends
		// no response.
		silent   bool
		canceled bool
	}{
		"own envoy answers": {
			handler: answer(http.StatusOK, token),
			timeout: 15 * time.Second,
		},
		"envoy of another proxy answers with the bootstrap of the caller": {
			handler: answer(http.StatusOK, "ffffffffffffffffffffffffffffffff"),
			timeout: 15 * time.Second,
			err:     ErrListenAddressUnavailable,
		},
		"envoy with the bootstrap of another proxy answers": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			timeout: 15 * time.Second,
			err:     ErrListenAddressUnavailable,
		},
		"answer with a longer body": {
			handler: answer(http.StatusOK, token+"0"),
			timeout: 15 * time.Second,
			err:     ErrListenAddressUnavailable,
		},
		"answer with another status": {
			handler: answer(http.StatusForbidden, token),
			timeout: 15 * time.Second,
			err:     ErrListenAddressUnavailable,
		},
		"redirect": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "http://redirect.invalid/", http.StatusFound)
			},
			timeout: 15 * time.Second,
			err:     ErrListenAddressUnavailable,
		},
		"listener sends no response": {
			silent:  true,
			timeout: 300 * time.Millisecond,
			err:     ErrListenerNotReady,
			notErr:  ErrListenAddressUnavailable,
		},
		"timeout expires": {
			timeout: 150 * time.Millisecond,
			err:     ErrListenerNotReady,
		},
		"caller cancels": {
			canceled: true,
			timeout:  15 * time.Second,
			err:      context.Canceled,
			notErr:   ErrListenerNotReady,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			opts := proxyOptions{bindAddress: loopbackIPv4, httpPort: freePort(t)}
			addr := fmt.Sprintf("%s:%d", opts.bindAddress, opts.httpPort)

			switch {
			case tt.handler != nil:
				serveProxyPort(t, opts, tt.handler)

			case tt.silent:
				listenProxyPort(t, opts)
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			if tt.canceled {
				cancel()
			}

			err := waitForProxyListener(ctx, addr, token, tt.timeout)
			if tt.err == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.err)

			if tt.notErr != nil {
				require.NotErrorIs(t, err, tt.notErr)
			}
		})
	}
}

// TestWaitForProxyListenerZone checks that the probe reaches a
// listener on an IPv6 address with a zone, such as fe80::1%eth0. The
// percent sign of the zone needs an escape in the URL of the probe
// request.
func TestWaitForProxyListenerZone(t *testing.T) {
	t.Parallel()

	const token = "0123456789abcdef0123456789abcdef"

	bindAddress := loopbackIPv6 + "%" + loopbackInterface(t)
	requireLoopback(t, bindAddress)

	opts := proxyOptions{bindAddress: bindAddress, httpPort: freePort(t)}
	addr := net.JoinHostPort(opts.bindAddress, strconv.Itoa(opts.httpPort))

	serveProxyPort(t, opts, func(w http.ResponseWriter, r *http.Request) {
		if r.Host != envoy.ProxyProbeHost || r.URL.Path != "/"+token {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		_, err := w.Write([]byte(token))
		assert.NoError(t, err)
	})

	require.NoError(t, waitForProxyListener(t.Context(), addr, token, 15*time.Second))
}

// TestWaitForProxyListenerLate checks that the wait continues while
// nothing listens on the address, and ends when the Envoy of the
// caller answers.
func TestWaitForProxyListenerLate(t *testing.T) {
	t.Parallel()

	const token = "0123456789abcdef0123456789abcdef"

	opts := proxyOptions{bindAddress: loopbackIPv4, httpPort: freePort(t)}
	addr := fmt.Sprintf("%s:%d", opts.bindAddress, opts.httpPort)

	errCh := make(chan error, 1)

	go func() {
		errCh <- waitForProxyListener(t.Context(), addr, token, 15*time.Second)
	}()

	select {
	case err := <-errCh:
		t.Fatalf("wait ended without a listener: %v", err)

	case <-time.After(3 * listenerPollInterval):
	}

	serveProxyPort(t, opts, func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write([]byte(token))
		assert.NoError(t, err)
	})

	select {
	case err := <-errCh:
		require.NoError(t, err)

	case <-time.After(15 * time.Second):
		t.Fatal("wait did not end")
	}
}
