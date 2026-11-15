//go:build linux

package main

import (
	"errors"
	"net"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/dnstest"
)

// requireUDPPortReleased fails the test unless the UDP address addr
// can be bound again within a few seconds.
//
// The bind can fail for a moment after the owner closes its socket. A
// parallel test that starts a child process copies every open
// descriptor into the child at fork. The copy keeps the port bound
// until the child calls exec. SO_REUSEADDR does not help, because the
// kernel honors it for UDP only when both sockets set it.
func requireUDPPortReleased(t *testing.T, addr string) {
	t.Helper()

	lc := net.ListenConfig{}

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		ln, err := lc.ListenPacket(t.Context(), "udp", addr)
		if !assert.NoError(c, err) {
			return
		}

		assert.NoError(c, ln.Close())
	}, 5*time.Second, 10*time.Millisecond)
}

func TestParseUpstreamDNS(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		resolvConf string
		want       string
	}{
		"standard": {
			resolvConf: "nameserver 8.8.8.8\nnameserver 8.8.4.4\n",
			want:       "8.8.8.8",
		},
		"multiple nameservers": {
			resolvConf: "search example.com\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n",
			want:       "1.1.1.1",
		},
		"skip ipv6 loopback": {
			resolvConf: "nameserver ::1\nnameserver 8.8.8.8\n",
			want:       "8.8.8.8",
		},
		"ipv6 non-loopback": {
			resolvConf: "nameserver 2001:4860:4860::8888\n",
			want:       "2001:4860:4860::8888",
		},
		"skip loopback": {
			resolvConf: "nameserver 127.0.0.1\nnameserver ::1\nnameserver 127.0.0.53\n",
			want:       "127.0.0.53",
		},
		"all loopback": {
			resolvConf: "nameserver 127.0.0.1\nnameserver ::1\n",
		},
		"empty": {
			resolvConf: "search example.com\n",
		},
		"comments and whitespace": {
			resolvConf: "# comment\n  nameserver  10.0.0.1  \n",
			want:       "10.0.0.1",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, ParseUpstreamDNS(tt.resolvConf))
		})
	}
}

// TestUserCommandResult names each test case after the way that the
// user command ends. Each case runs its script in a shell and passes
// the error from the wait to userCommandResult.
func TestUserCommandResult(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		script string
		// want is the code of the [*ExitError], or 0 for a nil result.
		want int
	}{
		"exits with status 0": {
			script: "exit 0",
			want:   0,
		},
		"exits with status 42": {
			script: "exit 42",
			want:   42,
		},
		// A shell exits with this status after SIGKILL ends one of
		// its own commands, so the code matches the SIGKILL case.
		"exits with status 137": {
			script: "exit 137",
			want:   137,
		},
		"ends on SIGKILL": {
			script: "kill -KILL $$",
			want:   137,
		},
		"ends on SIGTERM": {
			script: "kill -TERM $$",
			want:   143,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cmd := exec.CommandContext(t.Context(), "sh", "-c", tt.script)

			err := userCommandResult(t.Context(), cmd.Run())
			if tt.want == 0 {
				require.NoError(t, err)

				return
			}

			var exitErr *ExitError

			require.ErrorAs(t, err, &exitErr)
			assert.Equal(t, tt.want, exitErr.Code)
		})
	}
}

// TestUserCommandResultLogsSignal checks that userCommandResult logs
// a warning only for a user command that a signal ends. It replaces
// the default logger, which is incompatible with t.Parallel().
//
//nolint:paralleltest // see comment above.
func TestUserCommandResultLogsSignal(t *testing.T) {
	const msg = "user command ended on a signal"

	tests := map[string]struct {
		script string
		// want is the signal attribute of the warning, or empty
		// when userCommandResult must log no warning.
		want string
	}{
		"exits with status 0": {
			script: "exit 0",
		},
		"exits with status 42": {
			script: "exit 42",
		},
		// A shell exits with this status after a signal ends one of
		// its own commands.
		"exits with status 137": {
			script: "exit 137",
		},
		"ends on SIGKILL": {
			script: "kill -KILL $$",
			want:   "signal=killed",
		},
		"ends on SIGTERM": {
			script: "kill -TERM $$",
			want:   "signal=terminated",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			logs := captureLogs(t)

			cmd := exec.CommandContext(t.Context(), "sh", "-c", tt.script)

			//nolint:errcheck // TestUserCommandResult checks the result.
			userCommandResult(t.Context(), cmd.Run())

			if tt.want == "" {
				assert.NotContains(t, logs.String(), msg)

				return
			}

			assert.Contains(t, logs.String(), "level=WARN")
			assert.Contains(t, logs.String(), msg)
			assert.Contains(t, logs.String(), tt.want)
		})
	}
}

// TestEndingSignal names each test case after the way that the
// process ends. Each case runs its script in a shell and passes the
// error from the wait to endingSignal.
func TestEndingSignal(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		script string
		// want is the signal that ended the process, or 0 for a
		// process that exited on its own.
		want syscall.Signal
	}{
		"exits with status 42": {
			script: "exit 42",
		},
		// A shell exits with this status after a signal ends one of
		// its own commands.
		"exits with status 137": {
			script: "exit 137",
		},
		"ends on SIGKILL": {
			script: "kill -KILL $$",
			want:   syscall.SIGKILL,
		},
		"ends on SIGTERM": {
			script: "kill -TERM $$",
			want:   syscall.SIGTERM,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cmd := exec.CommandContext(t.Context(), "sh", "-c", tt.script)

			var exitErr *exec.ExitError

			require.ErrorAs(t, cmd.Run(), &exitErr)

			got, ok := endingSignal(exitErr)
			assert.Equal(t, tt.want != 0, ok)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUserCommandResultWaitError(t *testing.T) {
	t.Parallel()

	waitErr := errors.New("no child processes")

	err := userCommandResult(t.Context(), waitErr)
	require.ErrorIs(t, err, waitErr)
	require.ErrorContains(t, err, "waiting for user command")

	var exitErr *ExitError

	assert.NotErrorAs(t, err, &exitErr)
}

func TestDNSProxyShutdownOnInitFailure(t *testing.T) {
	t.Parallel()

	// Start a mock upstream DNS server.
	upstream := dnstest.StartServer(t, "1.2.3.4")

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
		}),
	}

	// Start the DNS proxy (simulates the Init step that succeeds).
	proxy := dnstest.StartProxy(t, cfg, upstream)

	// Verify the proxy is serving queries.
	client := &dns.Client{Net: "udp"}
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

	// Simulate Init failure cleanup: shut down the DNS proxy (what
	// the defer in Init does on error return).
	require.NoError(t, proxy.Shutdown())

	// Verify that Shutdown released the port.
	requireUDPPortReleased(t, proxy.Addr)
}

func TestShutdownOrder(t *testing.T) {
	t.Parallel()

	// Start a mock upstream DNS server and a DNS proxy.
	upstream := dnstest.StartServer(t, "1.2.3.4")

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
		}),
	}

	proxy := dnstest.StartProxy(t, cfg, upstream)

	// Start a long-running subprocess to simulate Envoy.
	envoyCmd := exec.CommandContext(t.Context(), "sleep", "60")
	require.NoError(t, envoyCmd.Start())

	// Verify DNS proxy is serving before shutdown.
	client := &dns.Client{Net: "udp"}
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

	// DNS should still be resolvable while Envoy is draining.
	// We verify this by checking that after shutdown returns,
	// the Envoy process has already exited (was waited on) and
	// the DNS proxy port is released.
	shutdown(t.Context(), &infra{
		envoyCmd:     envoyCmd,
		dnsProxy:     proxy,
		drainTimeout: config.DefaultEnvoyDrainTimeout,
	})

	// Envoy process should have been terminated and waited on.
	assert.NotNil(t, envoyCmd.ProcessState, "envoy process should have been waited on")

	// The shutdown must release the DNS proxy port.
	requireUDPPortReleased(t, proxy.Addr)
}
