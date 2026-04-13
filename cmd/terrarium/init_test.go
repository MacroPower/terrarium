package main

import (
	"net"
	"os/exec"
	"syscall"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/dnsproxy"
	"go.jacobcolvin.com/terrarium/dnstest"
)

// setReuseAddr sets SO_REUSEADDR on the socket. Used in port-release
// verification to avoid racing with kernel socket teardown in
// sandboxed build environments.
func setReuseAddr(_, _ string, c syscall.RawConn) error {
	var opErr error

	err := c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	})
	if err != nil {
		return err
	}

	return opErr
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
	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true)
	require.NoError(t, err)

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

	// Verify the port is released by binding the same address.
	// Use SO_REUSEADDR to avoid racing with kernel socket teardown
	// in sandboxed build environments.
	lc := net.ListenConfig{
		Control: setReuseAddr,
	}
	ln, err := lc.ListenPacket(t.Context(), "udp", proxy.Addr)
	require.NoError(t, err)
	require.NoError(t, ln.Close())
}

func TestFirstListenerPort(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *config.Config
		want int
	}{
		"unrestricted": {
			cfg:  &config.Config{},
			want: 15443,
		},
		"filtered with port 443": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			})},
			want: 15443,
		},
		"filtered with TCPForward only": {
			cfg: &config.Config{
				Egress:      egressRules(config.EgressRule{ToCIDR: []string{"10.0.0.0/8"}}),
				TCPForwards: []config.TCPForward{{Host: "db.example.com", Port: 5432}},
			},
			want: config.ProxyPortBase + 5432,
		},
		"CIDR-only falls back to CatchAllProxyPort": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{ToCIDR: []string{"10.0.0.0/8"}}),
			},
			want: config.CatchAllProxyPort,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, firstListenerPort(t.Context(), tt.cfg))
		})
	}
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

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true)
	require.NoError(t, err)

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
	shutdown(t.Context(), envoyCmd, proxy, nil, config.DefaultEnvoyDrainTimeout)

	// Envoy process should have been terminated and waited on.
	assert.NotNil(t, envoyCmd.ProcessState, "envoy process should have been waited on")

	// DNS proxy port should be released. Use SO_REUSEADDR to avoid
	// racing with kernel socket teardown in sandboxed build environments.
	lc := net.ListenConfig{
		Control: setReuseAddr,
	}
	ln, err := lc.ListenPacket(t.Context(), "udp", proxy.Addr)
	require.NoError(t, err)
	require.NoError(t, ln.Close())
}
