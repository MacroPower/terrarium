package dnsproxy_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/dnsproxy"
	"go.jacobcolvin.com/terrarium/dnstest"
)

// unusedUpstream is the upstream of a proxy that never forwards a
// query.
const unusedUpstream = "192.0.2.1:53"

// portTaker binds the TCP listeners of a proxy through
// [dnsproxy.WithTCPListen]. On each call that take selects, it binds
// the address itself before the proxy does, the way another process
// can hold the port. The bind of the proxy then reports that the
// address is in use.
//
// [dnsproxy.Start] calls listen from the goroutine of its caller, so
// the fields do not need a lock.
type portTaker struct {
	t *testing.T
	// take reports whether the taker binds the address of the call
	// with this number, counted from 1. A nil take selects no call.
	take func(call int) bool
	// addrs holds the address of each call, in order.
	addrs []string
	// taken holds the address of each call that take selected.
	taken []string
}

func (pt *portTaker) listen(ctx context.Context, lc *net.ListenConfig, addr string) (net.Listener, error) {
	pt.addrs = append(pt.addrs, addr)

	if pt.take != nil && pt.take(len(pt.addrs)) {
		pt.taken = append(pt.taken, addr)

		// When this bind fails, another process holds the address, and
		// the bind of the proxy fails in the same way.
		ln, err := lc.Listen(ctx, "tcp", addr)
		if err == nil {
			pt.t.Cleanup(func() { assert.NoError(pt.t, ln.Close()) })
		}
	}

	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listening TCP %s: %w", addr, err)
	}

	return ln, nil
}

// port returns the port of the "host:port" address addr.
func port(t *testing.T, addr string) int {
	t.Helper()

	_, portStr, err := net.SplitHostPort(addr)
	require.NoError(t, err)

	p, err := strconv.Atoi(portStr)
	require.NoError(t, err)

	return p
}

// requirePortFree checks that UDP and TCP can bind p on 127.0.0.1 and,
// with ipv6, on ::1. It skips the address of the taker, which holds
// TCP on that address.
func requirePortFree(t *testing.T, p int, ipv6 bool, taken string) {
	t.Helper()

	lc := net.ListenConfig{}

	hosts := []string{"127.0.0.1"}
	if ipv6 {
		hosts = append(hosts, "::1")
	}

	for _, host := range hosts {
		addr := net.JoinHostPort(host, strconv.Itoa(p))

		pc, err := lc.ListenPacket(t.Context(), "udp", addr)
		require.NoError(t, err, "udp %s", addr)
		require.NoError(t, pc.Close())

		if addr == taken {
			continue
		}

		ln, err := lc.Listen(t.Context(), "tcp", addr)
		require.NoError(t, err, "tcp %s", addr)
		require.NoError(t, ln.Close())
	}
}

// requireIPv6Loopback skips the test when the host cannot listen on
// ::1.
func requireIPv6Loopback(t *testing.T) {
	t.Helper()

	lc := net.ListenConfig{}

	ln, err := lc.Listen(t.Context(), "tcp", "[::1]:0")
	if err != nil {
		t.Skipf("loopback address ::1 unavailable: %v", err)
	}

	require.NoError(t, ln.Close())
}

func TestStartTriesAnotherPort(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		// takeCall is the call of the TCP listen function whose
		// address the test takes. With IPv6, the second call of an
		// attempt binds the IPv6 listener.
		takeCall int
		ipv6     bool
	}{
		"IPv4 TCP port in use": {takeCall: 1},
		"IPv6 TCP port in use": {takeCall: 2, ipv6: true},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if tc.ipv6 {
				requireIPv6Loopback(t)
			}

			upstream := dnstest.StartServer(t, "10.9.8.7")
			taker := &portTaker{t: t, take: func(call int) bool { return call == tc.takeCall }}

			// A nil config makes the proxy forward every query.
			proxy, err := dnsproxy.Start(t.Context(), nil, upstream, "127.0.0.1:0", !tc.ipv6,
				dnsproxy.WithTCPListen(taker.listen),
			)
			require.NoError(t, err)

			t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

			require.Len(t, taker.taken, 1)

			failedPort := port(t, taker.taken[0])
			assert.NotEqual(t, failedPort, port(t, proxy.Addr))

			// Start closed every socket of the attempt that failed, so
			// only the TCP listener of the taker holds the port.
			requirePortFree(t, failedPort, tc.ipv6, taker.taken[0])

			addrs := []string{proxy.Addr}
			if tc.ipv6 {
				addrs = append(addrs, net.JoinHostPort("::1", strconv.Itoa(port(t, proxy.Addr))))
			}

			for _, addr := range addrs {
				for _, network := range []string{"udp", "tcp"} {
					client := &dns.Client{Net: network}
					msg := new(dns.Msg)
					msg.SetQuestion("retry.example.com.", dns.TypeA)

					resp, _, err := client.Exchange(msg, addr)
					require.NoError(t, err, "%s %s", network, addr)
					require.NotNil(t, resp)
					assert.Len(t, resp.Answer, 1, "%s %s", network, addr)
				}
			}
		})
	}
}

func TestStartPortsInUse(t *testing.T) {
	t.Parallel()

	taker := &portTaker{t: t, take: func(int) bool { return true }}

	_, err := dnsproxy.Start(t.Context(), nil, unusedUpstream, "127.0.0.1:0", true,
		dnsproxy.WithTCPListen(taker.listen),
	)
	require.ErrorIs(t, err, syscall.EADDRINUSE)
	require.Len(t, taker.addrs, dnsproxy.BindAttempts)

	// Start closed the UDP socket of the attempt that failed, so the
	// port is free for UDP again.
	lc := net.ListenConfig{}

	pc, err := lc.ListenPacket(t.Context(), "udp", taker.addrs[len(taker.addrs)-1])
	require.NoError(t, err)
	require.NoError(t, pc.Close())
}

func TestStartOtherBindError(t *testing.T) {
	t.Parallel()

	errBind := errors.New("bind refused")

	// Start calls listen from the goroutine of the test, so addrs does
	// not need a lock.
	var addrs []string

	listen := func(_ context.Context, _ *net.ListenConfig, addr string) (net.Listener, error) {
		addrs = append(addrs, addr)

		return nil, errBind
	}

	_, err := dnsproxy.Start(t.Context(), nil, unusedUpstream, "127.0.0.1:0", true,
		dnsproxy.WithTCPListen(listen),
	)
	require.ErrorIs(t, err, errBind)

	// Start retries only a bind that reports that the address is in
	// use, so it returns the error of the first attempt.
	require.Len(t, addrs, 1)

	// Start closed the UDP socket of the attempt.
	requirePortFree(t, port(t, addrs[0]), false, "")
}

func TestStartFixedPortInUse(t *testing.T) {
	t.Parallel()

	// Keep the TCP listener, so that the port is free only for UDP.
	pc, ln, p := dnstest.Listen(t)
	require.NoError(t, pc.Close())

	t.Cleanup(func() { assert.NoError(t, ln.Close()) })

	taker := &portTaker{t: t}

	_, err := dnsproxy.Start(t.Context(), nil, unusedUpstream, net.JoinHostPort("127.0.0.1", strconv.Itoa(p)), true,
		dnsproxy.WithTCPListen(taker.listen),
	)
	require.ErrorIs(t, err, syscall.EADDRINUSE)

	// Start does not try a port that the caller did not name. Another
	// process can take the UDP port after the test closes it, and
	// Start then fails before it binds TCP.
	assert.LessOrEqual(t, len(taker.addrs), 1)
}
