package dnstest

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/dnsproxy"
)

// listenAttempts is the number of ports that [Listen] tries before it
// fails the test.
const listenAttempts = 10

// Listen binds a UDP socket and a TCP listener to one loopback port
// and returns both with the port. The caller closes both.
//
// The kernel picks a port that is free for UDP. A TCP socket of
// another test or process can hold the same port number. When the TCP
// bind reports that the address is in use, Listen tries a different
// port.
func Listen(t *testing.T) (net.PacketConn, net.Listener, int) {
	t.Helper()

	lc := net.ListenConfig{}

	for attempt := 1; ; attempt++ {
		pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
		require.NoError(t, err)

		udpAddr, ok := pc.LocalAddr().(*net.UDPAddr)
		require.True(t, ok)

		tcpLn, err := lc.Listen(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", udpAddr.Port))
		if err == nil {
			return pc, tcpLn, udpAddr.Port
		}

		require.NoError(t, pc.Close())

		if attempt == listenAttempts || !errors.Is(err, syscall.EADDRINUSE) {
			require.NoError(t, err)
		}
	}
}

// StartProxy starts a DNS proxy that listens on a loopback port that
// the kernel picks, with IPv6 disabled. The caller shuts the proxy
// down.
//
// [dnsproxy.Start] finds a port that is free for both UDP and TCP, so
// StartProxy does not handle the collision that [Listen] describes.
func StartProxy(
	t *testing.T, cfg *config.Config, upstream string, opts ...dnsproxy.Option,
) *dnsproxy.Proxy {
	t.Helper()

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true, opts...)
	require.NoError(t, err)

	return proxy
}

// StartServer starts a mock DNS server that responds to all queries
// with a single A record pointing to ip. It listens on both UDP and
// TCP on the same random port and registers a cleanup to shut both
// down. The returned string is the "host:port" address.
func StartServer(t *testing.T, ip string) string {
	t.Helper()

	pc, tcpLn, port := Listen(t)

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)

		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP(ip),
		})
		assert.NoError(t, w.WriteMsg(resp))
	})

	udpSrv := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	tcpSrv := &dns.Server{
		Listener: tcpLn,
		Handler:  handler,
	}

	udpReady := make(chan struct{})
	tcpReady := make(chan struct{})

	udpSrv.NotifyStartedFunc = func() { close(udpReady) }
	tcpSrv.NotifyStartedFunc = func() { close(tcpReady) }

	go func() {
		err := udpSrv.ActivateAndServe()
		if err != nil {
			slog.Debug("mock dns udp server exited", slog.Any("err", err))
		}
	}()

	go func() {
		err := tcpSrv.ActivateAndServe()
		if err != nil {
			slog.Debug("mock dns tcp server exited", slog.Any("err", err))
		}
	}()

	<-udpReady
	<-tcpReady

	t.Cleanup(func() {
		assert.NoError(t, udpSrv.Shutdown())
		assert.NoError(t, tcpSrv.Shutdown())
	})

	return fmt.Sprintf("127.0.0.1:%d", port)
}
