package terrarium_test

import (
	"fmt"
	"log/slog"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startMockDNS starts a mock DNS server that responds to queries with
// the given A record IP. Returns the server and its address.
func startMockDNS(t *testing.T, ip string) string {
	t.Helper()

	lc := net.ListenConfig{}

	pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	require.NoError(t, err)

	udpAddr, ok := pc.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	tcpLn, err := lc.Listen(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", udpAddr.Port))
	require.NoError(t, err)

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

	return fmt.Sprintf("127.0.0.1:%d", udpAddr.Port)
}
