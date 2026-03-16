package dnsproxy_test

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/dnsproxy"
	"go.jacobcolvin.com/terrarium/dnstest"
)

func egressRules(rules ...config.EgressRule) *[]config.EgressRule {
	return &rules
}

func TestStart(t *testing.T) {
	t.Parallel()

	upstream := dnstest.StartServer(t, "1.2.3.4")

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "match.example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
		}),
	}

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	// Query a matching domain through the proxy.
	client := &dns.Client{Net: "udp"}
	msg := new(dns.Msg)
	msg.SetQuestion("match.example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 1)

	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, "1.2.3.4", a.A.String())

	// Query a non-matching domain -- should get REFUSED in restricted mode.
	msg2 := new(dns.Msg)
	msg2.SetQuestion("nomatch.example.com.", dns.TypeA)

	resp2, _, err := client.Exchange(msg2, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp2)
	assert.Equal(t, dns.RcodeRefused, resp2.Rcode)
}

func TestProxyTCPPassthrough(t *testing.T) {
	t.Parallel()

	upstream := dnstest.StartServer(t, "5.6.7.8")

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "tcp.example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
		}),
	}

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	// TCP query for allowed domain should succeed.
	client := &dns.Client{Net: "tcp"}
	msg := new(dns.Msg)
	msg.SetQuestion("tcp.example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 1)

	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, "5.6.7.8", a.A.String())
}

func TestProxyBlockedMode(t *testing.T) {
	t.Parallel()

	upstream := dnstest.StartServer(t, "1.2.3.4")

	// Blocked config: egress: [{}] with default deny.
	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{}),
	}

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	// All queries should get REFUSED.
	client := &dns.Client{Net: "udp"}
	msg := new(dns.Msg)
	msg.SetQuestion("anything.example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeRefused, resp.Rcode)
	assert.Empty(t, resp.Answer)
}

func TestProxyRestrictedMode(t *testing.T) {
	t.Parallel()

	upstream := dnstest.StartServer(t, "10.0.0.1")

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "allowed.example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
		}),
	}

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	client := &dns.Client{Net: "udp"}

	// Allowed domain should succeed.
	msg := new(dns.Msg)
	msg.SetQuestion("allowed.example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 1)

	// Subdomain of allowed domain should get REFUSED (exact match only).
	msg2 := new(dns.Msg)
	msg2.SetQuestion("sub.allowed.example.com.", dns.TypeA)

	resp2, _, err := client.Exchange(msg2, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp2)
	assert.Equal(t, dns.RcodeRefused, resp2.Rcode)

	// Disallowed domain should get REFUSED.
	msg3 := new(dns.Msg)
	msg3.SetQuestion("blocked.example.com.", dns.TypeA)

	resp3, _, err := client.Exchange(msg3, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp3)
	assert.Equal(t, dns.RcodeRefused, resp3.Rcode)
}

func TestProxyRestrictedWildcard(t *testing.T) {
	t.Parallel()

	upstream := dnstest.StartServer(t, "10.0.0.2")

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
		}),
	}

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	client := &dns.Client{Net: "udp"}

	// Subdomain should succeed.
	msg := new(dns.Msg)
	msg.SetQuestion("sub.example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

	// Bare parent should get REFUSED (wildcard excludes bare parent).
	msg2 := new(dns.Msg)
	msg2.SetQuestion("example.com.", dns.TypeA)

	resp2, _, err := client.Exchange(msg2, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp2)
	assert.Equal(t, dns.RcodeRefused, resp2.Rcode)

	// Multi-label subdomain should get REFUSED (single-star depth).
	msg3 := new(dns.Msg)
	msg3.SetQuestion("a.b.example.com.", dns.TypeA)

	resp3, _, err := client.Exchange(msg3, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp3)
	assert.Equal(t, dns.RcodeRefused, resp3.Rcode)
}

func TestProxyBareWildcard(t *testing.T) {
	t.Parallel()

	upstream := dnstest.StartServer(t, "10.0.0.3")

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchPattern: "*"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
		}),
	}

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	// Bare wildcard should forward all queries.
	client := &dns.Client{Net: "udp"}
	msg := new(dns.Msg)
	msg.SetQuestion("anything.anywhere.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 1)
}

func TestProxyUnrestrictedMode(t *testing.T) {
	t.Parallel()

	upstream := dnstest.StartServer(t, "10.0.0.4")

	// nil config -> unrestricted.
	proxy, err := dnsproxy.Start(t.Context(), nil, upstream, "127.0.0.1:0", true)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	client := &dns.Client{Net: "udp"}
	msg := new(dns.Msg)
	msg.SetQuestion("anything.example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 1)
}

func TestProxyTCPPopulatesIPSet(t *testing.T) {
	t.Parallel()

	upstream := dnstest.StartServer(t, "10.20.30.40")

	var (
		mu       sync.Mutex
		recorded []string
	)

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "tcp-ipset.example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
		}),
	}

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true,
		dnsproxy.WithFQDNSetFunc(func(_ context.Context, setName string, ips []net.IP, ttl time.Duration) error {
			mu.Lock()
			defer mu.Unlock()

			recorded = append(recorded, fmt.Sprintf("%s %v %v", setName, ips, ttl))

			return nil
		}),
	)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	// TCP query should populate FQDN set.
	client := &dns.Client{Net: "tcp"}
	msg := new(dns.Msg)
	msg.SetQuestion("tcp-ipset.example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 1)

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, recorded, 1)
	assert.Contains(t, recorded[0], "terrarium_fqdn4_0")
	assert.Contains(t, recorded[0], "10.20.30.40")
}

func TestProxyTruncatedUDPThenTCPRetry(t *testing.T) {
	t.Parallel()

	// Mock upstream that returns a truncated UDP response,
	// then a full TCP response with A records.
	lc := net.ListenConfig{}

	pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	require.NoError(t, err)

	udpAddr, ok := pc.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	tcpLn, err := lc.Listen(t.Context(), "tcp", fmt.Sprintf("127.0.0.1:%d", udpAddr.Port))
	require.NoError(t, err)

	// UDP handler: return truncated response with no answers.
	udpHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)

		resp.Truncated = true

		assert.NoError(t, w.WriteMsg(resp))
	})

	// TCP handler: return full response with A records.
	tcpHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)

		resp.Answer = append(resp.Answer,
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("1.1.1.1"),
			},
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("2.2.2.2"),
			},
		)
		assert.NoError(t, w.WriteMsg(resp))
	})

	udpSrv := &dns.Server{PacketConn: pc, Handler: udpHandler}
	tcpSrv := &dns.Server{Listener: tcpLn, Handler: tcpHandler}

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

	upstreamAddr := fmt.Sprintf("127.0.0.1:%d", udpAddr.Port)

	var (
		mu       sync.Mutex
		recorded []string
	)

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "truncated.example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
		}),
	}

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstreamAddr, "127.0.0.1:0", true,
		dnsproxy.WithFQDNSetFunc(func(_ context.Context, setName string, ips []net.IP, ttl time.Duration) error {
			mu.Lock()
			defer mu.Unlock()

			recorded = append(recorded, fmt.Sprintf("%s %v %v", setName, ips, ttl))

			return nil
		}),
	)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	// Step 1: UDP query gets truncated response (no IPs to populate).
	udpClient := &dns.Client{Net: "udp"}
	msg := new(dns.Msg)
	msg.SetQuestion("truncated.example.com.", dns.TypeA)

	resp, _, err := udpClient.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.True(t, resp.Truncated)

	mu.Lock()
	assert.Empty(t, recorded, "truncated UDP response should not populate set")
	mu.Unlock()

	// Step 2: TCP retry gets full response with A records.
	tcpClient := &dns.Client{Net: "tcp"}

	resp2, _, err := tcpClient.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp2)
	assert.Equal(t, dns.RcodeSuccess, resp2.Rcode)
	require.Len(t, resp2.Answer, 2)

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, recorded, 1, "TCP retry should populate set")
	assert.Contains(t, recorded[0], "terrarium_fqdn4_0")
	assert.Contains(t, recorded[0], "1.1.1.1")
	assert.Contains(t, recorded[0], "2.2.2.2")
}

// startOversizedMockDNS starts a mock DNS server that returns many A
// records, producing a response that exceeds 512 bytes uncompressed.
func startOversizedMockDNS(t *testing.T) string {
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

		resp.Compress = true // Compress upstream so all records fit over UDP.

		// Add enough A records to exceed 512 bytes uncompressed.
		for i := range 20 {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP(fmt.Sprintf("10.0.%d.%d", i/256, i%256)),
			})
		}

		assert.NoError(t, w.WriteMsg(resp))
	})

	udpSrv := &dns.Server{PacketConn: pc, Handler: handler}
	tcpSrv := &dns.Server{Listener: tcpLn, Handler: handler}

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

func TestProxyUDPCompressionOversized(t *testing.T) {
	t.Parallel()

	upstream := startOversizedMockDNS(t)

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "compress.example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
		}),
	}

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	// UDP query for a domain that returns an oversized response.
	// Without compression, this would exceed the 512-byte UDP limit.
	// The proxy should compress it so all 20 records arrive intact.
	client := &dns.Client{Net: "udp"}
	msg := new(dns.Msg)
	msg.SetQuestion("compress.example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	assert.Len(t, resp.Answer, 20, "all 20 A records should arrive via compressed UDP")
}

func TestProxyTCPNoCompression(t *testing.T) {
	t.Parallel()

	upstream := startOversizedMockDNS(t)

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "compress.example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
		}),
	}

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	// TCP query should succeed with all records regardless of size.
	// Compression should NOT be applied for TCP (proto != "udp").
	client := &dns.Client{Net: "tcp"}
	msg := new(dns.Msg)
	msg.SetQuestion("compress.example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
	assert.Len(t, resp.Answer, 20, "all 20 A records should arrive via TCP")
	assert.False(t, resp.Compress, "TCP response should not have Compress flag set")
}

func TestProxyTCPForwardHosts(t *testing.T) {
	t.Parallel()

	upstream := dnstest.StartServer(t, "10.0.0.6")

	// Restricted mode with a TCPForward host that should be resolvable.
	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "github.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
		}),
		TCPForwards: []config.TCPForward{{Port: 22, Host: "git.example.com"}},
	}

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	client := &dns.Client{Net: "udp"}

	// FQDN domain should resolve.
	msg := new(dns.Msg)
	msg.SetQuestion("github.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

	// TCPForward host should also resolve.
	msg2 := new(dns.Msg)
	msg2.SetQuestion("git.example.com.", dns.TypeA)

	resp2, _, err := client.Exchange(msg2, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp2)
	assert.Equal(t, dns.RcodeSuccess, resp2.Rcode)

	// Unrelated domain should get REFUSED.
	msg3 := new(dns.Msg)
	msg3.SetQuestion("blocked.org.", dns.TypeA)

	resp3, _, err := client.Exchange(msg3, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp3)
	assert.Equal(t, dns.RcodeRefused, resp3.Rcode)
}

// startCNAMEMockDNS starts a mock DNS server that returns a CNAME
// chain followed by an A record. The CNAME has cnameTTL and the A
// record has aTTL.
func startCNAMEMockDNS(t *testing.T, cnameTTL, aTTL uint32) string {
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

		resp.Answer = append(resp.Answer,
			&dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    cnameTTL,
				},
				Target: "target.cdn.example.com.",
			},
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "target.cdn.example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    aTTL,
				},
				A: net.ParseIP("10.99.0.1"),
			},
		)
		assert.NoError(t, w.WriteMsg(resp))
	})

	udpSrv := &dns.Server{PacketConn: pc, Handler: handler}
	tcpSrv := &dns.Server{Listener: tcpLn, Handler: handler}

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

func TestProxyCNAMEMinTTL(t *testing.T) {
	t.Parallel()

	// CNAME TTL=30, A TTL=300 -- set should use TTL=60
	// (30 is below minIPSetTTL=60).
	upstream := startCNAMEMockDNS(t, 30, 300)

	var mu sync.Mutex

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "cname.example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
		}),
	}

	type setCall struct {
		ips []net.IP
		ttl time.Duration
	}

	var calls []setCall

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true,
		dnsproxy.WithFQDNSetFunc(func(_ context.Context, setName string, ips []net.IP, ttl time.Duration) error {
			mu.Lock()
			defer mu.Unlock()

			calls = append(calls, setCall{ips: ips, ttl: ttl})

			return nil
		}),
	)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	client := &dns.Client{Net: "udp"}
	msg := new(dns.Msg)
	msg.SetQuestion("cname.example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, calls, 1)

	// The minimum TTL across CNAME(30) and A(300) is 30, clamped
	// to minIPSetTTL=60.
	assert.Equal(t, 60*time.Second, calls[0].ttl)
	assert.Contains(t, fmt.Sprint(calls[0].ips), "10.99.0.1")
}

func TestProxyCNAMEHigherTTLUsesATTL(t *testing.T) {
	t.Parallel()

	// CNAME TTL=300, A TTL=120 -- set should use TTL=120.
	upstream := startCNAMEMockDNS(t, 300, 120)

	var mu sync.Mutex

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "cname2.example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
		}),
	}

	type setCall struct {
		ips []net.IP
		ttl time.Duration
	}

	var calls []setCall

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstream, "127.0.0.1:0", true,
		dnsproxy.WithFQDNSetFunc(func(_ context.Context, setName string, ips []net.IP, ttl time.Duration) error {
			mu.Lock()
			defer mu.Unlock()

			calls = append(calls, setCall{ips: ips, ttl: ttl})

			return nil
		}),
	)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	client := &dns.Client{Net: "udp"}
	msg := new(dns.Msg)
	msg.SetQuestion("cname2.example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

	mu.Lock()
	defer mu.Unlock()

	require.Len(t, calls, 1)

	// Minimum TTL is A(120), above minIPSetTTL so used directly.
	assert.Equal(t, 120*time.Second, calls[0].ttl)
	assert.Contains(t, fmt.Sprint(calls[0].ips), "10.99.0.1")
}

func TestProxyUpstreamTimeoutSilentDrop(t *testing.T) {
	t.Parallel()

	// Start a mock DNS server that never responds, causing upstream
	// timeout.
	lc := net.ListenConfig{}

	pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	require.NoError(t, err)

	udpAddr, ok := pc.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	t.Cleanup(func() { assert.NoError(t, pc.Close()) })

	upstreamAddr := fmt.Sprintf("127.0.0.1:%d", udpAddr.Port)

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "timeout.example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
		}),
	}

	proxy, err := dnsproxy.Start(t.Context(), cfg, upstreamAddr, "127.0.0.1:0", true,
		dnsproxy.WithClientTimeout(100*time.Millisecond),
	)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	// Query with a short client timeout. The proxy should not send
	// a response (silent drop), so the client itself times out.
	client := &dns.Client{
		Net:     "udp",
		Timeout: 500 * time.Millisecond,
	}

	msg := new(dns.Msg)
	msg.SetQuestion("timeout.example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)

	// The client should get a timeout error (no response from proxy).
	require.Error(t, err, "expected client timeout due to silent drop")
	assert.Nil(t, resp)
}

func TestProxyUpstreamConnectionRefusedSERVFAIL(t *testing.T) {
	t.Parallel()

	// Find a port that is not listening to trigger connection refused.
	lc := net.ListenConfig{}

	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := ln.Addr().String()
	require.NoError(t, ln.Close()) // Close immediately so the port is not listening.

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "refused.example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
		}),
	}

	proxy, err := dnsproxy.Start(t.Context(), cfg, addr, "127.0.0.1:0", true,
		dnsproxy.WithClientTimeout(2*time.Second),
	)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	// Use TCP so connection-refused is reliably detected.
	client := &dns.Client{
		Net:     "tcp",
		Timeout: 5 * time.Second,
	}

	msg := new(dns.Msg)
	msg.SetQuestion("refused.example.com.", dns.TypeA)

	resp, _, err := client.Exchange(msg, proxy.Addr)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, dns.RcodeServerFailure, resp.Rcode, "non-timeout upstream error should produce SERVFAIL")
}
