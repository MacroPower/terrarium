package dnstest_test

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/dnstest"
)

func TestListen(t *testing.T) {
	t.Parallel()

	pc, ln, port := dnstest.Listen(t)

	t.Cleanup(func() {
		assert.NoError(t, pc.Close())
		assert.NoError(t, ln.Close())
	})

	udpAddr, ok := pc.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)

	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok)

	assert.Positive(t, port)
	assert.Equal(t, port, udpAddr.Port)
	assert.Equal(t, port, tcpAddr.Port)
	assert.True(t, udpAddr.IP.IsLoopback())
	assert.True(t, tcpAddr.IP.IsLoopback())
}

func TestStartProxy(t *testing.T) {
	t.Parallel()

	upstream := dnstest.StartServer(t, "10.1.2.3")

	// A nil config makes the proxy forward every query.
	proxy := dnstest.StartProxy(t, nil, upstream)

	t.Cleanup(func() { assert.NoError(t, proxy.Shutdown()) })

	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			t.Parallel()

			client := &dns.Client{Net: network}
			msg := new(dns.Msg)
			msg.SetQuestion("proxy.example.com.", dns.TypeA)

			resp, _, err := client.Exchange(msg, proxy.Addr)
			require.NoError(t, err)
			require.NotNil(t, resp)
			require.Len(t, resp.Answer, 1)

			a, ok := resp.Answer[0].(*dns.A)
			require.True(t, ok)
			assert.Equal(t, "10.1.2.3", a.A.String())
		})
	}
}
