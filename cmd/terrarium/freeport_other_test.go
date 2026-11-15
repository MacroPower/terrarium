//go:build !linux

package main

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// freePort returns a TCP port of the IPv4 loopback address that the
// kernel picked. It closes the listener that received the port before
// it returns, so it does not reserve the port. Only Linux lets a
// second socket bind the port of a socket that holds it, so only the
// Linux variant keeps the port.
//
// Another process can therefore bind the port before the test does.
// A child process that the test binary starts during the close also
// holds a copy of the listener until it runs its program. A bind of
// the port fails with EADDRINUSE until then.
func freePort(t *testing.T) int {
	t.Helper()

	return freePorts(t, 1)[0]
}

// freePorts returns n TCP ports of the IPv4 loopback address that the
// kernel picked. The ports differ, because every listener stays open
// until each listener has a port. It closes the listeners before it
// returns, so it does not reserve the ports, as [freePort] does not.
func freePorts(t *testing.T, n int) []int {
	t.Helper()

	lc := net.ListenConfig{}

	ports := make([]int, n)
	listeners := make([]net.Listener, n)

	for i := range ports {
		ln, err := lc.Listen(t.Context(), "tcp4", net.JoinHostPort(loopbackIPv4, "0"))
		require.NoError(t, err)

		addr, ok := ln.Addr().(*net.TCPAddr)
		require.True(t, ok)

		ports[i] = addr.Port
		listeners[i] = ln
	}

	for _, ln := range listeners {
		require.NoError(t, ln.Close())
	}

	return ports
}
