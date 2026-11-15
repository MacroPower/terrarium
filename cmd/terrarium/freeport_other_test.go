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

	lc := net.ListenConfig{}

	ln, err := lc.Listen(t.Context(), "tcp4", net.JoinHostPort(loopbackIPv4, "0"))
	require.NoError(t, err)

	addr, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok)
	require.NoError(t, ln.Close())

	return addr.Port
}
