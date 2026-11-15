package main

import (
	"errors"
	"net"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freePort returns a TCP port that the kernel picked, and it reserves
// the port until the test ends.
//
// The reservation is a socket that binds the port of the IPv6
// wildcard address with SO_REUSEADDR, accepts IPv4 too, and never
// listens. The socket has these effects on Linux:
//
//   - The kernel does not give the port to a socket of any process
//     that binds port 0, on any address of either family.
//   - A socket that sets SO_REUSEADDR can bind the port of any address
//     and listen on it. Go and Envoy set the option on every listener.
//   - The kernel refuses a connection to the port until such a
//     listener opens.
//
// On a host without IPv6, the reservation binds the IPv4 loopback
// address and covers only that address and the IPv4 wildcard.
//
// The reservation stays open because a port that a closed listener
// held is not free for the next bind. A child process that the test
// binary starts during the close holds a copy of the listener until
// it runs its program. A bind of the port fails with EADDRINUSE until
// then. Another process can also receive the port from the kernel
// after the close.
func freePort(t *testing.T) int {
	t.Helper()

	fd, port, err := reservePort(syscall.AF_INET6)
	if err != nil {
		fd, port, err = reservePort(syscall.AF_INET)
	}

	require.NoError(t, err)

	// Cleanup functions run last in, first out, so the reservation
	// closes after every listener that the test opened on the port.
	t.Cleanup(func() {
		assert.NoError(t, syscall.Close(fd))
	})

	return port
}

// reservePort binds a socket of the address family family to port 0
// with SO_REUSEADDR and returns the socket and its port. An IPv6
// socket binds the wildcard address of both families. An IPv4 socket
// binds the IPv4 loopback address.
func reservePort(family int) (int, int, error) {
	fd, err := syscall.Socket(family, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, 0, err
	}

	port, err := bindReservation(fd, family)
	if err != nil {
		return 0, 0, errors.Join(err, syscall.Close(fd))
	}

	return fd, port, nil
}

// bindReservation sets the options of the reservation on the socket
// fd of the address family family and binds it to port 0. It returns
// the port that the kernel picked.
func bindReservation(fd, family int) (int, error) {
	err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	if err != nil {
		return 0, err
	}

	var sa syscall.Sockaddr = &syscall.SockaddrInet4{Addr: [4]byte(net.ParseIP(loopbackIPv4).To4())}

	if family == syscall.AF_INET6 {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
		if err != nil {
			return 0, err
		}

		sa = &syscall.SockaddrInet6{}
	}

	err = syscall.Bind(fd, sa)
	if err != nil {
		return 0, err
	}

	bound, err := syscall.Getsockname(fd)
	if err != nil {
		return 0, err
	}

	switch addr := bound.(type) {
	case *syscall.SockaddrInet4:
		return addr.Port, nil
	case *syscall.SockaddrInet6:
		return addr.Port, nil
	default:
		return 0, syscall.EAFNOSUPPORT
	}
}

// TestFreePort checks that [freePort] holds its port on each loopback
// address. It also checks that the port behaves as a free port for a
// test that listens on it.
func TestFreePort(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		ip      string
		network string
	}{
		"IPv4 loopback": {ip: loopbackIPv4, network: "tcp4"},
		"IPv6 loopback": {ip: loopbackIPv6, network: "tcp6"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			requireLoopback(t, tt.ip)

			port := freePort(t)
			addr := net.JoinHostPort(tt.ip, strconv.Itoa(port))

			dial := func() error {
				var d net.Dialer

				conn, err := d.DialContext(t.Context(), tt.network, addr)
				if err != nil {
					return err
				}

				return conn.Close()
			}

			require.ErrorIs(t, dial(), syscall.ECONNREFUSED, "the reservation must not listen")

			// A bind without SO_REUSEADDR fails only while a socket
			// holds the port.
			require.ErrorIs(t, bindWithoutReuse(t, tt.ip, port), syscall.EADDRINUSE,
				"the reservation must hold the port")

			var lc net.ListenConfig

			ln, err := lc.Listen(t.Context(), tt.network, addr)
			require.NoError(t, err)

			t.Cleanup(func() {
				assert.NoError(t, ln.Close())
			})

			require.NoError(t, dial())

			// The reservation must not let a second listener share
			// the port.
			_, err = lc.Listen(t.Context(), tt.network, addr)
			require.ErrorIs(t, err, syscall.EADDRINUSE)
		})
	}
}

// bindWithoutReuse binds a TCP socket to the address ip and the port
// port without SO_REUSEADDR, and it returns the error of the bind.
func bindWithoutReuse(t *testing.T, ip string, port int) error {
	t.Helper()

	parsed := net.ParseIP(ip)

	family := syscall.AF_INET6

	var sa syscall.Sockaddr = &syscall.SockaddrInet6{Port: port, Addr: [16]byte(parsed.To16())}

	if v4 := parsed.To4(); v4 != nil {
		family = syscall.AF_INET
		sa = &syscall.SockaddrInet4{Port: port, Addr: [4]byte(v4)}
	}

	fd, err := syscall.Socket(family, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, syscall.Close(fd))
	})

	return syscall.Bind(fd, sa)
}
