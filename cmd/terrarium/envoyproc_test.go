package main

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckListenAddress(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// err is an error that the check must wrap. Every case with
		// an err also requires [ErrListenAddressUnavailable].
		err error
		// held is the IP address that another listener holds on the
		// port. An empty value leaves the port free.
		held string
		// host is the host of the address to check.
		host string
		// linuxOnly marks a case that depends on the bind rules of
		// Linux.
		linuxOnly bool
	}{
		"free address": {
			host: loopbackIPv4,
		},
		"address in use": {
			held: loopbackIPv4,
			host: loopbackIPv4,
			err:  syscall.EADDRINUSE,
		},
		// Go sets SO_REUSEADDR on every listener. With that option
		// on both sockets, only Linux refuses a wildcard bind beside
		// a listener on a specific address.
		"wildcard over an address in use": {
			held:      loopbackIPv4,
			host:      "0.0.0.0",
			err:       syscall.EADDRINUSE,
			linuxOnly: true,
		},
		"IPv6 address in use": {
			held: loopbackIPv6,
			host: loopbackIPv6,
			err:  syscall.EADDRINUSE,
		},
		// Envoy binds an IPv4 wildcard for IPv4 alone, so an IPv6
		// listener on the port does not block it.
		"IPv4 wildcard beside an IPv6 listener": {
			held: loopbackIPv6,
			host: "0.0.0.0",
		},
		"address not on the host": {
			// The address is in TEST-NET-1 of RFC 5737.
			host: "192.0.2.1",
			err:  syscall.EADDRNOTAVAIL,
		},
		// The name resolves to a loopback address, so a bind of the
		// name succeeds. The check must refuse the name itself.
		"host name": {
			host: "localhost",
			err:  ErrListenAddressUnavailable,
		},
		"empty host": {
			err: ErrListenAddressUnavailable,
		},
	}

	// The kernel can give one port to two listeners that ask at
	// different times or for different address families. A case
	// that shared its port with another case would see the listener
	// of that case. The test therefore opens every listener here,
	// before a subtest runs. Each case reserves its port on the IPv4
	// loopback address, and all reservations stay open until every
	// case has a port.
	var (
		lc       net.ListenConfig
		reserved []net.Listener
	)

	ports := make(map[string]string, len(tests))
	skips := make(map[string]error, len(tests))

	for name, tt := range tests {
		ln, err := lc.Listen(t.Context(), "tcp4", net.JoinHostPort(loopbackIPv4, "0"))
		require.NoError(t, err)

		_, port, err := net.SplitHostPort(ln.Addr().String())
		require.NoError(t, err)

		ports[name] = port

		// The reservation is the held listener of a case that holds
		// the IPv4 loopback address.
		if tt.held == loopbackIPv4 {
			t.Cleanup(func() {
				assert.NoError(t, ln.Close())
			})

			continue
		}

		reserved = append(reserved, ln)

		if tt.held == "" {
			continue
		}

		skips[name] = loopbackError(t, tt.held)
		if skips[name] != nil {
			continue
		}

		held, err := lc.Listen(t.Context(), "tcp", net.JoinHostPort(tt.held, port))
		require.NoError(t, err)

		t.Cleanup(func() {
			assert.NoError(t, held.Close())
		})
	}

	for _, ln := range reserved {
		require.NoError(t, ln.Close())
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if tt.linuxOnly && runtime.GOOS != "linux" {
				t.Skip("needs the bind rules of Linux")
			}

			if skips[name] != nil {
				t.Skip(skips[name])
			}

			addr := net.JoinHostPort(tt.host, ports[name])

			err := checkListenAddress(t.Context(), addr)
			if tt.err == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, ErrListenAddressUnavailable)
			require.ErrorIs(t, err, tt.err)
			require.ErrorContains(t, err, addr)
		})
	}
}

func TestWaitForListener(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err      error
		notErr   error
		timeout  time.Duration
		listen   bool
		canceled bool
	}{
		"listener accepts": {
			listen:  true,
			timeout: 15 * time.Second,
		},
		"timeout expires": {
			timeout: 150 * time.Millisecond,
			err:     ErrListenerNotReady,
		},
		"caller cancels": {
			canceled: true,
			timeout:  15 * time.Second,
			err:      context.Canceled,
			notErr:   ErrListenerNotReady,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			addr := fmt.Sprintf("%s:%d", loopbackIPv4, freePort(t))

			if tt.listen {
				lc := net.ListenConfig{}

				ln, err := lc.Listen(t.Context(), "tcp", addr)
				require.NoError(t, err)

				t.Cleanup(func() {
					assert.NoError(t, ln.Close())
				})
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			if tt.canceled {
				cancel()
			}

			err := waitForListener(ctx, addr, tt.timeout)
			if tt.err == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.err)

			if tt.notErr != nil {
				require.NotErrorIs(t, err, tt.notErr)
			}
		})
	}
}
