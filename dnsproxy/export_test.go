package dnsproxy

import (
	"context"
	"net"
)

// BindAttempts exposes the unexported bindAttempts constant for tests.
const BindAttempts = bindAttempts

// WithTCPListen replaces the function that binds the TCP listeners of
// the proxy with fn. A test can then take a port before the proxy
// binds it. An [Option].
func WithTCPListen(
	fn func(ctx context.Context, lc *net.ListenConfig, addr string) (net.Listener, error),
) Option {
	return func(p *Proxy) {
		p.listenTCP = fn
	}
}
