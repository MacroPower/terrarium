package dnsproxy

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// setIPv6Transparent sets IPV6_TRANSPARENT and IPV6_V6ONLY on an IPv6
// socket so it can accept TPROXY'd packets with non-local destination
// addresses. IPV6_V6ONLY prevents the dual-stack socket from also
// binding IPv4, which would conflict with the separate IPv4 listener.
// Used as a [net.ListenConfig.Control] function in VM mode.
func setIPv6Transparent(_, _ string, c syscall.RawConn) error {
	var optErr error

	controlErr := c.Control(func(fd uintptr) {
		optErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_V6ONLY, 1)
		if optErr != nil {
			return
		}

		optErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	})
	if controlErr != nil {
		return fmt.Errorf("accessing raw socket: %w", controlErr)
	}

	if optErr != nil {
		return fmt.Errorf("setting IPv6 socket options: %w", optErr)
	}

	return nil
}
