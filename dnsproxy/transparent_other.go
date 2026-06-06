//go:build !linux

package dnsproxy

import (
	"errors"
	"syscall"
)

// errVMModeUnsupported reports that VM mode's transparent IPv6 sockets
// require Linux TPROXY support.
var errVMModeUnsupported = errors.New("vm mode requires linux")

// setIPv6Transparent is the non-Linux stub for the TPROXY socket
// option setup. VM mode is Linux-only; binding a transparent listener
// on other platforms returns [errVMModeUnsupported].
func setIPv6Transparent(_, _ string, _ syscall.RawConn) error {
	return errVMModeUnsupported
}
