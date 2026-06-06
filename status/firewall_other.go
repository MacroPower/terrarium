//go:build !linux

package status

import "errors"

// errFirewallUnsupported reports that nftables introspection requires
// Linux netlink support.
var errFirewallUnsupported = errors.New("firewall status requires linux")

// collectFirewall is the non-Linux stub for nftables introspection.
// The firewall data plane is Linux-only; the section renders as an
// error so the rest of the report stays useful.
func collectFirewall() FirewallSection {
	return FirewallSection{Err: errFirewallUnsupported}
}
