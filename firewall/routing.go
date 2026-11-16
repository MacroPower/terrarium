//go:build linux

package firewall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.jacobcolvin.com/terrarium/sysctl"
)

// SetupPolicyRouting configures policy routing and reverse path
// filtering for TPROXY. The kernel routes marked packets through
// loopback, so they arrive at the PREROUTING chain where TPROXY
// fires. Those packets keep their original, non-local source address,
// and strict reverse path filtering drops them. So the function sets
// rp_filter to loose mode (2) on lo and for all interfaces. In VM
// mode, [SetupForwardRouting] replaces the value for all interfaces.
func SetupPolicyRouting(ctx context.Context, sys *sysctl.Sysctl) error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("looking up loopback interface: %w", err)
	}

	loIndex := lo.Attrs().Index

	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		familyName := "IPv4"
		if family == unix.AF_INET6 {
			familyName = "IPv6"
		}

		// Delete-then-add for ip rule to prevent duplicates on restart.
		err := netlink.RuleDel(policyRule(family))
		if err != nil && !errors.Is(err, unix.ENOENT) {
			slog.DebugContext(
				ctx,
				"deleting stale policy rule (may not exist)",
				slog.String("family", familyName),
				slog.Any("err", err),
			)
		}

		err = netlink.RuleAdd(policyRule(family))
		if err != nil {
			return fmt.Errorf("adding %s policy rule: %w", familyName, err)
		}

		err = netlink.RouteReplace(policyRoute(family, loIndex))
		if err != nil {
			return fmt.Errorf("adding %s policy route: %w", familyName, err)
		}
	}

	// Set rp_filter to loose mode (2) on lo and all. The effective
	// rp_filter value of an interface is max(conf.all, conf.<iface>).
	err = sys.Write("2", "net", "ipv4", "conf", "lo", "rp_filter")
	if err != nil {
		return fmt.Errorf("setting lo rp_filter: %w", err)
	}

	err = sys.Write("2", "net", "ipv4", "conf", "all", "rp_filter")
	if err != nil {
		return fmt.Errorf("setting all rp_filter: %w", err)
	}

	return nil
}

// SetupForwardRouting sets the sysctl parameters that forwarded
// container traffic needs. Only VM mode calls it.
//
// It enables route_localnet for all interfaces, so that DNAT to
// 127.0.0.1 works on non-loopback interfaces. NAT PREROUTING needs
// that to redirect forwarded container traffic to Envoy and to the
// DNS proxy on loopback. The security implications are minimal in a
// VM isolation context where the VM itself is the security boundary.
//
// It also sets net.ipv4.conf.all.rp_filter to 0. The bridge
// prerouting chain of [ApplyRules] passes the forwarded UDP of a
// bridge-attached container to the network layer as a packet that
// the bridge port received. The bridge port has no IPv4 address, so
// the kernel drops such a packet unless the effective rp_filter
// value of the port is 0. That value is the larger of
// net.ipv4.conf.all.rp_filter and the value of the port.
// [SetupPolicyRouting] sets net.ipv4.conf.all.rp_filter to 2, so call
// SetupForwardRouting after it.
//
// The host sets the rp_filter value of each bridge port. A new
// interface takes the value of net.ipv4.conf.default.rp_filter, so
// SetupForwardRouting logs a warning when that value is not 0. On a
// host that runs systemd-udevd, the sysctl.d configuration can also
// set the value of each new interface.
func SetupForwardRouting(ctx context.Context, sys *sysctl.Sysctl) error {
	err := sys.Enable("net", "ipv4", "conf", "all", "route_localnet")
	if err != nil {
		return fmt.Errorf("setting route_localnet: %w", err)
	}

	err = sys.Write("0", "net", "ipv4", "conf", "all", "rp_filter")
	if err != nil {
		return fmt.Errorf("setting all rp_filter: %w", err)
	}

	rpFilter, err := sys.ReadInt("net", "ipv4", "conf", "default", "rp_filter")
	if err != nil {
		return fmt.Errorf("reading default rp_filter: %w", err)
	}

	if rpFilter != 0 {
		slog.WarnContext(ctx,
			"net.ipv4.conf.default.rp_filter is not 0, "+
				"so the kernel might drop forwarded IPv4 UDP of bridge-attached containers",
			slog.Int64("rp_filter", rpFilter),
		)
	}

	return nil
}

// CleanupPolicyRouting removes the policy routing rules and routes
// added by [SetupPolicyRouting]. Errors are logged but not returned
// (best-effort cleanup). Does not restore rp_filter since the
// network namespace is typically torn down on exit.
func CleanupPolicyRouting(ctx context.Context) {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		slog.DebugContext(ctx, "looking up loopback for cleanup", slog.Any("err", err))

		return
	}

	loIndex := lo.Attrs().Index

	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		familyName := "IPv4"
		if family == unix.AF_INET6 {
			familyName = "IPv6"
		}

		err := netlink.RuleDel(policyRule(family))
		if err != nil {
			slog.DebugContext(
				ctx,
				"cleaning up policy rule",
				slog.String("family", familyName),
				slog.Any("err", err),
			)
		}

		err = netlink.RouteDel(policyRoute(family, loIndex))
		if err != nil {
			slog.DebugContext(
				ctx,
				"cleaning up policy route",
				slog.String("family", familyName),
				slog.Any("err", err),
			)
		}
	}
}

// policyRule returns a netlink rule that matches packets with the
// TPROXY fwmark and directs them to the TPROXY routing table.
func policyRule(family int) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Mark = tproxyMark
	rule.Table = tproxyTable
	rule.Family = family

	return rule
}

// policyRoute returns a local default route through loopback in the
// TPROXY routing table, equivalent to "ip route replace local default
// dev lo table <tproxyTable>".
func policyRoute(family, loIndex int) *netlink.Route {
	dst := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	if family == unix.AF_INET6 {
		dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}

	return &netlink.Route{
		Dst:       dst,
		Type:      unix.RTN_LOCAL,
		Scope:     unix.RT_SCOPE_HOST,
		Table:     tproxyTable,
		LinkIndex: loIndex,
	}
}
