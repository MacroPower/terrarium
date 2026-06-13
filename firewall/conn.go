//go:build linux

package firewall

import "github.com/google/nftables"

// TableName is the nftables table that holds terrarium's policy
// rules. The table is replaced atomically on each
// [ApplyRules] invocation.
const TableName = "terrarium"

// GuardTableName is the separate nftables table that provides
// deny-all egress when the daemon's table is absent (restart gaps,
// crashes). Created externally by the host (e.g., NixOS
// networking.nftables.tables) and never modified by the daemon.
const GuardTableName = "terrarium-guard"

// UIDs holds the numeric user IDs that nftables rules use to
// distinguish infrastructure traffic from policy-evaluated traffic.
type UIDs struct {
	// ExcludeUIDs lists UIDs whose DNS traffic should not be
	// redirected to the local DNS proxy (e.g., a system DNS
	// forwarder like dnsmasq that needs to reach upstream servers).
	ExcludeUIDs []uint32

	Terrarium uint32
	Envoy     uint32
	Root      uint32

	// VMMode switches from container-style filtering, where only
	// the Terrarium UID is policy-evaluated, to VM-wide filtering,
	// where all UIDs except Envoy and Root are policy-evaluated.
	VMMode bool
}

const (
	// The fwmark value used to identify UDP packets that need
	// TPROXY processing. Set in the mangle output chain,
	// matched in the mangle prerouting chain.
	tproxyMark uint32 = 0x1

	// The fwmark bit set by the filter output chain to signal that
	// a packet has been evaluated by terrarium's policy engine. The
	// external guard table checks this bit instead of enumerating
	// terrarium-internal exceptions (UIDs, TPROXY mark, ICMP). Uses
	// bit 0x2 to coexist with [tproxyMark] (0x1).
	guardMark uint32 = 0x2

	// The policy routing table number used to route marked packets
	// back through loopback for TPROXY interception.
	tproxyTable = 100
)

// Conn abstracts the [nftables.Conn] methods used by rule building.
// Tests provide a recording implementation.
//
// See [*nftables.Conn] for an implementation.
type Conn interface {
	AddTable(t *nftables.Table) *nftables.Table
	AddChain(c *nftables.Chain) *nftables.Chain
	AddRule(r *nftables.Rule) *nftables.Rule
	AddSet(s *nftables.Set, elements []nftables.SetElement) error
	DelTable(t *nftables.Table)
	Flush() error
}
