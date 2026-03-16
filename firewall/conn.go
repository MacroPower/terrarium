package firewall

import "github.com/google/nftables"

const tableName = "terrarium"

// UIDs holds the numeric user IDs used in nftables UID match
// expressions. Values are passed from the CLI entrypoint.
type UIDs struct {
	Terrarium uint32
	Envoy     uint32
	Root      uint32
}

const (
	// tproxyMark is the fwmark value used to identify UDP packets
	// that need TPROXY processing. Set in the mangle output chain,
	// matched in the mangle prerouting chain.
	tproxyMark uint32 = 0x1

	// tproxyTable is the policy routing table number used to route
	// marked packets back through loopback for TPROXY interception.
	tproxyTable = 100
)

// Conn abstracts the nftables.Conn methods used by rule building.
// [*nftables.Conn] satisfies this interface. Tests provide a
// recording implementation.
type Conn interface {
	AddTable(t *nftables.Table) *nftables.Table
	AddChain(c *nftables.Chain) *nftables.Chain
	AddRule(r *nftables.Rule) *nftables.Rule
	AddSet(s *nftables.Set, elements []nftables.SetElement) error
	DelTable(t *nftables.Table)
	Flush() error
}
