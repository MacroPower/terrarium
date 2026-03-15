package firewall

import "github.com/google/nftables"

const tableName = "terrarium"

// UIDs holds the numeric user IDs used in nftables UID match
// expressions. Values are passed from the CLI entrypoint.
type UIDs struct {
	Sandbox uint32
	Envoy   uint32
	Root    uint32
}

const (
	protoTCP  = "tcp"
	protoUDP  = "udp"
	protoSCTP = "sctp"
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
