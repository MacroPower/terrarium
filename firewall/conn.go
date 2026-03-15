package firewall

import "github.com/google/nftables"

const tableName = "terrarium"

// UID/GID as uint32 for nftables expressions.
const (
	uidSandbox uint32 = 1000
	uidEnvoy   uint32 = 999
	uidRoot    uint32 = 0
)

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
