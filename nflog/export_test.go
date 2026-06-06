package nflog

import (
	"log/slog"
	"net/netip"

	"go.jacobcolvin.com/terrarium/eventstore"
	"go.jacobcolvin.com/terrarium/firewall/logprefix"
)

func noopLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// FiveTuple is the test-facing view of an unexported fiveTuple.
type FiveTuple struct {
	Dst    netip.Addr
	Sport  uint16
	Dport  uint16
	Proto  uint8
	Family uint8
}

// ParsePacket exposes parsePacket for nflog_test.
func ParsePacket(payload []byte) (FiveTuple, bool) {
	t, ok := parsePacket(payload)
	if !ok {
		return FiveTuple{}, false
	}

	return FiveTuple{
		Dst:    t.dst,
		Sport:  t.sport,
		Dport:  t.dport,
		Proto:  t.proto,
		Family: t.family,
	}, true
}

// ExtWalkLimit exposes the IPv6 extension-walk hop bound for tests.
const ExtWalkLimit = extWalkLimit

// DecisionFor exposes decisionFor for nflog_test.
func DecisionFor(k logprefix.Kind) eventstore.Decision { return decisionFor(k) }

// ReasonFor exposes reasonFor for nflog_test.
func ReasonFor(k logprefix.Kind, ruleIdx int) eventstore.Reason {
	return reasonFor(k, ruleIdx)
}

// ProtocolFor exposes protocolFor for nflog_test.
func ProtocolFor(proto, family uint8) eventstore.Protocol {
	return protocolFor(proto, family)
}

// CheckSeqForTest invokes the unexported sequence-gap counter on r.
func (r *Reader) CheckSeqForTest(seq *uint32) { r.checkSeq(seq) }

// NewReaderForTest builds a Reader that has not opened a netlink
// socket. Only the fields touched by checkSeq, ParseErrors, and
// LastEventTime are valid; calling Run on it panics.
func NewReaderForTest() *Reader {
	return &Reader{logger: noopLogger()}
}
