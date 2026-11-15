package nflog_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	"go.jacobcolvin.com/terrarium/eventstore"
	"go.jacobcolvin.com/terrarium/firewall/logprefix"
	"go.jacobcolvin.com/terrarium/nflog"
)

func TestDecisionFor(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		kind logprefix.Kind
		want eventstore.Decision
	}{
		"allow":            {kind: logprefix.KindAllow, want: eventstore.DecisionAllow},
		"deny":             {kind: logprefix.KindDeny, want: eventstore.DecisionDeny},
		"leak counts deny": {kind: logprefix.KindLeak, want: eventstore.DecisionDeny},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, nflog.DecisionFor(tt.kind))
		})
	}
}

func TestReasonFor(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		kind    logprefix.Kind
		ruleIdx int
		want    eventstore.Reason
	}{
		"leak always reports postrouting-guard": {
			kind:    logprefix.KindLeak,
			ruleIdx: -1,
			want:    eventstore.ReasonPostroutingGuard,
		},
		"deny no index -> empty": {
			kind:    logprefix.KindDeny,
			ruleIdx: -1,
			want:    "",
		},
		"deny rule=N -> rule=N": {
			kind:    logprefix.KindDeny,
			ruleIdx: 3,
			want:    eventstore.Reason("rule=3"),
		},
		"allow no index -> empty": {
			kind:    logprefix.KindAllow,
			ruleIdx: -1,
			want:    "",
		},
		"allow rule=N -> rule=N": {
			kind:    logprefix.KindAllow,
			ruleIdx: 7,
			want:    eventstore.Reason("rule=7"),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, nflog.ReasonFor(tt.kind, tt.ruleIdx))
		})
	}
}

// resolverFunc is a [nflog.Resolver] that calls the function.
type resolverFunc func(ip netip.Addr) (string, bool)

func (f resolverFunc) Lookup(ip netip.Addr) (string, bool) { return f(ip) }

// TestEventFor maps a log prefix and a packet onto an event. The
// resolver knows the name of the IPv4 destination only.
func TestEventFor(t *testing.T) {
	t.Parallel()

	ipv4 := netip.MustParseAddr("8.8.8.8")
	ipv6 := netip.MustParseAddr("2001:db8::1")

	resolver := resolverFunc(func(ip netip.Addr) (string, bool) {
		if ip == ipv4 {
			return "dns.example", true
		}

		return "", false
	})

	tcs := map[string]struct {
		prefix  string
		payload []byte
		want    eventstore.Event
		rejects bool
	}{
		"catch-all deny with a cached name": {
			prefix:  logprefix.Encode(logprefix.KindDeny, -1),
			payload: makeIPv4(t, unix.IPPROTO_TCP, tcpUDPHeader(40000, 443)),
			want: eventstore.Event{
				Source:   eventstore.SourceFirewall,
				Decision: eventstore.DecisionDeny,
				Domain:   "dns.example",
				DstIP:    ipv4,
				Port:     443,
				Protocol: eventstore.ProtocolTCP,
			},
		},
		"catch-all deny without a cached name": {
			prefix:  logprefix.Encode(logprefix.KindDeny, -1),
			payload: makeIPv6(t, unix.IPPROTO_UDP, tcpUDPHeader(40000, 53)),
			want: eventstore.Event{
				Source:   eventstore.SourceFirewall,
				Decision: eventstore.DecisionDeny,
				DstIP:    ipv6,
				Port:     53,
				Protocol: eventstore.ProtocolUDP,
			},
		},
		"allow from the first rule": {
			prefix:  logprefix.Encode(logprefix.KindAllow, 0),
			payload: makeIPv6(t, unix.IPPROTO_TCP, tcpUDPHeader(40000, 8443)),
			want: eventstore.Event{
				Source:       eventstore.SourceFirewall,
				Decision:     eventstore.DecisionAllow,
				DstIP:        ipv6,
				Port:         8443,
				Protocol:     eventstore.ProtocolTCP,
				Reason:       "rule=0",
				RuleIndex:    0,
				HasRuleIndex: true,
			},
		},
		"deny from a later rule": {
			prefix:  logprefix.Encode(logprefix.KindDeny, 3),
			payload: makeIPv4(t, unix.IPPROTO_UDP, tcpUDPHeader(40000, 123)),
			want: eventstore.Event{
				Source:       eventstore.SourceFirewall,
				Decision:     eventstore.DecisionDeny,
				Domain:       "dns.example",
				DstIP:        ipv4,
				Port:         123,
				Protocol:     eventstore.ProtocolUDP,
				Reason:       "rule=3",
				RuleIndex:    3,
				HasRuleIndex: true,
			},
		},
		"leak": {
			prefix:  logprefix.Encode(logprefix.KindLeak, -1),
			payload: makeIPv4(t, unix.IPPROTO_TCP, tcpUDPHeader(40000, 22)),
			want: eventstore.Event{
				Source:   eventstore.SourceFirewall,
				Decision: eventstore.DecisionDeny,
				Domain:   "dns.example",
				DstIP:    ipv4,
				Port:     22,
				Protocol: eventstore.ProtocolTCP,
				Reason:   eventstore.ReasonPostroutingGuard,
			},
		},
		"unknown prefix": {
			prefix:  "OTHER: ",
			payload: makeIPv4(t, unix.IPPROTO_TCP, tcpUDPHeader(40000, 443)),
			rejects: true,
		},
		"truncated packet": {
			prefix:  logprefix.Encode(logprefix.KindDeny, -1),
			payload: []byte{0x45, 0x00},
			rejects: true,
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, ok := nflog.EventFor(tc.prefix, tc.payload, resolver)

			assert.Equal(t, !tc.rejects, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestProtocolFor(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		proto  uint8
		family uint8
		want   eventstore.Protocol
	}{
		"TCP":          {proto: unix.IPPROTO_TCP, family: 4, want: eventstore.ProtocolTCP},
		"UDP":          {proto: unix.IPPROTO_UDP, family: 4, want: eventstore.ProtocolUDP},
		"ICMP IPv4":    {proto: unix.IPPROTO_ICMP, family: 4, want: eventstore.ProtocolICMP},
		"ICMP IPv6":    {proto: unix.IPPROTO_ICMP, family: 6, want: eventstore.ProtocolICMPv6},
		"ICMPv6":       {proto: unix.IPPROTO_ICMPV6, family: 6, want: eventstore.ProtocolICMPv6},
		"SCTP unknown": {proto: 132, family: 4, want: ""},
		"GRE unknown":  {proto: 47, family: 4, want: ""},
		"zero":         {proto: 0, family: 0, want: ""},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, nflog.ProtocolFor(tt.proto, tt.family))
		})
	}
}

func TestReaderNilSafe(t *testing.T) {
	t.Parallel()

	var r *nflog.Reader

	assert.Zero(t, r.KernelDrops())
	assert.Zero(t, r.ParseErrors())
	assert.True(t, r.LastEventTime().IsZero())
	assert.NoError(t, r.Close())
	assert.NoError(t, r.Run(t.Context()))
}

func TestReaderCheckSeq(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		seqs      []uint32
		wantDrops uint64
	}{
		"sequential no drops": {
			seqs:      []uint32{1, 2, 3, 4, 5},
			wantDrops: 0,
		},
		"single gap": {
			seqs:      []uint32{1, 2, 5, 6},
			wantDrops: 1,
		},
		"multiple gaps": {
			seqs:      []uint32{1, 5, 10, 11, 20},
			wantDrops: 3,
		},
		"first call seeds, no drop": {
			seqs:      []uint32{100, 101},
			wantDrops: 0,
		},
		"wraparound is not a gap": {
			seqs:      []uint32{0xFFFFFFFF, 0},
			wantDrops: 0,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := nflog.NewReaderForTest()

			for i := range tt.seqs {
				seq := tt.seqs[i]
				r.CheckSeqForTest(&seq)
			}

			assert.Equal(t, tt.wantDrops, r.KernelDrops())
		})
	}
}

func TestReaderCheckSeqNilSkips(t *testing.T) {
	t.Parallel()

	r := nflog.NewReaderForTest()

	r.CheckSeqForTest(nil)

	assert.Zero(t, r.KernelDrops(),
		"nil seq attribute must skip gap detection entirely")
}
