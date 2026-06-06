package nflog

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/florianl/go-nflog/v2"
	"golang.org/x/sys/unix"

	"go.jacobcolvin.com/terrarium/eventstore"
	"go.jacobcolvin.com/terrarium/firewall/logprefix"
)

// bufsize is the per-packet copy budget the kernel writes into each
// nflog message. 128 fits IPv6 with one extension header (Hop-by-Hop
// or Fragment) plus a TCP/UDP header without truncating the bytes
// [parsePacket] needs.
const bufsize = 128

// Resolver maps a destination IP to its most-recently-resolved qname.
// See [*dnscache.Cache] for an implementation.
type Resolver interface {
	// Lookup returns the most-recently-resolved non-expired qname
	// for ip. ok=false on cache miss or fully-expired entry.
	Lookup(ip netip.Addr) (string, bool)
}

// Reader binds to NETLINK_NETFILTER group N and ingests log events
// into an [*eventstore.Store]. Create with [New].
type Reader struct {
	nf       *nflog.Nflog
	store    *eventstore.Store
	resolver Resolver
	logger   *slog.Logger

	kernelDrops   atomic.Uint64
	parseErrors   atomic.Uint64
	lastEventUnix atomic.Int64

	closeOnce sync.Once

	// lastSeq and lastSeqValid are owned by the hook goroutine.
	// go-nflog's RegisterWithErrorFunc invokes the hook serially
	// from a single reader goroutine, so neither field needs a
	// lock. Cross-goroutine readers of KernelDrops use [atomic.Uint64].
	lastSeq      uint32
	group        uint16
	lastSeqValid bool
}

// New creates a [*Reader] bound to the given netlink log group. Blocks
// briefly to open the socket; returns an error on socket-open failure.
// Start the read loop with [Reader.Run]. store and r must be non-nil.
func New(group uint16, store *eventstore.Store, r Resolver, opts ...Option) (*Reader, error) {
	o := defaultReaderOptions()
	for _, opt := range opts {
		opt(&o)
	}

	cfg := &nflog.Config{
		Group:    group,
		Copymode: nflog.CopyPacket,
		Bufsize:  bufsize,
		Flags:    nflog.FlagSeq,
	}

	nf, err := nflog.Open(cfg)
	if err != nil {
		return nil, fmt.Errorf("opening nflog group %d: %w", group, err)
	}

	return &Reader{
		nf:       nf,
		store:    store,
		resolver: r,
		logger:   o.logger,
		group:    group,
	}, nil
}

// Run reads from the netlink socket until ctx is canceled. Returns
// nil on clean shutdown, error on unrecoverable read failure. The
// underlying nflog library blocks here; cancel ctx to unblock and
// drain the goroutine.
func (r *Reader) Run(ctx context.Context) error {
	if r == nil {
		return nil
	}

	hook := func(a nflog.Attribute) int {
		r.handle(a)

		return 0
	}

	errFn := func(err error) int {
		r.logger.WarnContext(ctx, "nflog: read error",
			slog.Uint64("group", uint64(r.group)),
			slog.Any("err", err),
		)

		// Continue receiving; transient netlink hiccups are
		// expected and the library serializes our hook calls.
		return 0
	}

	err := r.nf.RegisterWithErrorFunc(ctx, hook, errFn)
	if err != nil {
		return fmt.Errorf("registering nflog hook: %w", err)
	}

	<-ctx.Done()

	return nil
}

// Close releases the netlink socket and stops the reader. Safe to
// call on a nil receiver (no-op), matching [eventstore.Store.Close].
// Idempotent.
func (r *Reader) Close() error {
	if r == nil {
		return nil
	}

	var err error

	r.closeOnce.Do(func() {
		closeErr := r.nf.Close()
		if closeErr != nil {
			err = fmt.Errorf("closing nflog socket: %w", closeErr)
		}
	})

	return err
}

// KernelDrops reports the cumulative count of nflog seq gaps
// observed (kernel-side drops). A nil receiver returns 0.
func (r *Reader) KernelDrops() uint64 {
	if r == nil {
		return 0
	}

	return r.kernelDrops.Load()
}

// ParseErrors reports the cumulative count of malformed packets and
// undecodable prefixes. A nil receiver returns 0.
func (r *Reader) ParseErrors() uint64 {
	if r == nil {
		return 0
	}

	return r.parseErrors.Load()
}

// LastEventTime reports the wall-clock time of the most recent
// emitted event, or the zero time when none has been emitted yet. A
// nil receiver returns the zero time.
func (r *Reader) LastEventTime() time.Time {
	if r == nil {
		return time.Time{}
	}

	usec := r.lastEventUnix.Load()
	if usec == 0 {
		return time.Time{}
	}

	return time.UnixMicro(usec)
}

// handle is the per-packet hook entry. Decodes the prefix, parses
// the L3/L4 headers, looks up a qname, and emits one
// [eventstore.Event].
func (r *Reader) handle(a nflog.Attribute) {
	r.checkSeq(a.Seq)

	if a.Prefix == nil || a.Payload == nil {
		r.parseErrors.Add(1)

		return
	}

	kind, ruleIdx, ok := logprefix.Decode(*a.Prefix)
	if !ok {
		r.parseErrors.Add(1)

		return
	}

	tuple, ok := parsePacket(*a.Payload)
	if !ok {
		r.parseErrors.Add(1)

		return
	}

	event := eventstore.Event{
		Source:   eventstore.SourceFirewall,
		Decision: decisionFor(kind),
		Port:     int(tuple.dport),
		Protocol: protocolFor(tuple.proto, tuple.family),
		Reason:   reasonFor(kind, ruleIdx),
	}

	if qname, ok := r.resolver.Lookup(tuple.dst.Unmap()); ok {
		event.Domain = qname
	}

	r.store.Emit(event)
	r.lastEventUnix.Store(time.Now().UnixMicro())
}

// checkSeq tracks the per-instance sequence number reported by the
// kernel and increments [Reader.kernelDrops] on each gap. A nil
// `seq` (the kernel did not include the attribute) skips the gap
// check entirely.
//
// Called only from the go-nflog hook goroutine, which serializes
// callbacks; no synchronization on lastSeq / lastSeqValid is
// necessary.
func (r *Reader) checkSeq(seq *uint32) {
	if seq == nil {
		return
	}

	current := *seq

	if !r.lastSeqValid {
		r.lastSeq = current
		r.lastSeqValid = true

		return
	}

	expected := r.lastSeq + 1
	if current != expected {
		old := r.kernelDrops.Add(1)
		if old == 1 {
			r.logger.Warn("nflog: kernel-side drop detected (seq gap)",
				slog.Uint64("group", uint64(r.group)),
				slog.Uint64("expected", uint64(expected)),
				slog.Uint64("got", uint64(current)),
			)
		}
	}

	r.lastSeq = current
}

// decisionFor maps a [logprefix.Kind] onto an [eventstore.Decision].
// Leak events count as deny because the kernel drops the packet at
// the postrouting guard.
func decisionFor(kind logprefix.Kind) eventstore.Decision {
	switch kind {
	case logprefix.KindAllow:
		return eventstore.DecisionAllow
	case logprefix.KindDeny, logprefix.KindLeak:
		return eventstore.DecisionDeny
	}

	return eventstore.DecisionDeny
}

// reasonFor maps a [logprefix.Kind]+ruleIdx onto an
// [eventstore.Reason]. KindLeak always emits
// [eventstore.ReasonPostroutingGuard]; other kinds emit "rule=N" when
// a rule index was attached and the empty Reason otherwise.
func reasonFor(kind logprefix.Kind, ruleIdx int) eventstore.Reason {
	if kind == logprefix.KindLeak {
		return eventstore.ReasonPostroutingGuard
	}

	if ruleIdx < 0 {
		return ""
	}

	return eventstore.Reason("rule=" + strconv.Itoa(ruleIdx))
}

// protocolFor maps an L4 protocol number plus the IP family onto an
// [eventstore.Protocol] string. ICMP and ICMPv6 are disambiguated by
// family; other recognized values are TCP and UDP. Unknown protocols
// return the empty Protocol so the column is left NULL.
func protocolFor(proto, family uint8) eventstore.Protocol {
	switch proto {
	case unix.IPPROTO_TCP:
		return eventstore.ProtocolTCP
	case unix.IPPROTO_UDP:
		return eventstore.ProtocolUDP
	case unix.IPPROTO_ICMP:
		if family == 6 {
			return eventstore.ProtocolICMPv6
		}

		return eventstore.ProtocolICMP

	case unix.IPPROTO_ICMPV6:
		return eventstore.ProtocolICMPv6
	}

	return ""
}
