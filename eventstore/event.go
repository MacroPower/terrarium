package eventstore

import (
	"net/netip"
	"time"
)

// Source identifies which subsystem produced an [Event].
type Source string

// Source values.
const (
	// SourceDNS marks an event emitted by the DNS proxy.
	SourceDNS Source = "dns"

	// SourceEnvoy marks an event emitted by Envoy via gRPC ALS.
	SourceEnvoy Source = "envoy"

	// SourceFirewall marks an event emitted by the nflog reader
	// from a kernel `log group` directive.
	SourceFirewall Source = "firewall"
)

// Decision categorizes the policy outcome captured by an [Event].
type Decision string

// Decision values.
const (
	// DecisionAllow marks a request that completed normally.
	DecisionAllow Decision = "allow"

	// DecisionDeny marks a request rejected by policy.
	DecisionDeny Decision = "deny"

	// DecisionError marks a request that failed for a reason
	// unrelated to policy (e.g. upstream resolver error).
	DecisionError Decision = "error"
)

// Reason is a short tag explaining a deny or error decision.
type Reason string

// DNS deny / error reason values.
const (
	// ReasonBlockedMode is set on DNS deny events emitted from
	// blocked-mode (egress: [{}]) terrarium configurations.
	ReasonBlockedMode Reason = "blocked-mode"

	// ReasonNotAllowlisted is set on DNS deny events when the
	// queried name does not match any allowed domain.
	ReasonNotAllowlisted Reason = "not-allowlisted"

	// ReasonUpstream is set on DNS error events when the upstream
	// resolver returned a non-timeout error.
	ReasonUpstream Reason = "upstream"

	// ReasonPostroutingGuard is set on firewall deny events captured
	// by the postrouting leak guard chain (traffic that escaped the
	// NAT REDIRECT / TPROXY redirection and tried to leave on a
	// non-loopback interface).
	ReasonPostroutingGuard Reason = "postrouting-guard"
)

// Protocol is the upper-layer protocol tag written to [Event.Protocol].
type Protocol string

// Protocol values. Centralized here so the DNS proxy and the Envoy
// access-log translator stay in sync.
const (
	// ProtocolDNS marks events emitted by the DNS proxy.
	ProtocolDNS Protocol = "dns"

	// ProtocolHTTP marks events translated from Envoy
	// HTTPAccessLogEntry messages.
	ProtocolHTTP Protocol = "http"

	// ProtocolTCP marks events translated from Envoy
	// TCPAccessLogEntry messages.
	ProtocolTCP Protocol = "tcp"

	// ProtocolUDP marks UDP traffic captured by the nflog reader.
	ProtocolUDP Protocol = "udp"

	// ProtocolICMP marks IPv4 ICMP traffic captured by the nflog
	// reader.
	ProtocolICMP Protocol = "icmp"

	// ProtocolICMPv6 marks IPv6 ICMP traffic captured by the nflog
	// reader.
	ProtocolICMPv6 Protocol = "icmpv6"
)

// Event is one captured egress decision. Fields mirror the columns of
// the events table. Pointers are avoided so the zero value of any
// optional field round-trips cleanly.
type Event struct {
	// Time is when the event occurred. Zero values are replaced
	// with [time.Now] by the writer.
	Time time.Time

	// DstIP is the destination address of the flow. A firewall
	// event holds the destination of the packet, and an Envoy event
	// holds the upstream address that Envoy connected to. The store
	// records an IPv4-mapped IPv6 address as the IPv4 address.
	//
	// The zero value means unset. A DNS event leaves it unset,
	// because a query has no destination address. An Envoy event
	// leaves it unset when Envoy denied the request before it chose
	// an upstream.
	DstIP netip.Addr

	// Domain is the qname (DNS), :authority header (HTTP), or
	// SNI (TCP/TLS) value used for grouping in `stats top`.
	Domain string

	// Source is the subsystem that produced this event.
	Source Source

	// Decision is the policy outcome.
	Decision Decision

	// Protocol is the upper-layer protocol tag.
	// See [ProtocolDNS], [ProtocolHTTP], [ProtocolTCP].
	Protocol Protocol

	// HTTPMethod is the HTTP request method when applicable.
	HTTPMethod string

	// HTTPPath is the HTTP request path when applicable.
	HTTPPath string

	// Flags is the raw Envoy RESPONSE_FLAGS string when applicable.
	Flags string

	// Reason is a short tag explaining a deny/error decision.
	// See [ReasonBlockedMode], [ReasonNotAllowlisted], [ReasonUpstream].
	//
	// A firewall event that holds a rule index repeats the index
	// here as "rule=N". A firewall event for a packet that a rule
	// of the `egressDeny` list dropped holds "deny-rule=N". N is the
	// index of that rule in the `egressDeny` list of the policy that
	// was in force at the time of the event, and the first rule has
	// index 0.
	Reason Reason

	// Port is the destination port of the flow. A firewall event of
	// a TCP or UDP packet holds the destination port of the packet.
	// An Envoy event holds the port of the upstream that Envoy chose.
	//
	// An Envoy event of an HTTP request without an upstream holds
	// the port that the authority of the request names. When the
	// authority of a plain HTTP request names no port, the event
	// holds port 80.
	//
	// The zero value means unset. A DNS event and a firewall event
	// of another protocol, such as ICMP, leave it unset. An Envoy
	// event without an upstream leaves it unset in these cases:
	//
	//   - The event is a TCP event.
	//   - The HTTP request has no authority.
	//   - The HTTP request arrived inside a TLS tunnel, and its
	//     authority names no port.
	Port int

	// RuleIndex is the index of the rule that decided the event, in
	// the `egress` list of the policy that was in force at the time
	// of the event. The index starts at 0, so it holds a value only
	// when HasRuleIndex is true. Read that policy with
	// [Reader.PolicyAt], from the instance ID and the time of the
	// event. A firewall event during a daemon reload can hold the index
	// of a rule of the new policy. [Reader.PolicyAt] still returns the
	// previous policy for it, because the daemon records the snapshot
	// of the reload after it replaces the firewall rules.
	//
	// A firewall event holds a rule index when one egress rule
	// accepted the packet in the firewall. A firewall event for a
	// packet that no rule allows holds none. A firewall event for a
	// packet that an `egressDeny` rule dropped holds none, because
	// the index of that rule points into another list. Reason names
	// that rule. A DNS event holds none, because a name can match
	// several rules, and an Envoy event holds none.
	RuleIndex int

	// HTTPStatus is the HTTP response status when applicable.
	HTTPStatus int

	// BytesRx is the bytes received from the downstream peer.
	BytesRx int64

	// BytesTx is the bytes sent to the downstream peer.
	BytesTx int64

	// DurationMS is the request duration in milliseconds.
	DurationMS int64

	// HasRuleIndex reports whether RuleIndex holds a value.
	HasRuleIndex bool
}
