// Package nflog ingests kernel nfnetlink_log events into the
// [eventstore.Store]. Rules in the firewall package emit
// `log group N prefix "..."` directives whose payload is a
// [logprefix]-encoded decision and rule index. The [Reader] binds to
// the same group, parses the payload plus the L3+L4 packet headers,
// looks up a best-effort qname from a reverse cache, and emits one
// [eventstore.Event] per packet.
//
// The reader is consumptive only. It never mutates kernel rules, and
// the data plane is unaffected by its liveness or backpressure. When
// the [eventstore.Store] channel is full, [eventstore.Store.Emit]
// drops the event and bumps a counter, matching the overflow
// discipline of the DNS proxy and Envoy gRPC ALS source.
//
// Create instances with [New]. The default `Bufsize` of 128 fits
// worst-case IPv6 with one extension header (Hop-by-Hop or Fragment)
// plus a TCP/UDP header without truncating the bytes the 5-tuple
// parser needs.
package nflog
