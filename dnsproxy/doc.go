// Package dnsproxy is a filtering DNS proxy that resolves allowed
// domains via an upstream resolver and populates nftables IP sets
// with the resulting addresses for real-time firewall updates.
//
// Three filter modes control how queries are handled:
//
//   - Forward-all: every query is proxied to upstream unchanged.
//     Active when the config is nil, egress is unrestricted, or the
//     domain list contains a bare wildcard "*".
//   - Deny-all: every query receives REFUSED (RCODE 5) without
//     contacting upstream. Active when the config uses a blocked
//     egress rule (egress: [{}]).
//   - Allowlist: queries matching the domain list are forwarded to
//     upstream; non-matching queries receive NXDOMAIN (RCODE 3).
//     NXDOMAIN is used instead of REFUSED so that stub resolvers
//     (notably nsncd) correctly fall back through the resolv.conf
//     search domain list before giving up.
//
// For forwarded queries, every A/AAAA record in the response is
// inserted into the corresponding nftables set with a per-element
// TTL derived from the DNS response (clamped to a minimum of 60 s).
// CNAME chains are followed, and the TTL is taken as the minimum
// across the chain.
package dnsproxy
