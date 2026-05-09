// Package dnscache holds a bounded reverse map from
// destination IP to the most recent qname that resolved to it.
//
// The DNS proxy populates the cache synchronously on each successful
// resolution, before the upstream answer is written back to the
// client, so a workload's first SYN never races the cache write.
// Consumers query by [netip.Addr] to attach a domain to a
// kernel-logged egress packet. An IP that resolved recently still
// has its qname for a fixed grace window after the underlying TTL
// expires, which lets log records that lag the resolver decision
// still find a match.
//
// The cache is bounded two ways: a global LRU cap and a per-IP FIFO
// cap. Together they prevent memory exhaustion from a
// many-domains-per-IP attack or a long-tail of resolutions. A
// background sweeper reclaims entries whose newest record is past
// `ttl + grace`, so an IP that resolved once and is never looked up
// again does not pin memory forever.
//
// Create instances with [New]. Keys are [netip.Addr] values
// canonicalized via [netip.Addr.Unmap] so v4 and v4-mapped-v6 forms
// of the same address collapse to one entry.
package dnscache
