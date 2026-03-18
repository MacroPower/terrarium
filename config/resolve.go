package config

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// httpRuleKey returns a canonical string key for deduplicating
// [ResolvedHTTPRule] entries. The key includes all fields (method,
// path, host, headers, header matches) so that rules differing only
// in header constraints are not collapsed.
func httpRuleKey(hr ResolvedHTTPRule) string {
	var b strings.Builder

	b.WriteString(hr.Method)
	b.WriteByte('\x00')
	b.WriteString(hr.Path)
	b.WriteByte('\x00')
	b.WriteString(hr.Host)

	if len(hr.Headers) > 0 {
		sorted := make([]string, len(hr.Headers))
		copy(sorted, hr.Headers)
		sort.Strings(sorted)

		for _, h := range sorted {
			b.WriteByte('\x00')
			b.WriteString(h)
		}
	}

	if len(hr.HeaderMatches) > 0 {
		sorted := make([]HeaderMatch, len(hr.HeaderMatches))
		copy(sorted, hr.HeaderMatches)
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].Name != sorted[j].Name {
				return sorted[i].Name < sorted[j].Name
			}

			return sorted[i].Value < sorted[j].Value
		})

		for _, hm := range sorted {
			b.WriteByte('\x01')
			b.WriteString(hm.Name)
			b.WriteByte('=')
			b.WriteString(hm.Value)
			b.WriteByte(':')
			b.WriteString(string(hm.Mismatch))
		}
	}

	return b.String()
}

// sortHTTPRules sorts resolved HTTP rules by path, method, host, then
// by full canonical key for deterministic output when those fields tie.
func sortHTTPRules(rules []ResolvedHTTPRule) {
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Path != rules[j].Path {
			return rules[i].Path < rules[j].Path
		}

		if rules[i].Method != rules[j].Method {
			return rules[i].Method < rules[j].Method
		}

		if rules[i].Host != rules[j].Host {
			return rules[i].Host < rules[j].Host
		}

		return httpRuleKey(rules[i]) < httpRuleKey(rules[j])
	})
}

// FQDNSetName returns the nftables set name for a FQDN rule index
// and address family. Names follow terrarium_fqdn{4,6}_R where R is
// the 0-indexed position among FQDN-bearing rules with non-TCP ports.
func FQDNSetName(ruleIdx int, ipv6 bool) string {
	if ipv6 {
		return fmt.Sprintf("terrarium_fqdn6_%d", ruleIdx)
	}

	return fmt.Sprintf("terrarium_fqdn4_%d", ruleIdx)
}

// ICMPFQDNSetName returns the nftables set name for an ICMP FQDN
// rule index and address family. Names follow
// terrarium_fqdnicmp{4,6}_R where R is the 0-indexed position among
// ICMP+FQDN rules.
func ICMPFQDNSetName(ruleIdx int, ipv6 bool) string {
	if ipv6 {
		return fmt.Sprintf("terrarium_fqdnicmp6_%d", ruleIdx)
	}

	return fmt.Sprintf("terrarium_fqdnicmp4_%d", ruleIdx)
}

// CatchAllFQDNSetName returns the nftables set name for a catch-all
// FQDN rule index and address family. Names follow
// terrarium_fqdnca{4,6}_R where R is the 0-indexed position among
// catch-all FQDN rules (those without toPorts or with wildcard port 0).
func CatchAllFQDNSetName(ruleIdx int, ipv6 bool) string {
	if ipv6 {
		return fmt.Sprintf("terrarium_fqdnca6_%d", ruleIdx)
	}

	return fmt.Sprintf("terrarium_fqdnca4_%d", ruleIdx)
}

// TCPForwardHosts returns a deduplicated, sorted list of hostnames from
// the config's [TCPForward] entries.
func (c *Config) TCPForwardHosts() []string {
	seen := make(map[string]bool)

	var hosts []string
	for _, fwd := range c.TCPForwards {
		if !seen[fwd.Host] {
			seen[fwd.Host] = true
			hosts = append(hosts, fwd.Host)
		}
	}

	sort.Strings(hosts)

	return hosts
}

// ResolveRulesForPort returns resolved rules scoped to a specific port.
// Only rules whose toPorts match the given port (or that have no
// toPorts, meaning all ports) are included. L7 rules are extracted
// only from matching [PortRule] entries. When the same domain appears
// in multiple matching rules, L7 constraints are merged using OR
// semantics; if any occurrence has no L7 rules, the merged result has
// none (unrestricted wins).
//
// Note: matchPattern values (e.g. "*.example.com", "**.example.com")
// are preserved as domain keys. Envoy server_names uses suffix-based
// matching, which would match arbitrarily deep subdomains; an RBAC
// network filter (see buildWildcardRBACFilter) is prepended to
// wildcard filter chains to enforce the correct depth (single-label
// for *, multi-label for **), matching CiliumNetworkPolicy semantics.
func (c *Config) ResolveRulesForPort(ctx context.Context, port int) []ResolvedRule {
	type merged struct {
		httpRules    []ResolvedHTTPRule
		unrestricted bool
	}

	byDomain := make(map[string]*merged)

	var order []string

	egressRules := c.EgressRules()
	for i := range egressRules {
		hasFQDNs := len(egressRules[i].ToFQDNs) > 0
		hasCIDR := len(egressRules[i].ToCIDR) > 0 || len(egressRules[i].ToCIDRSet) > 0

		if !hasFQDNs && !hasCIDR {
			continue
		}

		// CIDR rules only contribute when they have L7 rules.
		if hasCIDR && !hasFQDNs && !ruleHasL7(egressRules[i]) {
			continue
		}

		matched, hasPlainL4, httpRules, serverNames := matchRuleForPort(ctx, egressRules[i], port)
		if !matched {
			continue
		}

		addDomain := func(domain string) {
			m, exists := byDomain[domain]
			if !exists {
				m = &merged{}
				byDomain[domain] = m
				order = append(order, domain)
			}

			if hasPlainL4 {
				m.unrestricted = true
			} else {
				m.httpRules = append(m.httpRules, httpRules...)
			}
		}

		if hasFQDNs {
			domains := fqdnDomains(egressRules[i].ToFQDNs)

			// serverNames replaces FQDN domains for SNI
			// filtering: DNS resolution still uses FQDN
			// matchName/matchPattern, but the Envoy SNI
			// allowlist uses serverNames instead.
			if len(serverNames) > 0 && !hasPlainL4 {
				domains = serverNames
			}

			for _, d := range domains {
				addDomain(d)
			}
		}

		// CIDR+L7 rules use a catch-all domain ("*") with HTTP
		// restrictions. The Envoy listener receives CIDR traffic
		// via nftables REDIRECT and applies the L7 filter.
		if hasCIDR && len(httpRules) > 0 {
			addDomain("*")
		}
	}

	sort.Strings(order)

	result := make([]ResolvedRule, 0, len(order))
	for _, d := range order {
		m := byDomain[d]
		r := ResolvedRule{Domain: d}

		if !m.unrestricted && len(m.httpRules) > 0 {
			// Deduplicate HTTP rules by all fields (method,
			// path, host, headers, header matches).
			seen := make(map[string]bool, len(m.httpRules))
			for _, hr := range m.httpRules {
				k := httpRuleKey(hr)
				if !seen[k] {
					seen[k] = true

					r.HTTPRules = append(r.HTTPRules, hr)
				}
			}

			sortHTTPRules(r.HTTPRules)
		}

		result = append(result, r)
	}

	return result
}

// ruleHasL7 reports whether an egress rule has any L7 HTTP rules
// in its toPorts entries.
func ruleHasL7(rule EgressRule) bool {
	for _, pr := range rule.ToPorts {
		if pr.Rules != nil && len(pr.Rules.HTTP) > 0 {
			return true
		}
	}

	return false
}

// fqdnDomains extracts the effective domain from each
// [FQDNSelector], preferring matchName over matchPattern. Bare
// double-star patterns ("**") are normalized to a single star.
func fqdnDomains(fqdns []FQDNSelector) []string {
	domains := make([]string, 0, len(fqdns))
	for _, fqdn := range fqdns {
		domain := fqdn.MatchName
		if domain == "" {
			domain = fqdn.MatchPattern
			if domain == "**" {
				domain = "*"
			}
		}

		domains = append(domains, domain)
	}

	return domains
}

// matchRuleForPort determines whether an egress rule applies to the
// given port and collects L7 rules and serverNames from matching
// toPorts entries.
//
// Two-way distinction for PortRule.Rules:
//   - Rules == nil, Rules.HTTP == nil, or len(HTTP) == 0: plain L4, no L7
//     inspection.
//   - Rules.HTTP non-empty: L7 active with rules.
//
// A PortRule with serverNames but no L7 rules is TLS-restricted, not
// plain L4. The collected serverNames are returned separately for the
// caller to use as SNI allowlist domains.
//
// Cilium semantics: if ANY matching PortRule for this port has no L7
// rules and no serverNames (plain L4), it nullifies sibling L7 rules
// on the same port within this EgressRule.
func matchRuleForPort(ctx context.Context, rule EgressRule, port int) (bool, bool, []ResolvedHTTPRule, []string) {
	if len(rule.ToPorts) == 0 {
		// No toPorts: domain allowed on all ports, no L7
		// restrictions from this rule.
		return true, true, nil, nil
	}

	var (
		matched     bool
		hasPlainL4  bool
		httpRules   []ResolvedHTTPRule
		serverNames []string
	)

	for _, pr := range rule.ToPorts {
		if !portRuleMatchesPort(ctx, pr, port) {
			continue
		}

		matched = true

		if pr.Rules == nil || pr.Rules.HTTP == nil || len(pr.Rules.HTTP) == 0 {
			// PortRule with serverNames is TLS-restricted,
			// not plain L4. Collect serverNames separately.
			if len(pr.ServerNames) > 0 {
				serverNames = append(serverNames, pr.ServerNames...)
			} else if portRuleHasTCPPort(ctx, pr, port) {
				// Plain L4 rule on this port: nullifies
				// all sibling L7 for this EgressRule.
				// Only TCP-compatible entries can nullify
				// L7 (HTTP inspection is TCP-only). A
				// UDP/443 entry must not cancel TCP/443
				// L7 rules.
				hasPlainL4 = true
			}
		} else {
			for _, h := range pr.Rules.HTTP {
				httpRules = append(httpRules, ResolvedHTTPRule(h))
			}
		}
	}

	return matched, hasPlainL4, httpRules, serverNames
}

// portRuleMatchesPort reports whether a port rule matches a specific
// port number. An empty Ports list matches all ports (Cilium semantics
// for L7-only toPorts). When EndPort is set, the rule matches any port
// in the range [Port, EndPort] inclusive.
func portRuleMatchesPort(ctx context.Context, pr PortRule, port int) bool {
	if len(pr.Ports) == 0 {
		return true
	}

	for _, p := range pr.Ports {
		resolved, err := ResolvePort(ctx, p.Port)
		if err != nil {
			continue
		}

		n := int(resolved)

		// Port 0 is a wildcard: matches any target port.
		if n == 0 {
			return true
		}

		if p.EndPort > 0 && port >= n && port <= p.EndPort {
			return true
		}

		if n == port {
			return true
		}
	}

	return false
}

// portRuleHasTCPPort reports whether a [PortRule] contains a
// TCP-compatible port entry matching the given port number. An entry is
// TCP-compatible when its protocol is TCP, ANY, or empty (the default).
// This prevents non-TCP entries (UDP, SCTP) from nullifying TCP L7
// rules during intra-rule L7 resolution, matching Cilium's per-(port,
// protocol) L4Filter semantics.
func portRuleHasTCPPort(ctx context.Context, pr PortRule, port int) bool {
	if len(pr.Ports) == 0 {
		// No ports list means L7-only toPorts entry, which is
		// implicitly TCP (HTTP inspection requires TCP).
		return true
	}

	for _, p := range pr.Ports {
		proto := normalizeProtocol(p.Protocol)
		if proto != ProtoAny && proto != ProtoTCP {
			continue // UDP, SCTP -- skip
		}

		resolved, err := ResolvePort(ctx, p.Port)
		if err != nil {
			continue
		}

		n := int(resolved)

		if n == 0 {
			return true
		}

		if p.EndPort > 0 && port >= n && port <= p.EndPort {
			return true
		}

		if n == port {
			return true
		}
	}

	return false
}

// ResolveRules converts egress rules into a flat, deduplicated, sorted
// list of [ResolvedRule] across all resolved ports. Delegates to
// [Config.ResolveRulesForPort] for each port from
// [Config.ResolvePorts] and unions the results. When a domain
// appears unrestricted on any port, the global result is unrestricted.
func (c *Config) ResolveRules(ctx context.Context) []ResolvedRule {
	ports := c.ResolvePorts(ctx)

	type merged struct {
		httpRules    map[string]ResolvedHTTPRule
		unrestricted bool
	}

	byDomain := make(map[string]*merged)

	var order []string

	for _, port := range ports {
		portRules := c.ResolveRulesForPort(ctx, port)

		for _, r := range portRules {
			m, exists := byDomain[r.Domain]
			if !exists {
				m = &merged{
					httpRules: make(map[string]ResolvedHTTPRule),
				}
				byDomain[r.Domain] = m
				order = append(order, r.Domain)
			}

			if !r.IsRestricted() {
				m.unrestricted = true
			}

			for _, hr := range r.HTTPRules {
				k := httpRuleKey(hr)
				m.httpRules[k] = hr
			}
		}
	}

	sort.Strings(order)

	result := make([]ResolvedRule, 0, len(order))
	for _, d := range order {
		m := byDomain[d]
		r := ResolvedRule{Domain: d}
		if !m.unrestricted && len(m.httpRules) > 0 {
			r.HTTPRules = make([]ResolvedHTTPRule, 0, len(m.httpRules))
			for _, hr := range m.httpRules {
				r.HTTPRules = append(r.HTTPRules, hr)
			}

			sortHTTPRules(r.HTTPRules)
		}

		result = append(result, r)
	}

	return result
}

// ResolveDomains resolves all egress rules into a flat, deduplicated,
// sorted domain list.
func (c *Config) ResolveDomains(ctx context.Context) []string {
	rules := c.ResolveRules(ctx)

	domains := make([]string, len(rules))
	for i, r := range rules {
		domains[i] = r.Domain
	}

	return domains
}

// ResolvePorts collects port numbers for Envoy listeners from egress
// rules. Returns nil when egress is unrestricted or blocked, since
// neither mode needs Envoy FQDN listeners. CIDR-only rules
// (toCIDRSet without toFQDNs) are skipped because they bypass Envoy.
// Ports that are exclusively non-TCP (e.g. UDP-only or SCTP-only) are
// excluded since Envoy only creates TCP listeners. Ports from
// FQDN-bearing rules and single-port toPorts-only rules (no L3
// selectors) both contribute to the resolved set. Open-port ranges
// (endPort > 0 on toPorts-only rules) are skipped because they
// bypass Envoy via direct iptables ACCEPT. Returns a sorted,
// deduplicated list.
//
// Non-TCP ports from FQDN rules are handled separately by
// [Config.ResolveFQDNNonTCPPorts] and enforced via ipset-backed iptables rules.
func (c *Config) ResolvePorts(ctx context.Context) []int {
	if c.IsEgressUnrestricted() {
		return nil
	}

	rules := c.EgressRules()
	if rules == nil {
		return nil
	}

	seen := make(map[int]bool)
	for ri := range rules {
		// Empty rules have no selectors, so they contribute
		// nothing to Envoy listeners.
		if len(rules[ri].ToFQDNs) == 0 && len(rules[ri].ToPorts) == 0 &&
			len(rules[ri].ToCIDR) == 0 && len(rules[ri].ToCIDRSet) == 0 {
			continue
		}

		// CIDR-only rules bypass Envoy unless they have
		// serverNames (which require Envoy for SNI inspection)
		// or L7 HTTP rules (which require Envoy for request
		// filtering). Validation prevents FQDN+CIDR combinations,
		// so this is equivalent to "not an FQDN rule" when no
		// serverNames and no L7.
		if len(rules[ri].ToCIDRSet) > 0 || len(rules[ri].ToCIDR) > 0 {
			if !ruleHasServerNames(rules[ri]) && !ruleHasL7(rules[ri]) {
				continue
			}
		}

		isOpenPortRule := len(rules[ri].ToFQDNs) == 0

		// Explicit ports from FQDN and open-port rules contribute.
		// FQDN rules without toPorts (catch-all) are handled by
		// [Config.ResolveCatchAllFQDNRules] and don't need Envoy
		// listeners. Skip ports that are exclusively non-TCP (e.g.
		// UDP-only or SCTP-only), since Envoy only handles TCP
		// listeners. Open-port ranges bypass Envoy via direct
		// iptables ACCEPT; they don't need REDIRECT listeners.
		for _, pr := range rules[ri].ToPorts {
			for _, p := range pr.Ports {
				proto := normalizeProtocol(p.Protocol)
				if proto != ProtoAny && proto != ProtoTCP {
					continue
				}

				if isOpenPortRule && p.EndPort > 0 {
					continue
				}

				resolved, err := ResolvePort(ctx, p.Port)
				if err == nil && resolved > 0 {
					seen[int(resolved)] = true

					// FQDN rules with endPort need individual
					// Envoy listeners for each port in the range.
					// Validation caps the range size.
					if !isOpenPortRule && p.EndPort > 0 {
						for ep := int(resolved) + 1; ep <= p.EndPort; ep++ {
							seen[ep] = true
						}
					}
				}
			}
		}
	}

	result := make([]int, 0, len(seen))
	for p := range seen {
		result = append(result, p)
	}

	sort.Ints(result)
	if len(result) == 0 {
		return nil
	}

	return result
}

// ExtraPorts returns resolved ports that are not in DefaultPorts
// (80 and 443), since those have dedicated redirect rules.
func (c *Config) ExtraPorts(ctx context.Context) []int {
	var extra []int
	for _, p := range c.ResolvePorts(ctx) {
		if p != 80 && p != 443 {
			extra = append(extra, p)
		}
	}

	return extra
}

// HasUnrestrictedOpenPorts reports whether any port-only egress rule
// (no toFQDNs, toCIDR, or toCIDRSet) contains a toPorts entry with
// an empty Ports list. Under Cilium semantics, empty Ports means "all
// ports"; combined with the implicit wildcard L3 (no L3 selector),
// this allows all traffic. Terrarium represents this as an
// unrestricted ACCEPT for the user UID in iptables, which subsumes
// CIDR except DROPs and CIDR ACCEPTs from other rules (Cilium OR
// semantics across rules).
func (c *Config) HasUnrestrictedOpenPorts(ctx context.Context) bool {
	eRules := c.EgressRules()
	for ri := range eRules {
		if len(eRules[ri].ToFQDNs) > 0 || len(eRules[ri].ToCIDR) > 0 || len(eRules[ri].ToCIDRSet) > 0 {
			continue
		}

		for _, pr := range eRules[ri].ToPorts {
			if len(pr.Ports) == 0 {
				return true
			}

			for _, p := range pr.Ports {
				n, err := ResolvePort(ctx, p.Port)
				if err != nil || n == 0 {
					return true
				}
			}
		}
	}

	return false
}

// ResolveOpenPortRules returns resolved open port entries from rules
// that have toPorts but neither toFQDNs nor toCIDRSet. These ports
// allow all destinations (passthrough without domain filtering). ANY
// protocol is expanded into separate TCP, UDP, and SCTP entries.
func (c *Config) ResolveOpenPortRules(ctx context.Context) []ResolvedOpenPort {
	seen := make(map[string]bool)

	var result []ResolvedOpenPort

	openRules := c.EgressRules()
	for ri := range openRules {
		if len(openRules[ri].ToFQDNs) > 0 || len(openRules[ri].ToCIDR) > 0 || len(openRules[ri].ToCIDRSet) > 0 {
			continue
		}

		for _, pr := range openRules[ri].ToPorts {
			for _, p := range pr.Ports {
				resolved, err := ResolvePort(ctx, p.Port)
				if err != nil || resolved == 0 {
					continue
				}

				n := int(resolved)
				proto := normalizeProtocol(p.Protocol)
				protos := []string{proto}
				if proto == ProtoAny {
					protos = []string{ProtoTCP, ProtoUDP, ProtoSCTP}
				}

				for _, pr := range protos {
					k := pr + "/" + strconv.Itoa(n) + "/" + strconv.Itoa(p.EndPort)
					if !seen[k] {
						seen[k] = true

						result = append(result, ResolvedOpenPort{Port: n, EndPort: p.EndPort, Protocol: pr})
					}
				}
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Port != result[j].Port {
			return result[i].Port < result[j].Port
		}

		if result[i].EndPort != result[j].EndPort {
			return result[i].EndPort < result[j].EndPort
		}

		return result[i].Protocol < result[j].Protocol
	})

	return result
}

// ResolveOpenPorts returns sorted, deduplicated port numbers from open
// port rules. This is a convenience wrapper over [Config.ResolveOpenPortRules]
// used by Envoy listener creation where only port numbers matter.
func (c *Config) ResolveOpenPorts(ctx context.Context) []int {
	openRules := c.ResolveOpenPortRules(ctx)
	seen := make(map[int]bool, len(openRules))

	var result []int
	for _, r := range openRules {
		if !seen[r.Port] {
			seen[r.Port] = true
			result = append(result, r.Port)
		}
	}

	return result
}

// ruleHasNonTCPPorts reports whether an egress rule has any ports with
// a non-TCP protocol (UDP, SCTP, or ANY which expands to UDP).
func ruleHasNonTCPPorts(rule EgressRule) bool {
	for _, pr := range rule.ToPorts {
		for _, p := range pr.Ports {
			proto := normalizeProtocol(p.Protocol)
			if proto != ProtoTCP {
				return true
			}
		}
	}

	return false
}

// ResolveFQDNNonTCPPorts returns resolved non-TCP port entries from
// FQDN rules, grouped per rule. Each qualifying rule (FQDN selectors
// with non-TCP ports) gets its own [FQDNRulePorts] entry so iptables
// can reference per-rule ipsets. These ports are enforced via
// ipset-backed iptables rules that restrict traffic to DNS-resolved
// IPs (the security decision). TPROXY independently routes all
// terrarium UDP through Envoy for access logging, but the filter
// chain ACCEPT here is what permits the traffic. ANY protocol is
// expanded into UDP and SCTP entries (TCP is handled by
// [Config.ResolvePorts] + Envoy). Returns nil when egress is
// unrestricted, blocked, or has no FQDN rules with non-TCP ports.
func (c *Config) ResolveFQDNNonTCPPorts(ctx context.Context) []FQDNRulePorts {
	if c.IsEgressUnrestricted() {
		return nil
	}

	rules := c.EgressRules()
	if rules == nil {
		return nil
	}

	var result []FQDNRulePorts

	ruleIdx := 0

	for ri := range rules {
		if len(rules[ri].ToFQDNs) == 0 || !ruleHasNonTCPPorts(rules[ri]) {
			continue
		}

		seen := make(map[string]bool)

		var ports []ResolvedOpenPort

		for _, pr := range rules[ri].ToPorts {
			for _, p := range pr.Ports {
				resolved, err := ResolvePort(ctx, p.Port)
				if err != nil || resolved == 0 {
					continue
				}

				n := int(resolved)
				proto := normalizeProtocol(p.Protocol)

				// TCP is handled by Envoy via ResolvePorts.
				var protos []string

				switch proto {
				case ProtoTCP:
					continue
				case ProtoUDP, ProtoSCTP:
					protos = []string{proto}
				case ProtoAny:
					// ANY: expand to non-TCP protocols only.
					protos = []string{ProtoUDP, ProtoSCTP}
				}

				for _, pr := range protos {
					k := pr + "/" + strconv.Itoa(n) + "/" + strconv.Itoa(p.EndPort)
					if !seen[k] {
						seen[k] = true

						ports = append(ports, ResolvedOpenPort{Port: n, EndPort: p.EndPort, Protocol: pr})
					}
				}
			}
		}

		if len(ports) > 0 {
			sort.Slice(ports, func(i, j int) bool {
				if ports[i].Port != ports[j].Port {
					return ports[i].Port < ports[j].Port
				}

				if ports[i].EndPort != ports[j].EndPort {
					return ports[i].EndPort < ports[j].EndPort
				}

				return ports[i].Protocol < ports[j].Protocol
			})

			result = append(result, FQDNRulePorts{RuleIndex: ruleIdx, Ports: ports})
		}

		ruleIdx++
	}

	return result
}

// HasFQDNNonTCPPorts reports whether the config contains any FQDN
// rules with non-TCP ports that need ipset-backed iptables rules.
func (c *Config) HasFQDNNonTCPPorts(ctx context.Context) bool {
	return len(c.ResolveFQDNNonTCPPorts(ctx)) > 0
}

// CompileFQDNPatterns returns compiled regexes for all [FQDNSelector]
// entries in FQDN rules that have non-TCP ports. Each pattern carries
// a RuleIndex matching the index used by [Config.ResolveFQDNNonTCPPorts], so
// DNS responses can populate the correct per-rule ipset. Patterns are
// deduplicated within each rule (same selector appearing twice in one
// rule produces one entry) but not across rules (same selector in two
// rules produces two entries with different RuleIndex values).
// [TCPForward] hosts are excluded (they use Envoy, not ipset
// filtering).
func (c *Config) CompileFQDNPatterns() []FQDNPattern {
	var patterns []FQDNPattern

	ruleIdx := 0

	patRules := c.EgressRules()
	for ri := range patRules {
		if len(patRules[ri].ToFQDNs) == 0 || !ruleHasNonTCPPorts(patRules[ri]) {
			continue
		}

		seen := make(map[string]bool)

		for _, fqdn := range patRules[ri].ToFQDNs {
			var original string

			var isMatchName bool

			if fqdn.MatchName != "" {
				original = fqdn.MatchName
				isMatchName = true
			} else {
				original = fqdn.MatchPattern
			}

			if seen[original] {
				continue
			}

			seen[original] = true

			regex := patternToAnchoredRegex(original, isMatchName)
			patterns = append(patterns, FQDNPattern{
				Original:  original,
				Regex:     regexp.MustCompile(regex),
				RuleIndex: ruleIdx,
			})
		}

		ruleIdx++
	}

	return patterns
}

// patternToAnchoredRegex converts an FQDN selector value into an
// anchored regex that matches FQDN-form names (with trailing dot).
// Follows Cilium's matchpattern.ToAnchoredRegexp, including the
// "**." prefix (multi-label depth matching via Cilium's
// subdomainWildcardSpecifierPrefix in matchpattern.go).
func patternToAnchoredRegex(pattern string, isMatchName bool) string {
	if isMatchName {
		escaped := strings.ReplaceAll(pattern, ".", "[.]")

		return "^" + escaped + "[.]$"
	}

	// Collapse runs of 3+ stars to ** so that e.g. "***.example.com"
	// is treated identically to "**.example.com" (Cilium equivalence).
	for strings.Contains(pattern, "***") {
		pattern = strings.ReplaceAll(pattern, "***", "**")
	}

	if isBareWildcard(pattern) {
		return `(^([-a-zA-Z0-9_]+[.])+$)|(^[.]$)`
	}

	// "**." prefix: one or more dot-separated DNS labels followed by
	// the fixed suffix. Matches arbitrary depth (a.b.c.suffix.).
	if strings.HasPrefix(pattern, "**.") {
		suffix := pattern[3:]
		escaped := strings.ReplaceAll(suffix, ".", "[.]")

		return `^([-a-zA-Z0-9_]+([.][-a-zA-Z0-9_]+){0,})[.]` + escaped + `[.]$`
	}

	// Standard Cilium: each "." becomes "[.]", each "*" becomes
	// "[-a-zA-Z0-9_]*" (zero or more chars within a single label).
	// Mid-position "**" naturally collapses to single-label since
	// each star is expanded independently.
	result := strings.ReplaceAll(pattern, ".", "[.]")
	result = strings.ReplaceAll(result, "*", "[-a-zA-Z0-9_]*")

	return "^" + result + "[.]$"
}

// isBareWildcard reports whether pattern consists entirely of "*"
// characters (e.g. "*", "**", "***").
func isBareWildcard(pattern string) bool {
	return strings.TrimLeft(pattern, "*") == ""
}

// ResolveCIDRRules collects toCIDR and toCIDRSet entries from all
// egress rules, preserving port associations from each rule's toPorts,
// and separates them by address family. Under Cilium semantics, CIDR
// rules are direct L3 allow selectors that bypass the Envoy proxy. If
// the parent rule has toPorts, the CIDR is port-scoped (L3 AND L4);
// otherwise the CIDR allows any port.
func (c *Config) ResolveCIDRRules(ctx context.Context) ([]ResolvedCIDR, []ResolvedCIDR) {
	var ipv4, ipv6 []ResolvedCIDR

	ruleIdx := 0

	cidrRules := c.EgressRules()
	for ri := range cidrRules {
		if len(cidrRules[ri].ToCIDRSet) == 0 && len(cidrRules[ri].ToCIDR) == 0 {
			continue
		}

		ports := resolvePortsFromRule(ctx, cidrRules[ri])
		serverNames := collectServerNames(cidrRules[ri])

		// Collect ports that have L7 rules so the firewall can
		// redirect those to Envoy instead of issuing RETURN.
		l7Ports := resolveL7Ports(ctx, cidrRules[ri])

		// Combine toCIDR and toCIDRSet into a unified list.
		allCIDRs := make([]CIDRRule, 0, len(cidrRules[ri].ToCIDR)+len(cidrRules[ri].ToCIDRSet))
		for _, cidr := range cidrRules[ri].ToCIDR {
			allCIDRs = append(allCIDRs, CIDRRule{CIDR: cidr})
		}

		allCIDRs = append(allCIDRs, cidrRules[ri].ToCIDRSet...)

		for _, cidr := range allCIDRs {
			v4, v6 := classifyCIDR(cidr, ports, ruleIdx)
			if v4 != nil {
				v4.ServerNames = serverNames
				v4.L7Ports = l7Ports
				ipv4 = append(ipv4, *v4)
			}

			if v6 != nil {
				v6.ServerNames = serverNames
				v6.L7Ports = l7Ports
				ipv6 = append(ipv6, *v6)
			}
		}

		ruleIdx++
	}

	return ipv4, ipv6
}

// ResolveServerNameRulesForPort returns resolved rules from CIDR
// rules that have serverNames on the given port. These are converted
// into [ResolvedRule] entries so Envoy can create SNI filter chains
// for them. ServerNames on CIDR rules are always passthrough (no L7
// HTTP inspection). FQDN rules with serverNames are handled by
// [Config.ResolveRulesForPort] instead.
func (c *Config) ResolveServerNameRulesForPort(ctx context.Context, port int) []ResolvedRule {
	seen := make(map[string]bool)

	var result []ResolvedRule

	rules := c.EgressRules()
	for ri := range rules {
		if len(rules[ri].ToCIDR) == 0 && len(rules[ri].ToCIDRSet) == 0 {
			continue
		}

		for _, pr := range rules[ri].ToPorts {
			if len(pr.ServerNames) == 0 {
				continue
			}

			if !portRuleMatchesPort(ctx, PortRule{Ports: pr.Ports}, port) {
				continue
			}

			for _, name := range pr.ServerNames {
				if !seen[name] {
					seen[name] = true
					result = append(result, ResolvedRule{Domain: name})
				}
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Domain < result[j].Domain
	})

	return result
}

// resolveL7Ports returns the set of port numbers from toPorts entries
// that have L7 HTTP rules. Returns nil when no L7 rules are present.
func resolveL7Ports(ctx context.Context, rule EgressRule) map[int]bool {
	var result map[int]bool

	for _, pr := range rule.ToPorts {
		if pr.Rules == nil || len(pr.Rules.HTTP) == 0 {
			continue
		}

		for _, p := range pr.Ports {
			resolved, err := ResolvePort(ctx, p.Port)
			if err != nil || resolved == 0 {
				continue
			}

			if result == nil {
				result = make(map[int]bool)
			}

			result[int(resolved)] = true
		}
	}

	return result
}

// ruleHasServerNames reports whether any toPorts entry in an egress
// rule has serverNames set.
func ruleHasServerNames(rule EgressRule) bool {
	for _, pr := range rule.ToPorts {
		if len(pr.ServerNames) > 0 {
			return true
		}
	}

	return false
}

// collectServerNames returns a deduplicated, sorted list of
// serverNames from all toPorts entries on an egress rule.
func collectServerNames(rule EgressRule) []string {
	seen := make(map[string]bool)

	var names []string

	for _, pr := range rule.ToPorts {
		for _, name := range pr.ServerNames {
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}

	sort.Strings(names)

	if len(names) == 0 {
		return nil
	}

	return names
}

// resolvePortsFromRule extracts a sorted, deduplicated list of resolved
// port-protocol pairs from a rule's toPorts. Returns nil when the rule
// has no toPorts or when any PortRule has an empty Ports list (meaning
// all ports).
func resolvePortsFromRule(ctx context.Context, rule EgressRule) []ResolvedPortProto {
	return resolvePortsFromPortRules(ctx, rule.ToPorts)
}

// resolvePortsFromPortRules extracts a sorted, deduplicated list of
// resolved port-protocol pairs from a list of [PortRule]s. Returns
// nil when the list is empty or when any PortRule has an empty Ports
// list (meaning all ports). Used by both allow and deny rule
// resolution.
func resolvePortsFromPortRules(ctx context.Context, portRules []PortRule) []ResolvedPortProto {
	if len(portRules) == 0 {
		return nil
	}

	seen := make(map[string]bool)

	var ports []ResolvedPortProto

	for _, pr := range portRules {
		if len(pr.Ports) == 0 {
			// Empty Ports list means all ports.
			return nil
		}

		for _, p := range pr.Ports {
			resolved, err := ResolvePort(ctx, p.Port)
			if err != nil {
				continue
			}

			if resolved == 0 {
				// Wildcard port: equivalent to empty Ports list.
				return nil
			}

			n := int(resolved)
			proto := normalizeProtocol(p.Protocol)
			// Expand ANY protocol into separate TCP, UDP, and SCTP
			// entries so port matching always has a concrete protocol.
			protos := []string{proto}
			if proto == ProtoAny {
				protos = []string{ProtoTCP, ProtoUDP, ProtoSCTP}
			}

			for _, expandedProto := range protos {
				k := expandedProto + "/" + strconv.Itoa(n) + "/" + strconv.Itoa(p.EndPort)
				if !seen[k] {
					seen[k] = true

					ports = append(ports, ResolvedPortProto{
						Port:     n,
						EndPort:  p.EndPort,
						Protocol: expandedProto,
					})
				}
			}
		}
	}

	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Port != ports[j].Port {
			return ports[i].Port < ports[j].Port
		}

		if ports[i].EndPort != ports[j].EndPort {
			return ports[i].EndPort < ports[j].EndPort
		}

		return ports[i].Protocol < ports[j].Protocol
	})

	return ports
}

// classifyCIDR parses a CIDR rule and classifies it by address family,
// filtering except entries to only include those matching the same
// family. The ruleIndex is propagated to the resulting [ResolvedCIDR]
// to track which egress rule it came from.
func classifyCIDR(cidr CIDRRule, ports []ResolvedPortProto, ruleIndex int) (*ResolvedCIDR, *ResolvedCIDR) {
	_, _, err := net.ParseCIDR(cidr.CIDR)
	if err != nil {
		return nil, nil
	}

	// Filter except entries by address family. Use string-based
	// detection to avoid Go's IPv4-mapped IPv6 normalization where
	// To4() returns non-nil for "::ffff:10.0.0.0/104".
	var v4Except, v6Except []string
	for _, exc := range cidr.Except {
		_, _, excErr := net.ParseCIDR(exc)
		if excErr != nil {
			continue
		}

		if strings.Contains(exc, ":") {
			v6Except = append(v6Except, exc)
		} else {
			v4Except = append(v4Except, exc)
		}
	}

	if strings.Contains(cidr.CIDR, ":") {
		resolved := ResolvedCIDR{CIDR: cidr.CIDR, Except: v6Except, Ports: ports, RuleIndex: ruleIndex}
		if len(resolved.Except) == 0 {
			resolved.Except = nil
		}

		return nil, &resolved
	}

	resolved := ResolvedCIDR{CIDR: cidr.CIDR, Except: v4Except, Ports: ports, RuleIndex: ruleIndex}
	if len(resolved.Except) == 0 {
		resolved.Except = nil
	}

	return &resolved, nil
}

// ResolveDenyCIDRRules collects toCIDR and toCIDRSet entries from all
// egress deny rules, preserving port associations, and separates them
// by address family. Same shape as [Config.ResolveCIDRRules] but for
// deny rules.
func (c *Config) ResolveDenyCIDRRules(ctx context.Context) ([]ResolvedCIDR, []ResolvedCIDR) {
	var ipv4, ipv6 []ResolvedCIDR

	denyRules := c.EgressDenyRules()
	for ri := range denyRules {
		if len(denyRules[ri].ToCIDRSet) == 0 && len(denyRules[ri].ToCIDR) == 0 {
			continue
		}

		ports := resolvePortsFromDenyRule(ctx, denyRules[ri])

		allCIDRs := make([]CIDRRule, 0, len(denyRules[ri].ToCIDR)+len(denyRules[ri].ToCIDRSet))
		for _, cidr := range denyRules[ri].ToCIDR {
			allCIDRs = append(allCIDRs, CIDRRule{CIDR: cidr})
		}

		allCIDRs = append(allCIDRs, denyRules[ri].ToCIDRSet...)

		for _, cidr := range allCIDRs {
			v4, v6 := classifyCIDR(cidr, ports, ri)
			if v4 != nil {
				ipv4 = append(ipv4, *v4)
			}

			if v6 != nil {
				ipv6 = append(ipv6, *v6)
			}
		}
	}

	return ipv4, ipv6
}

// resolvePortsFromDenyRule extracts resolved port-protocol pairs from
// a deny rule's toPorts. Delegates to [resolvePortsFromPortRules].
func resolvePortsFromDenyRule(ctx context.Context, rule EgressDenyRule) []ResolvedPortProto {
	return resolvePortsFromPortRules(ctx, rule.ToPorts)
}

// ResolveICMPRules flattens all ICMPRule entries across egress allow
// rules into per-field [ResolvedICMP] entries with their rule index.
// Type codes are already resolved to numeric strings during
// normalization. Returns nil when no egress rules have ICMP entries.
func (c *Config) ResolveICMPRules() []ResolvedICMP {
	return resolveICMPs(c.EgressRules())
}

// ResolveDenyICMPRules flattens all ICMPRule entries across egress
// deny rules into per-field [ResolvedICMP] entries. Same shape as
// [Config.ResolveICMPRules] but for deny rules. CIDRs from sibling
// L3 selectors are attached for destination scoping.
func (c *Config) ResolveDenyICMPRules() []ResolvedICMP {
	deny := c.EgressDenyRules()
	rules := make([]EgressRule, len(deny))

	for i := range deny {
		rules[i] = EgressRule{
			ToCIDR:    deny[i].ToCIDR,
			ToCIDRSet: deny[i].ToCIDRSet,
			ICMPs:     deny[i].ICMPs,
		}
	}

	return resolveICMPs(rules)
}

// resolveICMPs is the shared implementation for ResolveICMPRules.
// CIDRs from sibling toCIDR/toCIDRSet selectors on each rule are
// attached to the resolved entries, filtered by address family, so
// the firewall can scope ICMP rules to the correct L3 destinations.
// When a rule has toFQDNs, UseFQDNSet and FQDNRuleIndex are set on
// each emitted entry so the firewall can use FQDN ipset lookups.
func resolveICMPs(rules []EgressRule) []ResolvedICMP {
	if len(rules) == 0 {
		return nil
	}

	var result []ResolvedICMP

	fqdnRuleIdx := 0

	for ri := range rules {
		hasFQDNs := len(rules[ri].ToFQDNs) > 0

		// Collect CIDRs from sibling L3 selectors on this rule.
		var allCIDRs []CIDRRule
		if len(rules[ri].ToCIDR) > 0 || len(rules[ri].ToCIDRSet) > 0 {
			for _, cidr := range rules[ri].ToCIDR {
				allCIDRs = append(allCIDRs, CIDRRule{CIDR: cidr})
			}

			allCIDRs = append(allCIDRs, rules[ri].ToCIDRSet...)
		}

		for _, icmp := range rules[ri].ICMPs {
			for _, f := range icmp.Fields {
				code, err := strconv.ParseUint(f.Type, 10, 8)
				if err != nil {
					continue // already validated and normalized
				}

				// Filter CIDRs by address family to match the
				// ICMP family (IPv4 CIDRs for IPv4 ICMP, etc.).
				var cidrs []CIDRRule
				if len(allCIDRs) > 0 {
					isV6 := f.Family == FamilyIPv6
					for _, c := range allCIDRs {
						if cidrIsIPv6(c.CIDR) == isV6 {
							cidrs = append(cidrs, c)
						}
					}
				}

				entry := ResolvedICMP{
					CIDRs:     cidrs,
					Family:    f.Family,
					Type:      uint8(code),
					RuleIndex: ri,
				}

				if hasFQDNs {
					entry.UseFQDNSet = true
					entry.FQDNRuleIndex = fqdnRuleIdx
				}

				result = append(result, entry)
			}
		}

		if hasFQDNs && len(rules[ri].ICMPs) > 0 {
			fqdnRuleIdx++
		}
	}

	return result
}

// ResolveDenyPortOnlyRules collects port-protocol pairs from egress
// deny rules that have toPorts but no L3 selectors (no toCIDR or
// toCIDRSet). Under Cilium semantics, a deny rule with only toPorts
// means "deny traffic to any destination on these ports." These are
// separate from [Config.ResolveDenyCIDRRules], which handles deny
// rules with CIDR selectors.
func (c *Config) ResolveDenyPortOnlyRules(ctx context.Context) []ResolvedPortProto {
	denyRules := c.EgressDenyRules()

	seen := make(map[string]bool)

	var result []ResolvedPortProto

	for ri := range denyRules {
		if len(denyRules[ri].ToCIDR) > 0 || len(denyRules[ri].ToCIDRSet) > 0 {
			continue
		}

		// An empty deny rule (no L3 or L4 selectors) is a no-op
		// under Cilium semantics; skip it.
		if len(denyRules[ri].ToPorts) == 0 {
			continue
		}

		ports := resolvePortsFromDenyRule(ctx, denyRules[ri])
		if ports == nil {
			// nil means wildcard (all ports). Emit a single
			// zero-port entry so the firewall can generate a
			// blanket DROP without port matching.
			ports = []ResolvedPortProto{{}}
		}

		for _, pp := range ports {
			k := pp.Protocol + "/" + strconv.Itoa(pp.Port) + "/" + strconv.Itoa(pp.EndPort)
			if !seen[k] {
				seen[k] = true

				result = append(result, pp)
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Port != result[j].Port {
			return result[i].Port < result[j].Port
		}

		if result[i].EndPort != result[j].EndPort {
			return result[i].EndPort < result[j].EndPort
		}

		return result[i].Protocol < result[j].Protocol
	})

	return result
}

// isCatchAllFQDNRule reports whether an egress rule has toFQDNs but no
// explicit ports, meaning it should allow all ports to matched domains.
// This includes rules with no toPorts at all, and rules where all ports
// are wildcard port 0 (without L7).
func isCatchAllFQDNRule(rule EgressRule) bool {
	if len(rule.ToFQDNs) == 0 {
		return false
	}

	if len(rule.ToPorts) == 0 {
		return true
	}

	// Check if all port entries are wildcard 0.
	for _, pr := range rule.ToPorts {
		if len(pr.Ports) == 0 {
			return true
		}

		for _, p := range pr.Ports {
			if p.Port != "0" {
				return false
			}
		}
	}

	return true
}

// ResolveCatchAllFQDNRules returns rule indices for FQDN rules that
// need all-port ipset-based enforcement (no toPorts or wildcard port 0
// without L7). Each rule gets its own ipset pair. Returns nil when
// egress is unrestricted, blocked, or has no catch-all FQDN rules.
func (c *Config) ResolveCatchAllFQDNRules() []int {
	if c.IsEgressUnrestricted() {
		return nil
	}

	rules := c.EgressRules()
	if rules == nil {
		return nil
	}

	var result []int

	ruleIdx := 0

	for ri := range rules {
		if !isCatchAllFQDNRule(rules[ri]) {
			continue
		}

		result = append(result, ruleIdx)
		ruleIdx++
	}

	return result
}

// isICMPFQDNRule reports whether an egress rule has both ICMPs and
// toFQDNs, qualifying it for ICMP FQDN set enforcement.
func isICMPFQDNRule(rule EgressRule) bool {
	return len(rule.ICMPs) > 0 && len(rule.ToFQDNs) > 0
}

// ResolveICMPFQDNRules returns rule indices for rules with both ICMPs
// and toFQDNs. Each qualifying rule gets its own ipset pair for
// destination matching. Returns nil when no rules qualify.
func (c *Config) ResolveICMPFQDNRules() []int {
	if c.IsEgressUnrestricted() {
		return nil
	}

	rules := c.EgressRules()
	if rules == nil {
		return nil
	}

	var result []int

	ruleIdx := 0

	for ri := range rules {
		if !isICMPFQDNRule(rules[ri]) {
			continue
		}

		result = append(result, ruleIdx)
		ruleIdx++
	}

	return result
}

// CompileICMPFQDNPatterns returns compiled regexes for all
// [FQDNSelector] entries in ICMP+FQDN rules. Each pattern carries a
// RuleIndex matching the index used by [Config.ResolveICMPFQDNRules]
// and the FQDNRuleIndex in [ResolvedICMP], so DNS responses can
// populate the correct per-rule ipset.
func (c *Config) CompileICMPFQDNPatterns() []FQDNPattern {
	var patterns []FQDNPattern

	ruleIdx := 0

	rules := c.EgressRules()
	for ri := range rules {
		if !isICMPFQDNRule(rules[ri]) {
			continue
		}

		seen := make(map[string]bool)

		for _, fqdn := range rules[ri].ToFQDNs {
			var original string

			var isMatchName bool

			if fqdn.MatchName != "" {
				original = fqdn.MatchName
				isMatchName = true
			} else {
				original = fqdn.MatchPattern
			}

			if seen[original] {
				continue
			}

			seen[original] = true

			regex := patternToAnchoredRegex(original, isMatchName)
			patterns = append(patterns, FQDNPattern{
				Original:  original,
				Regex:     regexp.MustCompile(regex),
				RuleIndex: ruleIdx,
			})
		}

		ruleIdx++
	}

	return patterns
}

// CompileCatchAllFQDNPatterns returns compiled regexes for all
// [FQDNSelector] entries in catch-all FQDN rules (no toPorts or
// wildcard port 0). Each pattern carries a RuleIndex matching the
// index used by [Config.ResolveCatchAllFQDNRules], so DNS responses
// can populate the correct per-rule ipset.
func (c *Config) CompileCatchAllFQDNPatterns() []FQDNPattern {
	var patterns []FQDNPattern

	ruleIdx := 0

	rules := c.EgressRules()
	for ri := range rules {
		if !isCatchAllFQDNRule(rules[ri]) {
			continue
		}

		seen := make(map[string]bool)

		for _, fqdn := range rules[ri].ToFQDNs {
			var original string

			var isMatchName bool

			if fqdn.MatchName != "" {
				original = fqdn.MatchName
				isMatchName = true
			} else {
				original = fqdn.MatchPattern
			}

			if seen[original] {
				continue
			}

			seen[original] = true

			regex := patternToAnchoredRegex(original, isMatchName)
			patterns = append(patterns, FQDNPattern{
				Original:  original,
				Regex:     regexp.MustCompile(regex),
				RuleIndex: ruleIdx,
			})
		}

		ruleIdx++
	}

	return patterns
}
