package config

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

// normalizeEgressRule mutates an egress rule in place to normalize
// FQDN case, service name port case, and trailing dots. Must be called
// before validation so that normalized values pass the validators.
// Returns an error if a serverNames entry is empty, since normalization
// would otherwise silently filter it via [isBareWildcard].
func normalizeEgressRule(c *Config, ruleIdx int) error {
	rule := &(*c.Egress)[ruleIdx]

	for j := range rule.ToPorts {
		for k := range rule.ToPorts[j].Ports {
			if isSvcName(rule.ToPorts[j].Ports[k].Port) {
				rule.ToPorts[j].Ports[k].Port = strings.ToLower(rule.ToPorts[j].Ports[k].Port)
			}
		}
	}

	for j := range rule.ToPorts {
		// Check for empty server names before normalization so the
		// error is specific (not a generic invalid-characters error
		// from the regex check or silent filtering via isBareWildcard).
		if slices.Contains(rule.ToPorts[j].ServerNames, "") {
			return fmt.Errorf("%w: rule %d", ErrServerNamesEmpty, ruleIdx)
		}

		for k := range rule.ToPorts[j].ServerNames {
			rule.ToPorts[j].ServerNames[k] = strings.TrimRight(
				strings.ToLower(rule.ToPorts[j].ServerNames[k]), ".")
			for strings.Contains(rule.ToPorts[j].ServerNames[k], "***") {
				rule.ToPorts[j].ServerNames[k] = strings.ReplaceAll(
					rule.ToPorts[j].ServerNames[k], "***", "**")
			}
		}

		// Bare wildcards ("*", "**", etc.) are semantically equivalent
		// to omitting serverNames (no SNI restriction). Filter them out
		// so downstream validation and resolution see an empty list.
		filtered := rule.ToPorts[j].ServerNames[:0]
		for _, name := range rule.ToPorts[j].ServerNames {
			if !isBareWildcard(name) {
				filtered = append(filtered, name)
			}
		}

		if len(filtered) == 0 {
			rule.ToPorts[j].ServerNames = nil
		} else {
			rule.ToPorts[j].ServerNames = filtered
		}
	}

	for j := range rule.ToFQDNs {
		fqdn := &rule.ToFQDNs[j]
		fqdn.MatchName = strings.TrimRight(strings.ToLower(fqdn.MatchName), ".")

		fqdn.MatchPattern = strings.TrimRight(strings.ToLower(fqdn.MatchPattern), ".")
		for strings.Contains(fqdn.MatchPattern, "***") {
			fqdn.MatchPattern = strings.ReplaceAll(fqdn.MatchPattern, "***", "**")
		}
	}

	for j := range rule.ToPorts {
		if rule.ToPorts[j].Rules == nil {
			continue
		}

		for k := range rule.ToPorts[j].Rules.DNS {
			dns := &rule.ToPorts[j].Rules.DNS[k]
			dns.MatchName = strings.TrimRight(strings.ToLower(dns.MatchName), ".")

			dns.MatchPattern = strings.TrimRight(strings.ToLower(dns.MatchPattern), ".")
			for strings.Contains(dns.MatchPattern, "***") {
				dns.MatchPattern = strings.ReplaceAll(dns.MatchPattern, "***", "**")
			}
		}
	}

	for j := range rule.ToCIDR {
		rule.ToCIDR[j] = normalizeCIDR(rule.ToCIDR[j])
	}

	for j := range rule.ToCIDRSet {
		rule.ToCIDRSet[j].CIDR = normalizeCIDRStrict(rule.ToCIDRSet[j].CIDR)
		for k := range rule.ToCIDRSet[j].Except {
			rule.ToCIDRSet[j].Except[k] = normalizeCIDRStrict(rule.ToCIDRSet[j].Except[k])
		}
	}

	normalizeICMPRules(rule.ICMPs)

	return nil
}

// normalizeEgressDenyRule mutates an egress deny rule in place to
// normalize service name port case and CIDR notation.
func normalizeEgressDenyRule(c *Config, i int) {
	rule := &(*c.EgressDeny)[i]

	for j := range rule.ToPorts {
		for k := range rule.ToPorts[j].Ports {
			if isSvcName(rule.ToPorts[j].Ports[k].Port) {
				rule.ToPorts[j].Ports[k].Port = strings.ToLower(rule.ToPorts[j].Ports[k].Port)
			}
		}
	}

	for j := range rule.ToCIDR {
		rule.ToCIDR[j] = normalizeCIDR(rule.ToCIDR[j])
	}

	for j := range rule.ToCIDRSet {
		rule.ToCIDRSet[j].CIDR = normalizeCIDRStrict(rule.ToCIDRSet[j].CIDR)
		for k := range rule.ToCIDRSet[j].Except {
			rule.ToCIDRSet[j].Except[k] = normalizeCIDRStrict(rule.ToCIDRSet[j].Except[k])
		}
	}

	normalizeICMPRules(rule.ICMPs)
}

// normalizeICMPRules normalizes ICMP rule fields in place: empty
// family defaults to [FamilyIPv4], and CamelCase type names are
// resolved to numeric strings for downstream consistency.
func normalizeICMPRules(icmps []ICMPRule) {
	for i := range icmps {
		for j := range icmps[i].Fields {
			f := &icmps[i].Fields[j]

			normalized, err := normalizeICMPFamily(f.Family)
			if err == nil {
				f.Family = normalized
			}

			code, err := resolveICMPType(f.Family, f.Type)
			if err == nil {
				f.Type = strconv.FormatUint(uint64(code), 10)
			}
		}
	}
}

// normalizeCIDR returns s in CIDR notation. If s is already a valid
// CIDR prefix it is returned as-is. If s is a bare IP address, the
// appropriate full-length prefix is appended (/32 for IPv4, /128 for
// IPv6). If s is neither, it is returned unchanged so that downstream
// validation can produce the appropriate error.
func normalizeCIDR(s string) string {
	_, network, err := net.ParseCIDR(s)
	if err == nil {
		return network.String()
	}

	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}

	// Use string-based detection to match classifyCIDR's approach.
	// This avoids To4() returning non-nil for IPv4-mapped IPv6
	// addresses like "::ffff:10.0.0.1", which should get /128.
	if strings.Contains(s, ":") {
		return s + "/128"
	}

	return s + "/32"
}

// normalizeCIDRStrict normalizes valid CIDR prefixes by masking host
// bits, but returns bare IP addresses unchanged. This allows downstream
// validation to reject bare IPs in contexts that require CIDR notation
// (e.g. toCIDRSet), matching Cilium's CIDRRule.sanitize() behavior.
func normalizeCIDRStrict(s string) string {
	_, network, err := net.ParseCIDR(s)
	if err == nil {
		return network.String()
	}

	return s
}

// cidrIsIPv6 reports whether a CIDR string represents an IPv6 address,
// using string-based detection (presence of ":") to match classifyCIDR.
func cidrIsIPv6(s string) bool {
	return strings.Contains(s, ":")
}
