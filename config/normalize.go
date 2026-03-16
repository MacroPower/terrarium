package config

import (
	"net"
	"strconv"
	"strings"
)

// normalizeEgressRule mutates an egress rule in place to normalize
// protocol case, FQDN case, and trailing dots. Must be called before
// validation so that normalized values pass the validators.
func normalizeEgressRule(c *Config, i int) {
	rule := &(*c.Egress)[i]

	for j := range rule.ToPorts {
		for k := range rule.ToPorts[j].Ports {
			rule.ToPorts[j].Ports[k].Protocol = strings.ToUpper(rule.ToPorts[j].Ports[k].Protocol)
			if isSvcName(rule.ToPorts[j].Ports[k].Port) {
				rule.ToPorts[j].Ports[k].Port = strings.ToLower(rule.ToPorts[j].Ports[k].Port)
			}
		}
	}

	for j := range rule.ToPorts {
		for k := range rule.ToPorts[j].ServerNames {
			rule.ToPorts[j].ServerNames[k] = strings.TrimRight(
				strings.ToLower(rule.ToPorts[j].ServerNames[k]), ".")
			for strings.Contains(rule.ToPorts[j].ServerNames[k], "***") {
				rule.ToPorts[j].ServerNames[k] = strings.ReplaceAll(
					rule.ToPorts[j].ServerNames[k], "***", "**")
			}
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
		rule.ToCIDRSet[j].CIDR = normalizeCIDR(rule.ToCIDRSet[j].CIDR)
		for k := range rule.ToCIDRSet[j].Except {
			rule.ToCIDRSet[j].Except[k] = normalizeCIDR(rule.ToCIDRSet[j].Except[k])
		}
	}

	normalizeICMPRules(rule.ICMPs)
}

// normalizeEgressDenyRule mutates an egress deny rule in place to
// normalize protocol case and CIDR notation.
func normalizeEgressDenyRule(c *Config, i int) {
	rule := &(*c.EgressDeny)[i]

	for j := range rule.ToPorts {
		for k := range rule.ToPorts[j].Ports {
			rule.ToPorts[j].Ports[k].Protocol = strings.ToUpper(rule.ToPorts[j].Ports[k].Protocol)
			if isSvcName(rule.ToPorts[j].Ports[k].Port) {
				rule.ToPorts[j].Ports[k].Port = strings.ToLower(rule.ToPorts[j].Ports[k].Port)
			}
		}
	}

	for j := range rule.ToCIDR {
		rule.ToCIDR[j] = normalizeCIDR(rule.ToCIDR[j])
	}

	for j := range rule.ToCIDRSet {
		rule.ToCIDRSet[j].CIDR = normalizeCIDR(rule.ToCIDRSet[j].CIDR)
		for k := range rule.ToCIDRSet[j].Except {
			rule.ToCIDRSet[j].Except[k] = normalizeCIDR(rule.ToCIDRSet[j].Except[k])
		}
	}

	normalizeICMPRules(rule.ICMPs)
}

// normalizeICMPRules normalizes ICMP rule fields in place: family
// is case-normalized to "IPv4"/"IPv6", and CamelCase type names are
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

// cidrIsIPv6 reports whether a CIDR string represents an IPv6 address,
// using string-based detection (presence of ":") to match classifyCIDR.
func cidrIsIPv6(s string) bool {
	return strings.Contains(s, ":")
}
