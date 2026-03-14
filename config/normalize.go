package config

import (
	"net"
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

	for j := range rule.ToFQDNs {
		fqdn := &rule.ToFQDNs[j]
		fqdn.MatchName = strings.TrimRight(strings.ToLower(fqdn.MatchName), ".")

		fqdn.MatchPattern = strings.TrimRight(strings.ToLower(fqdn.MatchPattern), ".")
		for strings.Contains(fqdn.MatchPattern, "***") {
			fqdn.MatchPattern = strings.ReplaceAll(fqdn.MatchPattern, "***", "**")
		}
	}

	for j := range rule.ToCIDR {
		rule.ToCIDR[j] = normalizeCIDR(rule.ToCIDR[j])
	}
}

// normalizeCIDR returns s in CIDR notation. If s is already a valid
// CIDR prefix it is returned as-is. If s is a bare IP address, the
// appropriate full-length prefix is appended (/32 for IPv4, /128 for
// IPv6). If s is neither, it is returned unchanged so that downstream
// validation can produce the appropriate error.
func normalizeCIDR(s string) string {
	_, _, err := net.ParseCIDR(s)
	if err == nil {
		return s
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

// isIPv4MappedIPv6 reports whether s is an IPv4-mapped IPv6 CIDR or
// address (e.g. "::ffff:10.0.0.0/104" or "::ffff:10.0.0.1"). These
// addresses contain a colon (so string-based detection classifies them
// as IPv6) but [net.ParseCIDR] normalizes them to IPv4, creating a
// family mismatch that causes silent misclassification.
func isIPv4MappedIPv6(s string) bool {
	if !strings.Contains(s, ":") {
		return false
	}

	// Strip the CIDR prefix length if present.
	host, _, _ := strings.Cut(s, "/")

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	// ip.To4() returns non-nil for IPv4-mapped IPv6 addresses, but
	// we only want to flag addresses that also contain ":" in the
	// original string (pure IPv4 like "10.0.0.1" also has To4() != nil).
	return ip.To4() != nil
}

// cidrIsIPv6 reports whether a CIDR string represents an IPv6 address,
// using string-based detection (presence of ":") to match classifyCIDR.
func cidrIsIPv6(s string) bool {
	return strings.Contains(s, ":")
}
