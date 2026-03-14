package envoy

import (
	"regexp"
	"strings"
)

// wildcardToSNIRegex converts a Cilium-style wildcard pattern into a
// regex for RBAC SNI matching. It handles two forms:
//
//   - "*." prefix (single-label): matches exactly one DNS label.
//     Example: "*.example.com" -> "^[-a-zA-Z0-9_]+\.example\.com$"
//     matches:  "sub.example.com"
//     rejects:  "a.b.example.com"
//
//   - "**." prefix (multi-label): matches one or more DNS labels at
//     arbitrary depth, mirroring Cilium's [dnsWildcardREGroup].
//     Example: "**.example.com" ->
//     "^[-a-zA-Z0-9_]+(\.[-a-zA-Z0-9_]+)*\.example\.com$"
//     matches:  "sub.example.com", "a.b.example.com"
//     rejects:  "example.com"
//
// Both forms use + (one-or-more) on the first label's character class,
// not * (zero-or-more), because empty DNS labels are invalid in SNI
// (RFC 6066 section 3). This is an intentional terrarium strictness:
// Cilium's single-label regex uses * (allowing empty labels like
// ".example.com"), but since SNI values in practice never have empty
// labels, the + quantifier is both correct and more precise.
//
// SNI values never contain trailing dots (RFC 6066 section 3), so unlike
// Cilium's regex (which uses [.] for FQDN-form names), this uses literal
// \. separators and omits the trailing dot anchor.
//
// [dnsWildcardREGroup]: Cilium pkg/fqdn/matchpattern constants.
func wildcardToSNIRegex(pattern string) string {
	if strings.HasPrefix(pattern, "**.") {
		suffix := pattern[3:]
		// One or more dot-separated labels, then the fixed suffix.
		return `^[-a-zA-Z0-9_]+(\.[-a-zA-Z0-9_]+)*\.` + regexp.QuoteMeta(suffix) + `$`
	}

	suffix := strings.TrimPrefix(pattern, "*.")

	return `^[-a-zA-Z0-9_]+\.` + regexp.QuoteMeta(suffix) + `$`
}

// wildcardToHostRegex converts a wildcard pattern into a regex for HTTP
// Host/:authority header matching. Like [wildcardToSNIRegex] but also
// accepts an optional ":port" suffix, since HTTP/1.1 Host and HTTP/2
// :authority headers may include a port (e.g. "sub.example.com:80").
//
// The quantifier is "+" (one or more) rather than Cilium's "*" (zero or
// more) because an empty DNS label is not a valid hostname and cannot
// appear in an HTTP Host header.
//
// Example: "*.example.com" -> "^[-a-zA-Z0-9_]+\.example\.com(:\d+)?$"
//
//	matches:  "sub.example.com", "sub.example.com:80"
//	rejects:  "a.b.example.com", "a.b.example.com:80"
func wildcardToHostRegex(pattern string) string {
	if strings.HasPrefix(pattern, "**.") {
		suffix := pattern[3:]
		return `^[-a-zA-Z0-9_]+(\.[-a-zA-Z0-9_]+)*\.` + regexp.QuoteMeta(suffix) + `(:\d+)?$`
	}

	suffix := strings.TrimPrefix(pattern, "*.")

	return `^[-a-zA-Z0-9_]+\.` + regexp.QuoteMeta(suffix) + `(:\d+)?$`
}

// wildcardServerName converts a domain pattern to an Envoy server_names
// entry. Both "*.example.com" and "**.example.com" use "*.example.com"
// in server_names because Envoy's suffix matching is inherently
// multi-label. The RBAC filter (via [wildcardToSNIRegex]) provides the
// correct depth restriction.
func wildcardServerName(domain string) string {
	if strings.HasPrefix(domain, "**.") {
		return "*." + domain[3:]
	}

	return domain
}
