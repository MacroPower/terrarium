package envoy

import (
	"regexp"
	"strings"
)

// labelCharClass is the character class for a single DNS label,
// matching Cilium's [-a-zA-Z0-9_] set.
const labelCharClass = `[-a-zA-Z0-9_]`

// WildcardToSNIRegex converts a Cilium-style wildcard pattern into a
// regex for RBAC SNI matching. It supports wildcards in any position:
//
//   - "*." prefix (single-label): matches exactly one DNS label.
//     Example: "*.example.com" -> "^[-a-zA-Z0-9_]+\.example\.com$"
//
//   - "**." prefix (multi-label): matches one or more DNS labels at
//     arbitrary depth, mirroring Cilium's [dnsWildcardREGroup].
//     Example: "**.example.com" ->
//     "^[-a-zA-Z0-9_]+(\.[-a-zA-Z0-9_]+)*\.example\.com$"
//
//   - Arbitrary position wildcards: each "*" within a label matches
//     zero or more label characters (matching Cilium's semantics).
//     Example: "*.ci*.io" -> "^[-a-zA-Z0-9_]+\.ci[-a-zA-Z0-9_]*\.io$"
//
// Whole-label wildcards use + (one-or-more) because empty DNS labels
// are invalid in SNI (RFC 6066 section 3). Intra-label wildcards use
// * (zero-or-more) because e.g. "ci*" should match "ci".
//
// SNI values never contain trailing dots (RFC 6066 section 3), so this
// uses literal \. separators and omits the trailing dot anchor.
//
// [dnsWildcardREGroup]: Cilium pkg/fqdn/matchpattern constants.
func WildcardToSNIRegex(pattern string) string {
	return WildcardToRegex(pattern, "")
}

// WildcardToHostRegex converts a wildcard pattern into a regex for HTTP
// Host/:authority header matching. Like [WildcardToSNIRegex] but also
// accepts an optional ":port" suffix, since HTTP/1.1 Host and HTTP/2
// :authority headers may include a port (e.g. "sub.example.com:80").
//
// Example: "*.example.com" -> "^[-a-zA-Z0-9_]+\.example\.com(:\d+)?$"
func WildcardToHostRegex(pattern string) string {
	return WildcardToRegex(pattern, `(:\d+)?`)
}

// WildcardToRegex is the shared core for [WildcardToSNIRegex] and
// [WildcardToHostRegex]. The beforeAnchor string (e.g. `(:\d+)?`) is
// inserted before the trailing `$` anchor.
func WildcardToRegex(pattern, beforeAnchor string) string {
	// Handle "**." prefix specially: one or more dot-separated labels.
	if strings.HasPrefix(pattern, "**.") {
		suffix := pattern[3:]
		suffixRegex := convertSuffix(suffix)

		return `^` + labelCharClass + `+(\.` + labelCharClass + `+)*\.` + suffixRegex + beforeAnchor + `$`
	}

	// General approach: QuoteMeta the pattern, then replace escaped
	// stars back to regex wildcards with appropriate quantifiers.
	escaped := regexp.QuoteMeta(pattern)

	// Split on dots (escaped as \.) to process per-label.
	labels := strings.Split(escaped, `\.`)
	for i, label := range labels {
		if !strings.Contains(label, `\*`) {
			continue
		}

		// A label that is just "\*" is a whole-label wildcard.
		if label == `\*` {
			labels[i] = labelCharClass + `+`
		} else {
			// Intra-label wildcard: zero-or-more for partial matches.
			labels[i] = strings.ReplaceAll(label, `\*`, labelCharClass+`*`)
		}
	}

	return `^` + strings.Join(labels, `\.`) + beforeAnchor + `$`
}

// convertSuffix converts a suffix (after stripping "**.") to regex,
// handling any wildcards in the suffix itself.
func convertSuffix(suffix string) string {
	escaped := regexp.QuoteMeta(suffix)
	labels := strings.Split(escaped, `\.`)

	for i, label := range labels {
		if !strings.Contains(label, `\*`) {
			continue
		}

		if label == `\*` {
			labels[i] = labelCharClass + `+`
		} else {
			labels[i] = strings.ReplaceAll(label, `\*`, labelCharClass+`*`)
		}
	}

	return strings.Join(labels, `\.`)
}

// WildcardServerName converts a domain pattern to an Envoy server_names
// entry. For patterns with only a leading wildcard prefix ("*.suffix"
// or "**.suffix" where suffix is wildcard-free), the "**." is
// normalized to "*.". For patterns with non-leading wildcards, the
// longest wildcard-free suffix is extracted and prepended with "*.":
//
//   - "api.*.example.com" -> "*.example.com"
//   - "*.ci*.io" -> "*.io"
//   - "*.*.cilium.io" -> "*.cilium.io"
//
// The RBAC filter (via [WildcardToSNIRegex]) provides the correct
// pattern-level restriction; server_names is intentionally broad for
// Envoy's suffix-based filter chain matching.
func WildcardServerName(domain string) string {
	if strings.HasPrefix(domain, "**.") {
		suffix := domain[3:]
		if !strings.Contains(suffix, "*") {
			return "*." + suffix
		}

		return "*." + longestWildcardFreeSuffix(suffix)
	}

	if strings.HasPrefix(domain, "*.") {
		suffix := domain[2:]
		if !strings.Contains(suffix, "*") {
			return domain
		}

		return "*." + longestWildcardFreeSuffix(suffix)
	}

	// Bare wildcards ("*", "**") pass through as-is; they are
	// handled specially by the caller (converted to open/catch-all).
	if !strings.Contains(domain, ".") {
		return domain
	}

	// Non-leading wildcard without a prefix (e.g. "api.*.example.com").
	if strings.Contains(domain, "*") {
		return "*." + longestWildcardFreeSuffix(domain)
	}

	return domain
}

// longestWildcardFreeSuffix returns the longest right-aligned run of
// wildcard-free labels from a dot-separated string.
func longestWildcardFreeSuffix(s string) string {
	labels := strings.Split(s, ".")

	// Walk right-to-left to find the longest wildcard-free suffix.
	start := len(labels)
	for i := len(labels) - 1; i >= 0; i-- {
		if strings.Contains(labels[i], "*") {
			break
		}

		start = i
	}

	if start >= len(labels) {
		// All labels contain wildcards; return the last label as
		// a fallback (shouldn't happen with valid patterns).
		return labels[len(labels)-1]
	}

	return strings.Join(labels[start:], ".")
}

// IsWildcardDomain reports whether d contains any wildcard characters.
func IsWildcardDomain(d string) bool {
	return strings.Contains(d, "*")
}
