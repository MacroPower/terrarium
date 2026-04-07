package dnsproxy

import (
	"regexp"
	"sort"
	"strings"

	"go.jacobcolvin.com/terrarium/config"
)

// Domain is an allowed domain entry for DNS filtering. Wildcard
// entries (from matchPattern "*.example.com" or "**.example.com")
// match subdomains only; exact entries match the domain itself and
// all subdomains.
type Domain struct {
	// Regex is a compiled pattern for partial wildcard matching
	// (e.g. "api.*.example.com", "*.ci*.io"). When set, [Matches]
	// uses this regex instead of suffix-based logic. The regex
	// matches lowercase non-FQDN form (no trailing dot).
	Regex *regexp.Regexp
	// Name is the domain without any wildcard prefix. For partial
	// wildcard patterns, this is the longest wildcard-free suffix
	// (used for DNS forwarding breadth).
	Name string
	// Wildcard is true when the entry originated from a matchPattern
	// with a leading wildcard prefix ("*." or "**."), restricting
	// matches to subdomains only (excluding the bare parent domain).
	Wildcard bool
	// MultiLevel is true for "**." patterns, allowing matches at
	// arbitrary subdomain depth. When false (single-star "*."
	// pattern), only one label before the suffix is allowed. This
	// mirrors Cilium's depth restriction for single-star wildcards.
	MultiLevel bool
}

// Matches reports whether qname (in FQDN wire format with trailing
// dot) matches this domain entry. When Regex is set, the compiled
// pattern is used directly. Otherwise, non-wildcard entries match the
// domain and all subdomains (like dnsmasq /domain/). Wildcard entries
// match subdomains only, not the bare parent (like dnsmasq /*.domain/).
// The leading-dot check prevents false positives (notexample.com vs
// example.com).
func (d Domain) Matches(qname string) bool {
	q := strings.TrimSuffix(qname, ".")
	if q == "" {
		return false
	}

	q = strings.ToLower(q)

	if d.Regex != nil {
		return d.Regex.MatchString(q)
	}

	if d.Wildcard {
		suffix := "." + d.Name
		if !strings.HasSuffix(q, suffix) {
			return false
		}

		if !d.MultiLevel {
			// Single-star: exactly one label before the suffix.
			prefix := q[:len(q)-len(suffix)]

			return !strings.Contains(prefix, ".")
		}

		return true
	}

	return q == d.Name || strings.HasSuffix(q, "."+d.Name)
}

// CollectDomains returns a sorted, deduplicated list of domains
// that should be forwarded in restricted mode. Includes FQDN domains
// (preserving wildcard vs exact distinction for correct filtering)
// and [TCPForward] hosts. The bare wildcard "*" pattern is included
// as-is for the caller to handle.
func CollectDomains(cfg *config.Config) []Domain {
	seen := make(map[string]bool)

	var result []Domain

	eRules := cfg.EgressRules()
	for ri := range eRules {
		for _, fqdn := range eRules[ri].ToFQDNs {
			var d Domain

			if fqdn.MatchName != "" {
				d = Domain{Name: fqdn.MatchName}
			} else {
				d = patternToDomain(fqdn.MatchPattern)
			}

			if d.Name == "*" {
				if !seen["*"] {
					seen["*"] = true

					result = append(result, Domain{Name: "*"})
				}

				continue
			}

			if seen[d.Name] {
				upgradeDomain(result, d)

				continue
			}

			seen[d.Name] = true
			result = append(result, d)
		}
	}

	// Collect DNS L7 rule domains from port-53 toPorts entries.
	for ri := range eRules {
		for _, pr := range eRules[ri].ToPorts {
			if pr.Rules == nil || len(pr.Rules.DNS) == 0 {
				continue
			}

			for _, dns := range pr.Rules.DNS {
				// Collect domains for each field independently.
				// When both are set they are evaluated with OR
				// semantics, matching Cilium's behavior.
				var domains []Domain

				if dns.MatchName != "" {
					domains = append(domains, Domain{Name: dns.MatchName})
				}

				if dns.MatchPattern != "" {
					domains = append(domains, patternToDomain(dns.MatchPattern))
				}

				for _, d := range domains {
					if d.Name == "*" {
						if !seen["*"] {
							seen["*"] = true

							result = append(result, Domain{Name: "*"})
						}

						continue
					}

					if seen[d.Name] {
						upgradeDomain(result, d)

						continue
					}

					seen[d.Name] = true
					result = append(result, d)
				}
			}
		}
	}

	return collectTCPForwardHosts(cfg, result, seen)
}

// patternToDomain converts a matchPattern into a [Domain]. For simple
// leading wildcard patterns ("*.suffix", "**.suffix"), the suffix is
// extracted directly. For patterns with non-leading wildcards (e.g.
// "api.*.example.com", "*.ci*.io"), a regex is compiled and the
// longest wildcard-free suffix is used as Name for DNS forwarding
// breadth. The intentionally broad forwarding is acceptable because
// [Matches] (regex) and the Envoy/nftables layers enforce the actual
// security restriction.
func patternToDomain(pattern string) Domain {
	// Detect multi-level ("**.") before stripping.
	multiLevel := strings.HasPrefix(pattern, "**.")

	// Strip all leading "*" characters then the following "." to
	// extract the base domain.
	stripped := strings.TrimLeft(pattern, "*")
	stripped = strings.TrimPrefix(stripped, ".")

	if stripped == "" {
		// Bare wildcard "*", "**", etc.
		return Domain{Name: "*"}
	}

	// Check if the stripped suffix still contains wildcards. If so,
	// this is a partial wildcard pattern that needs regex matching.
	if strings.Contains(stripped, "*") {
		// Build a regex matching the full pattern (lowercase,
		// non-FQDN form, no trailing dot).
		re := CompileMatchRegex(pattern)

		// Extract the longest wildcard-free suffix for DNS
		// forwarding. This is intentionally broad.
		suffix := longestWildcardFreeSuffix(pattern)

		return Domain{
			Name:       suffix,
			Wildcard:   true,
			MultiLevel: true,
			Regex:      re,
		}
	}

	return Domain{Name: stripped, Wildcard: true, MultiLevel: multiLevel}
}

// CompileMatchRegex compiles a matchPattern into a regex that
// matches lowercase non-FQDN domain names (no trailing dot). Each
// "*" matches zero or more label characters ([-a-zA-Z0-9_]), and
// "." is a literal dot separator. Exported for testing.
func CompileMatchRegex(pattern string) *regexp.Regexp {
	// Handle "**." prefix: one or more dot-separated labels.
	if strings.HasPrefix(pattern, "**.") {
		rest := pattern[3:]
		suffixRe := strings.ReplaceAll(regexp.QuoteMeta(rest), `\*`, `[-a-zA-Z0-9_]*`)

		return regexp.MustCompile(`^[-a-zA-Z0-9_]+(\.[-a-zA-Z0-9_]+)*\.` + suffixRe + `$`)
	}

	// General: escape then replace stars. QuoteMeta escapes "*" to
	// "\*" and "." to "\." which is already valid regex for literal
	// dots, so only the star replacement is needed.
	re := strings.ReplaceAll(regexp.QuoteMeta(pattern), `\*`, `[-a-zA-Z0-9_]*`)

	return regexp.MustCompile(`^` + re + `$`)
}

// longestWildcardFreeSuffix returns the longest right-aligned run of
// dot-separated labels that contain no wildcards.
func longestWildcardFreeSuffix(s string) string {
	labels := strings.Split(s, ".")
	start := len(labels)

	for i := len(labels) - 1; i >= 0; i-- {
		if strings.Contains(labels[i], "*") {
			break
		}

		start = i
	}

	if start >= len(labels) {
		return labels[len(labels)-1]
	}

	return strings.Join(labels[start:], ".")
}

// upgradeDomain adjusts an existing entry in result when the same
// domain is encountered again with different wildcard properties.
func upgradeDomain(result []Domain, d Domain) {
	for i := range result {
		if result[i].Name != d.Name {
			continue
		}

		// Wildcard after exact is a no-op: exact entries already
		// match all subdomains, so the wildcard adds nothing.

		// Exact matchName upgrades a wildcard entry so the bare
		// domain also resolves.
		if !d.Wildcard && result[i].Wildcard {
			result[i].Wildcard = false
		}

		// Multi-level wildcard upgrades single-level (superset).
		if d.Wildcard && d.MultiLevel && !result[i].MultiLevel {
			result[i].MultiLevel = true
		}

		return
	}
}

// collectTCPForwardHosts adds TCPForward hosts to the domain list.
func collectTCPForwardHosts(cfg *config.Config, result []Domain, seen map[string]bool) []Domain {
	for _, host := range cfg.TCPForwardHosts() {
		if seen[host] {
			// TCPForward hosts need the bare domain to resolve.
			// If a wildcard FQDN entry exists for the same
			// domain, upgrade to non-wildcard so both the bare
			// domain and subdomains resolve.
			for i := range result {
				if result[i].Name == host && result[i].Wildcard {
					result[i].Wildcard = false
					break
				}
			}

			continue
		}

		seen[host] = true
		result = append(result, Domain{Name: host})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result
}
