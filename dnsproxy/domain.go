package dnsproxy

import (
	"sort"
	"strings"

	"go.jacobcolvin.com/terrarium/config"
)

// Domain is an allowed domain entry for DNS filtering. Wildcard
// entries (from matchPattern "*.example.com" or "**.example.com")
// match subdomains only; exact entries match the domain itself and
// all subdomains.
type Domain struct {
	// Name is the domain without any wildcard prefix.
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
// dot) matches this domain entry. Non-wildcard entries match the
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

	return q == d.Name
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
				// Detect multi-level ("**.") before stripping.
				multiLevel := strings.HasPrefix(fqdn.MatchPattern, "**.")

				// Strip all leading "*" characters then the
				// following "." to extract the base domain.
				stripped := strings.TrimLeft(fqdn.MatchPattern, "*")
				stripped = strings.TrimPrefix(stripped, ".")
				if stripped == "" {
					// Bare wildcard "*", "**", etc.: pass
					// through for catch-all handling.
					if !seen["*"] {
						seen["*"] = true

						result = append(result, Domain{Name: "*"})
					}

					continue
				}

				d = Domain{Name: stripped, Wildcard: true, MultiLevel: multiLevel}
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
				var d Domain

				if dns.MatchName != "" {
					d = Domain{Name: dns.MatchName}
				} else {
					multiLevel := strings.HasPrefix(dns.MatchPattern, "**.")

					stripped := strings.TrimLeft(dns.MatchPattern, "*")
					stripped = strings.TrimPrefix(stripped, ".")
					if stripped == "" {
						if !seen["*"] {
							seen["*"] = true

							result = append(result, Domain{Name: "*"})
						}

						continue
					}

					d = Domain{Name: stripped, Wildcard: true, MultiLevel: multiLevel}
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

	return collectTCPForwardHosts(cfg, result, seen)
}

// upgradeDomain adjusts an existing entry in result when the same
// domain is encountered again with different wildcard properties.
func upgradeDomain(result []Domain, d Domain) {
	for i := range result {
		if result[i].Name != d.Name {
			continue
		}

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
