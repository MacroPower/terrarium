package dnsproxy_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/dnsproxy"
)

func TestDomainMatches(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		domain dnsproxy.Domain
		qname  string
		want   bool
	}{
		"non-wildcard exact match": {
			domain: dnsproxy.Domain{Name: "example.com"},
			qname:  "example.com.",
			want:   true,
		},
		"non-wildcard subdomain": {
			domain: dnsproxy.Domain{Name: "example.com"},
			qname:  "sub.example.com.",
			want:   false,
		},
		"non-wildcard deep subdomain": {
			domain: dnsproxy.Domain{Name: "example.com"},
			qname:  "a.b.c.example.com.",
			want:   false,
		},
		"non-wildcard suffix trap": {
			domain: dnsproxy.Domain{Name: "example.com"},
			qname:  "notexample.com.",
			want:   false,
		},
		"non-wildcard unrelated domain": {
			domain: dnsproxy.Domain{Name: "example.com"},
			qname:  "other.org.",
			want:   false,
		},
		"wildcard subdomain match": {
			domain: dnsproxy.Domain{Name: "example.com", Wildcard: true},
			qname:  "sub.example.com.",
			want:   true,
		},
		"wildcard rejects deep subdomain": {
			domain: dnsproxy.Domain{Name: "example.com", Wildcard: true},
			qname:  "a.b.example.com.",
			want:   false,
		},
		"multi-level wildcard deep subdomain": {
			domain: dnsproxy.Domain{Name: "example.com", Wildcard: true, MultiLevel: true},
			qname:  "a.b.example.com.",
			want:   true,
		},
		"multi-level wildcard single subdomain": {
			domain: dnsproxy.Domain{Name: "example.com", Wildcard: true, MultiLevel: true},
			qname:  "sub.example.com.",
			want:   true,
		},
		"multi-level wildcard rejects bare parent": {
			domain: dnsproxy.Domain{Name: "example.com", Wildcard: true, MultiLevel: true},
			qname:  "example.com.",
			want:   false,
		},
		"wildcard rejects bare parent": {
			domain: dnsproxy.Domain{Name: "example.com", Wildcard: true},
			qname:  "example.com.",
			want:   false,
		},
		"wildcard suffix trap": {
			domain: dnsproxy.Domain{Name: "example.com", Wildcard: true},
			qname:  "notexample.com.",
			want:   false,
		},
		"empty qname": {
			domain: dnsproxy.Domain{Name: "example.com"},
			qname:  "",
			want:   false,
		},
		"root dot only": {
			domain: dnsproxy.Domain{Name: "example.com"},
			qname:  ".",
			want:   false,
		},
		"case insensitive": {
			domain: dnsproxy.Domain{Name: "example.com"},
			qname:  "EXAMPLE.COM.",
			want:   true,
		},
		"regex partial wildcard match": {
			domain: dnsproxy.Domain{
				Name:       "example.com",
				Wildcard:   true,
				MultiLevel: true,
				Regex:      dnsproxy.CompileMatchRegex("api.*.example.com"),
			},
			qname: "api.foo.example.com.",
			want:  true,
		},
		"regex partial wildcard rejects deep": {
			domain: dnsproxy.Domain{
				Name:       "example.com",
				Wildcard:   true,
				MultiLevel: true,
				Regex:      dnsproxy.CompileMatchRegex("api.*.example.com"),
			},
			qname: "api.foo.bar.example.com.",
			want:  false,
		},
		"regex partial wildcard rejects wrong prefix": {
			domain: dnsproxy.Domain{
				Name:       "example.com",
				Wildcard:   true,
				MultiLevel: true,
				Regex:      dnsproxy.CompileMatchRegex("api.*.example.com"),
			},
			qname: "notapi.foo.example.com.",
			want:  false,
		},
		"regex intra-label wildcard": {
			domain: dnsproxy.Domain{
				Name:       "io",
				Wildcard:   true,
				MultiLevel: true,
				Regex:      dnsproxy.CompileMatchRegex("*.ci*.io"),
			},
			qname: "sub.cilium.io.",
			want:  true,
		},
		"regex intra-label wildcard rejects bare": {
			domain: dnsproxy.Domain{
				Name:       "io",
				Wildcard:   true,
				MultiLevel: true,
				Regex:      dnsproxy.CompileMatchRegex("*.ci*.io"),
			},
			qname: "cilium.io.",
			want:  false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, tt.domain.Matches(tt.qname))
		})
	}
}

func TestCollectDomains(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  config.Config
		want []dnsproxy.Domain
	}{
		"matchName produces non-wildcard": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "github.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			want: []dnsproxy.Domain{{Name: "github.com"}},
		},
		"matchPattern produces wildcard": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			want: []dnsproxy.Domain{{Name: "example.com", Wildcard: true}},
		},
		"double-star produces multi-level wildcard": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "**.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			want: []dnsproxy.Domain{{Name: "example.com", Wildcard: true, MultiLevel: true}},
		},
		"multi-level upgrades single-level for same domain": {
			cfg: config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchPattern: "**.example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			want: []dnsproxy.Domain{{Name: "example.com", Wildcard: true, MultiLevel: true}},
		},
		"bare wildcard passthrough": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			want: []dnsproxy.Domain{{Name: "*"}},
		},
		"matchName upgrades wildcard for same domain": {
			cfg: config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			want: []dnsproxy.Domain{{Name: "example.com"}},
		},
		"TCPForward host upgrade": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
				TCPForwards: []config.TCPForward{{Port: 22, Host: "example.com"}},
			},
			want: []dnsproxy.Domain{{Name: "example.com"}},
		},
		"TCPForward adds new host": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "github.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
				TCPForwards: []config.TCPForward{{Port: 22, Host: "git.example.com"}},
			},
			want: []dnsproxy.Domain{
				{Name: "git.example.com"},
				{Name: "github.com"},
			},
		},
		"dedup same matchName": {
			cfg: config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}}}},
					},
				),
			},
			want: []dnsproxy.Domain{{Name: "example.com"}},
		},
		"sorted output": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{
						{MatchName: "z.example.com"},
						{MatchName: "a.example.com"},
					},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			want: []dnsproxy.Domain{
				{Name: "a.example.com"},
				{Name: "z.example.com"},
			},
		},
		"DNS rule matchName contributes to domains": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []config.PortRule{
						{Ports: []config.Port{{Port: "443"}}},
						{
							Ports: []config.Port{{Port: "53"}},
							Rules: &config.L7Rules{DNS: []config.DNSRule{
								{MatchName: "api.example.com"},
							}},
						},
					},
				}),
			},
			want: []dnsproxy.Domain{
				{Name: "api.example.com"},
				{Name: "dns.example.com"},
			},
		},
		"DNS rule matchPattern contributes wildcard domain": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []config.PortRule{
						{Ports: []config.Port{{Port: "443"}}},
						{
							Ports: []config.Port{{Port: "53"}},
							Rules: &config.L7Rules{DNS: []config.DNSRule{
								{MatchPattern: "*.example.com"},
							}},
						},
					},
				}),
			},
			want: []dnsproxy.Domain{
				{Name: "dns.example.com"},
				{Name: "example.com", Wildcard: true},
			},
		},
		"DNS rule double-star pattern contributes multi-level wildcard": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []config.PortRule{
						{Ports: []config.Port{{Port: "443"}}},
						{
							Ports: []config.Port{{Port: "53"}},
							Rules: &config.L7Rules{DNS: []config.DNSRule{
								{MatchPattern: "**.example.com"},
							}},
						},
					},
				}),
			},
			want: []dnsproxy.Domain{
				{Name: "dns.example.com"},
				{Name: "example.com", Wildcard: true, MultiLevel: true},
			},
		},
		"DNS rule deduplicates with toFQDNs domain": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{
						{Ports: []config.Port{{Port: "443"}}},
						{
							Ports: []config.Port{{Port: "53"}},
							Rules: &config.L7Rules{DNS: []config.DNSRule{
								{MatchName: "example.com"},
							}},
						},
					},
				}),
			},
			want: []dnsproxy.Domain{
				{Name: "example.com"},
			},
		},
		"DNS rule bare wildcard passthrough": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []config.PortRule{
						{Ports: []config.Port{{Port: "443"}}},
						{
							Ports: []config.Port{{Port: "53"}},
							Rules: &config.L7Rules{DNS: []config.DNSRule{
								{MatchPattern: "*"},
							}},
						},
					},
				}),
			},
			want: []dnsproxy.Domain{
				{Name: "*"},
				{Name: "dns.example.com"},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := dnsproxy.CollectDomains(&tt.cfg)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCollectDomainsPartialWildcard(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchPattern: "api.*.example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
		}),
	}

	got := dnsproxy.CollectDomains(&cfg)
	require.Len(t, got, 1)
	assert.Equal(t, "example.com", got[0].Name)
	assert.True(t, got[0].Wildcard)
	assert.True(t, got[0].MultiLevel)
	assert.NotNil(t, got[0].Regex)
	assert.True(t, got[0].Matches("api.foo.example.com."))
	assert.False(t, got[0].Matches("api.foo.bar.example.com."))
	assert.False(t, got[0].Matches("notapi.foo.example.com."))
}

func TestCollectDomainsIntraLabelWildcard(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.ci*.io"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
		}),
	}

	got := dnsproxy.CollectDomains(&cfg)
	require.Len(t, got, 1)
	assert.Equal(t, "io", got[0].Name)
	assert.True(t, got[0].Wildcard)
	assert.NotNil(t, got[0].Regex)
	assert.True(t, got[0].Matches("sub.cilium.io."))
	assert.True(t, got[0].Matches("sub.ci.io."))
	assert.False(t, got[0].Matches("cilium.io."))
}

func TestMatchFQDNPatterns(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{
					{MatchName: "exact.example.com"},
					{MatchPattern: "*.wild.example.com"},
					{MatchPattern: "**.deep.example.com"},
					{MatchPattern: "*"},
				},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
			},
		),
	}
	patterns := cfg.CompileFQDNPatterns()

	tests := map[string]struct {
		qname string
		want  bool
	}{
		"exact match": {
			qname: "exact.example.com.",
			want:  true,
		},
		"exact no match wrong name": {
			qname: "other.example.com.",
			want:  true, // matches bare wildcard "*"
		},
		"single-star matches one label": {
			qname: "sub.wild.example.com.",
			want:  true,
		},
		"single-star rejects multi-label": {
			qname: "a.b.wild.example.com.",
			want:  true, // matches bare wildcard "*"
		},
		"double-star matches one label": {
			qname: "sub.deep.example.com.",
			want:  true,
		},
		"double-star matches multi-label": {
			qname: "a.b.deep.example.com.",
			want:  true,
		},
		"bare wildcard matches anything": {
			qname: "anything.anywhere.com.",
			want:  true,
		},
		"bare wildcard matches root": {
			qname: ".",
			want:  true,
		},
		"empty string no match": {
			qname: "",
			want:  false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			matched := false
			for _, p := range patterns {
				if p.Regex.MatchString(tt.qname) {
					matched = true

					break
				}
			}

			assert.Equal(t, tt.want, matched)
		})
	}
}

// TestMatchFQDNPatternsWithoutBareWildcard tests pattern matching
// without a bare wildcard to verify single-star depth restriction.
func TestMatchFQDNPatternsWithoutBareWildcard(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{
				{MatchPattern: "*.example.com"},
				{MatchPattern: "**.deep.other.com"},
			},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
		}),
	}
	patterns := cfg.CompileFQDNPatterns()

	tests := map[string]struct {
		qname string
		want  bool
	}{
		"single-star matches one label": {
			qname: "sub.example.com.",
			want:  true,
		},
		"single-star rejects multi-label": {
			qname: "a.b.example.com.",
			want:  false,
		},
		"single-star rejects bare parent": {
			qname: "example.com.",
			want:  false,
		},
		"double-star matches one label": {
			qname: "sub.deep.other.com.",
			want:  true,
		},
		"double-star matches multi-label": {
			qname: "a.b.deep.other.com.",
			want:  true,
		},
		"double-star rejects bare parent": {
			qname: "deep.other.com.",
			want:  false,
		},
		"unrelated domain": {
			qname: "other.com.",
			want:  false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			matched := false
			for _, p := range patterns {
				if p.Regex.MatchString(tt.qname) {
					matched = true

					break
				}
			}

			assert.Equal(t, tt.want, matched)
		})
	}
}
