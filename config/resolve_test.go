package config_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
)

func TestTCPForwardHosts(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		forwards []config.TCPForward
		want     []string
	}{
		"deduplicated and sorted": {
			forwards: []config.TCPForward{
				{Port: 22, Host: "github.com"},
				{Port: 3306, Host: "db.example.com"},
				{Port: 5432, Host: "github.com"},
			},
			want: []string{"db.example.com", "github.com"},
		},
		"empty": {},
		"single": {
			forwards: []config.TCPForward{{Port: 22, Host: "gitlab.com"}},
			want:     []string{"gitlab.com"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.Config{TCPForwards: tt.forwards}
			assert.Equal(t, tt.want, cfg.TCPForwardHosts())
		})
	}
}

func TestResolveDomains(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Egress: egressRules(
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{
					{MatchName: "github.com"},
					{MatchName: "extra.com"},
				},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			},
			config.EgressRule{
				ToFQDNs: []config.FQDNSelector{
					{MatchName: "github.com"},
				},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			},
		),
	}

	domains := cfg.ResolveDomains()

	// Github.com appears in both rules but should be deduplicated.
	count := 0
	for _, d := range domains {
		if d == "github.com" {
			count++
		}
	}

	assert.Equal(t, 1, count, "github.com should appear exactly once")
	assert.True(t, sort.StringsAreSorted(domains))
}

func TestResolveRules(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg      *config.Config
		want     []config.ResolvedRule
		wantNone bool
	}{
		"simple FQDN rule": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "registry.npmjs.org"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			want: []config.ResolvedRule{{Domain: "registry.npmjs.org"}},
		},
		"FQDN with L7 paths": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{
						{MatchName: "api.example.com"},
						{MatchName: "cdn.example.com"},
					},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Path: "/v1/"},
							{Path: "/v2/"},
						}},
					}},
				}),
			},
			want: []config.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []config.ResolvedHTTPRule{{Path: "/v1/"}, {Path: "/v2/"}}},
				{Domain: "cdn.example.com", HTTPRules: []config.ResolvedHTTPRule{{Path: "/v1/"}, {Path: "/v2/"}}},
			},
		},
		"merge L7 across rules": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []config.PortRule{{
							Ports: []config.Port{{Port: "443"}},
							Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
						}},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []config.PortRule{{
							Ports: []config.Port{{Port: "443"}},
							Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v2/"}}},
						}},
					},
				),
			},
			want: []config.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []config.ResolvedHTTPRule{{Path: "/v1/"}, {Path: "/v2/"}}},
			},
		},
		"plain L4 wins over L7 paths": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []config.PortRule{{
							Ports: []config.Port{{Port: "443"}},
							Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
						}},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			want: []config.ResolvedRule{
				{Domain: "api.example.com"},
			},
		},
		"deduplicate paths": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Path: "/v1/"},
							{Path: "/v1/"},
						}},
					}},
				}),
			},
			want: []config.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []config.ResolvedHTTPRule{{Path: "/v1/"}}},
			},
		},
		"methods merge across rules": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []config.PortRule{{
							Ports: []config.Port{{Port: "443"}},
							Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Method: "GET"}}},
						}},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []config.PortRule{{
							Ports: []config.Port{{Port: "443"}},
							Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Method: "POST"}}},
						}},
					},
				),
			},
			want: []config.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []config.ResolvedHTTPRule{{Method: "GET"}, {Method: "POST"}}},
			},
		},
		"plain L4 wins over methods": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []config.PortRule{{
							Ports: []config.Port{{Port: "443"}},
							Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Method: "GET"}}},
						}},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			want: []config.ResolvedRule{
				{Domain: "api.example.com"},
			},
		},
		"dedup methods": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Method: "GET"},
							{Method: "GET"},
						}},
					}},
				}),
			},
			want: []config.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []config.ResolvedHTTPRule{{Method: "GET"}}},
			},
		},
		"paths and methods paired": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Path: "/v1/", Method: "GET"},
							{Path: "/v1/", Method: "POST"},
						}},
					}},
				}),
			},
			want: []config.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []config.ResolvedHTTPRule{
					{Method: "GET", Path: "/v1/"},
					{Method: "POST", Path: "/v1/"},
				}},
			},
		},
		"HTTP rules are paired not cross-producted": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{
							{Method: "GET", Path: "/api"},
							{Method: "POST", Path: "/submit"},
						}},
					}},
				}),
			},
			want: []config.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []config.ResolvedHTTPRule{
					{Method: "GET", Path: "/api"},
					{Method: "POST", Path: "/submit"},
				}},
			},
		},
		"CIDR-only rule skipped": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}}},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			want: []config.ResolvedRule{{Domain: "example.com"}},
		},
		"matchPattern used as domain": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
			want: []config.ResolvedRule{{Domain: "*.example.com"}},
		},
		"nil egress returns empty": {
			cfg:      &config.Config{},
			wantNone: true,
		},
		"empty egress returns empty": {
			cfg:      &config.Config{Egress: egressRules()},
			wantNone: true,
		},
		"empty HTTP propagates as unrestricted through ResolveRules": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{}},
					}},
				}),
			},
			want: []config.ResolvedRule{{Domain: "api.example.com"}},
		},
		"cross-domain L7 isolation": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []config.PortRule{{
							Ports: []config.Port{{Port: "443"}},
							Rules: &config.L7Rules{HTTP: []config.HTTPRule{
								{Method: "GET", Path: "/v1/"},
							}},
						}},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "cdn.example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			want: []config.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []config.ResolvedHTTPRule{
					{Method: "GET", Path: "/v1/"},
				}},
				{Domain: "cdn.example.com"},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rules := tt.cfg.ResolveRules()
			if tt.wantNone {
				assert.Empty(t, rules)
			} else {
				assert.Equal(t, tt.want, rules)
			}
		})
	}
}

func TestResolveRulesForPort(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg      *config.Config
		want     []config.ResolvedRule
		port     int
		wantNone bool
	}{
		"domain scoped to port 443 only - matching": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "github.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			})},
			port: 443,
			want: []config.ResolvedRule{{Domain: "github.com"}},
		},
		"domain scoped to port 443 only - non-matching": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "github.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			})},
			port:     80,
			wantNone: true,
		},
		"domain with multiple ports matches each": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "github.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}, {Port: "8080"}}}},
			})},
			port: 8080,
			want: []config.ResolvedRule{{Domain: "github.com"}},
		},
		"per-port L7 scoping": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "8080"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v2/"}}},
					}},
				},
			)},
			port: 443,
			want: []config.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []config.ResolvedHTTPRule{{Path: "/v1/"}}},
			},
		},
		"per-port L7 scoping - other port": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "8080"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v2/"}}},
					}},
				},
			)},
			port: 8080,
			want: []config.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []config.ResolvedHTTPRule{{Path: "/v2/"}}},
			},
		},
		"same domain same port merges L7": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v2/"}}},
					}},
				},
			)},
			port: 443,
			want: []config.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []config.ResolvedHTTPRule{{Path: "/v1/"}, {Path: "/v2/"}}},
			},
		},
		"empty Ports list matches all ports": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{
					{Ports: []config.Port{{Port: "443"}}},
					{Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}}},
				},
			})},
			port: 9999,
			want: []config.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []config.ResolvedHTTPRule{{Path: "/v1/"}}},
			},
		},
		"plain L4 nullifies sibling L7 on same port": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{
					{Ports: []config.Port{{Port: "443"}}},
					{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Method: "GET"}}},
					},
				},
			})},
			port: 443,
			want: []config.ResolvedRule{{Domain: "api.example.com"}},
		},
		"ANY plain L4 nullifies TCP L7 on same port": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{
					{Ports: []config.Port{{Port: "443"}}},
					{
						Ports: []config.Port{{Port: "443", Protocol: "TCP"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/api"}}},
					},
				},
			})},
			port: 443,
			want: []config.ResolvedRule{{Domain: "api.example.com"}},
		},
		"UDP plain L4 does not nullify TCP L7 on same port": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{
					{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}},
					{
						Ports: []config.Port{{Port: "443", Protocol: "TCP"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/api"}}},
					},
				},
			})},
			port: 443,
			want: []config.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []config.ResolvedHTTPRule{{Path: "/api"}}},
			},
		},
		"TCP plain L4 still nullifies TCP L7 on same port": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{
					{Ports: []config.Port{{Port: "443", Protocol: "TCP"}}},
					{
						Ports: []config.Port{{Port: "443", Protocol: "TCP"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/api"}}},
					},
				},
			})},
			port: 443,
			want: []config.ResolvedRule{{Domain: "api.example.com"}},
		},
		"toPorts-only rule excluded": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}},
			})},
			port:     8080,
			wantNone: true,
		},
		"mixed rules per port": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "always.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "80"}, {Port: "443"}}}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "only443.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				},
			)},
			port: 80,
			want: []config.ResolvedRule{{Domain: "always.com"}},
		},
		"empty HTTP list produces unrestricted rule": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{}},
				}},
			})},
			port: 443,
			want: []config.ResolvedRule{{Domain: "api.example.com"}},
		},
		"empty HTTP merged with L7 rules is unrestricted": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{}},
					}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
					}},
				},
			)},
			port: 443,
			want: []config.ResolvedRule{{Domain: "api.example.com"}},
		},
		"empty HTTP plus plain L4 is unrestricted": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: []config.HTTPRule{}},
					}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				},
			)},
			port: 443,
			want: []config.ResolvedRule{{Domain: "api.example.com"}},
		},
		"rules nil HTTP is plain L4": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "443"}},
					Rules: &config.L7Rules{},
				}},
			})},
			port: 443,
			want: []config.ResolvedRule{{Domain: "api.example.com"}},
		},
		"separate FQDN and CIDR rules contribute domains": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				},
				config.EgressRule{
					ToCIDR:  []string{"10.0.0.0/8"},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				},
			)},
			port: 443,
			want: []config.ResolvedRule{{Domain: "api.example.com"}},
		},
		"endPort range matches port within range": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "400", EndPort: 500}}}},
			})},
			port: 450,
			want: []config.ResolvedRule{{Domain: "api.example.com"}},
		},
		"endPort range does not match port outside range": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "400", EndPort: 500}}}},
			})},
			port:     501,
			wantNone: true,
		},
		"endPort range matches start port": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "400", EndPort: 500}}}},
			})},
			port: 400,
			want: []config.ResolvedRule{{Domain: "api.example.com"}},
		},
		"endPort range matches end port": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "400", EndPort: 500}}}},
			})},
			port: 500,
			want: []config.ResolvedRule{{Domain: "api.example.com"}},
		},
		"deep wildcard preserves double-star domain": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchPattern: "**.example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			})},
			port: 443,
			want: []config.ResolvedRule{{Domain: "**.example.com"}},
		},
		"bare double star resolves as single star": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchPattern: "**"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			})},
			port: 443,
			want: []config.ResolvedRule{{Domain: "*"}},
		},
		"port 0 matches all target ports": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "wildcard.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "0"}}}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "specific.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				},
			)},
			port: 443,
			want: []config.ResolvedRule{
				{Domain: "specific.example.com"},
				{Domain: "wildcard.example.com"},
			},
		},
		"port 0 matches non-standard ports": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "wildcard.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "0"}}}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "specific.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}},
				},
			)},
			port: 8080,
			want: []config.ResolvedRule{
				{Domain: "specific.example.com"},
				{Domain: "wildcard.example.com"},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rules := tt.cfg.ResolveRulesForPort(tt.port)
			if tt.wantNone {
				assert.Empty(t, rules)
			} else {
				assert.Equal(t, tt.want, rules)
			}
		})
	}
}

func TestResolveOpenPorts(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *config.Config
		want []int
	}{
		"toPorts-only rule produces open ports": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}},
			})},
			want: []int{8080},
		},
		"rule with toFQDNs not open": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}},
			})},
		},
		"rule with toCIDRSet not open": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
				ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}},
			})},
		},
		"rule with toCIDR not open": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToCIDR:  []string{"0.0.0.0/0"},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}},
			})},
		},
		"no toPorts-only rules": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			})},
		},
		"multiple open ports": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}, {Port: "9090"}}}},
			})},
			want: []int{8080, 9090},
		},
		"mixed open and domain rules": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				},
				config.EgressRule{ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "3000"}}}}},
			)},
			want: []int{3000},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tt.cfg.ResolveOpenPorts()
			if tt.want == nil {
				assert.Empty(t, got)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestResolveOpenPortRules(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *config.Config
		want []config.ResolvedOpenPort
	}{
		"TCP open port": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080", Protocol: "TCP"}}}},
			})},
			want: []config.ResolvedOpenPort{{Port: 8080, Protocol: "TCP"}},
		},
		"UDP open port": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "5353", Protocol: "UDP"}}}},
			})},
			want: []config.ResolvedOpenPort{{Port: 5353, Protocol: "UDP"}},
		},
		"SCTP open port": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "3868", Protocol: "SCTP"}}}},
			})},
			want: []config.ResolvedOpenPort{{Port: 3868, Protocol: "SCTP"}},
		},
		"ANY protocol open port expands": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080", Protocol: "ANY"}}}},
			})},
			want: []config.ResolvedOpenPort{
				{Port: 8080, Protocol: "TCP"},
				{Port: 8080, Protocol: "UDP"},
			},
		},
		"empty protocol open port expands": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}},
			})},
			want: []config.ResolvedOpenPort{
				{Port: 8080, Protocol: "TCP"},
				{Port: 8080, Protocol: "UDP"},
			},
		},
		"rule with toFQDNs not open": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}},
			})},
		},
		"TCP open port with endPort": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "8000", EndPort: 9000, Protocol: "TCP"},
				}}},
			})},
			want: []config.ResolvedOpenPort{
				{Port: 8000, EndPort: 9000, Protocol: "TCP"},
			},
		},
		"UDP open port with endPort": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "5000", EndPort: 6000, Protocol: "UDP"},
				}}},
			})},
			want: []config.ResolvedOpenPort{
				{Port: 5000, EndPort: 6000, Protocol: "UDP"},
			},
		},
		"ANY protocol open port with endPort expands": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8000", EndPort: 9000}}}},
			})},
			want: []config.ResolvedOpenPort{
				{Port: 8000, EndPort: 9000, Protocol: "TCP"},
				{Port: 8000, EndPort: 9000, Protocol: "UDP"},
			},
		},
		"endPort equal to port": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{
					{Port: "8000", EndPort: 8000, Protocol: "TCP"},
				}}},
			})},
			want: []config.ResolvedOpenPort{
				{Port: 8000, EndPort: 8000, Protocol: "TCP"},
			},
		},
		"dedup across rules with same range": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToPorts: []config.PortRule{
						{Ports: []config.Port{{Port: "8000", EndPort: 9000, Protocol: "TCP"}}},
					},
				},
				config.EgressRule{
					ToPorts: []config.PortRule{
						{Ports: []config.Port{{Port: "8000", EndPort: 9000, Protocol: "TCP"}}},
					},
				},
			)},
			want: []config.ResolvedOpenPort{
				{Port: 8000, EndPort: 9000, Protocol: "TCP"},
			},
		},
		"mixed single and range for same start port": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8000", Protocol: "TCP"}}}},
				},
				config.EgressRule{
					ToPorts: []config.PortRule{
						{Ports: []config.Port{{Port: "8000", EndPort: 9000, Protocol: "TCP"}}},
					},
				},
			)},
			want: []config.ResolvedOpenPort{
				{Port: 8000, Protocol: "TCP"},
				{Port: 8000, EndPort: 9000, Protocol: "TCP"},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tt.cfg.ResolveOpenPortRules()
			if tt.want == nil {
				assert.Empty(t, got)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestHasUnrestrictedOpenPorts(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *config.Config
		want bool
	}{
		"empty Ports list is unrestricted": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{}},
			})},
			want: true,
		},
		"port 0 counts as unrestricted": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "0"}}}},
			})},
			want: true,
		},
		"specific port is not unrestricted": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			})},
			want: false,
		},
		"FQDN rule with port 0 not unrestricted": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "0"}}}},
			})},
			want: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, tt.cfg.HasUnrestrictedOpenPorts())
		})
	}
}

func TestResolveFQDNNonTCPPorts(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *config.Config
		want []config.FQDNRulePorts
	}{
		"FQDN UDP port": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
			})},
			want: []config.FQDNRulePorts{
				{RuleIndex: 0, Ports: []config.ResolvedOpenPort{{Port: 443, Protocol: "UDP"}}},
			},
		},
		"FQDN SCTP port": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "3868", Protocol: "SCTP"}}}},
			})},
			want: []config.FQDNRulePorts{
				{RuleIndex: 0, Ports: []config.ResolvedOpenPort{{Port: 3868, Protocol: "SCTP"}}},
			},
		},
		"FQDN ANY port expands to udp": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
			})},
			want: []config.FQDNRulePorts{
				{RuleIndex: 0, Ports: []config.ResolvedOpenPort{{Port: 443, Protocol: "UDP"}}},
			},
		},
		"FQDN TCP-only returns nil": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "TCP"}}}},
			})},
		},
		"CIDR rule with UDP returns nil": {
			cfg: &config.Config{Egress: egressRules(config.EgressRule{
				ToCIDRSet: []config.CIDRRule{{CIDR: "8.8.8.0/24"}},
				ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "53", Protocol: "UDP"}}}},
			})},
		},
		"unrestricted returns nil": {
			cfg: &config.Config{},
		},
		"two FQDN rules get separate indices": {
			cfg: &config.Config{Egress: egressRules(
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "a.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
				},
				config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "b.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080", Protocol: "UDP"}}}},
				},
			)},
			want: []config.FQDNRulePorts{
				{RuleIndex: 0, Ports: []config.ResolvedOpenPort{{Port: 443, Protocol: "UDP"}}},
				{RuleIndex: 1, Ports: []config.ResolvedOpenPort{{Port: 8080, Protocol: "UDP"}}},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tt.cfg.ResolveFQDNNonTCPPorts()
			if tt.want == nil {
				assert.Empty(t, got)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestResolvePorts(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *config.Config
		want []int
	}{
		"explicit ports": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{
						{Port: "80"},
						{Port: "443"},
						{Port: "8080"},
					}}},
				}),
			},
			want: []int{80, 443, 8080},
		},
		"FQDN with explicit ports": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				}),
			},
			want: []int{80, 443},
		},
		"nil egress returns nil": {
			cfg: &config.Config{},
		},
		"empty egress returns nil": {
			cfg: &config.Config{Egress: egressRules()},
		},
		"deduplication": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "a.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "b.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			want: []int{443},
		},
		"toCIDR-only rule excluded from ports": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToCIDR:  []string{"10.0.0.0/8"},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			want: []int{443},
		},
		"CIDR-only rule excluded from ports": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
						ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "8080"}}}},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			want: []int{443},
		},
		"empty rule returns nil ports": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{}),
			},
		},
		"CIDR-only rule returns nil": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "0.0.0.0/0"}},
				}),
			},
		},
		"UDP-only port excluded": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{
						{Port: "443", Protocol: "TCP"},
						{Port: "5353", Protocol: "UDP"},
					}}},
				}),
			},
			want: []int{443},
		},
		"SCTP-only port excluded": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{
						{Port: "443", Protocol: "TCP"},
						{Port: "3868", Protocol: "SCTP"},
					}}},
				}),
			},
			want: []int{443},
		},
		"ANY protocol port included": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{
						{Port: "8080", Protocol: "ANY"},
					}}},
				}),
			},
			want: []int{8080},
		},
		"separate FQDN and CIDR rules contribute FQDN ports": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
					config.EgressRule{
						ToCIDR:  []string{"10.0.0.0/8"},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			want: []int{443},
		},
		"open-port range excluded from Envoy listeners": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToPorts: []config.PortRule{
							{Ports: []config.Port{{Port: "8000", EndPort: 9000, Protocol: "TCP"}}},
						},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			want: []int{443},
		},
		"open-port single port included in Envoy listeners": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080", Protocol: "TCP"}}}},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			want: []int{443, 8080},
		},
		"port 0 does not appear in resolved ports": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "0"}}}},
				}),
			},
		},
		"FQDN endPort expands range": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{
						{Port: "8000", EndPort: 8003},
					}}},
				}),
			},
			want: []int{8000, 8001, 8002, 8003},
		},
		"FQDN endPort mixed with single port": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{
						{Port: "443"},
						{Port: "8000", EndPort: 8002},
					}}},
				}),
			},
			want: []int{443, 8000, 8001, 8002},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.cfg.ResolvePorts())
		})
	}
}

func TestExtraPorts(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *config.Config
		want []int
	}{
		"extra ports present": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{
						{Port: "80"}, {Port: "443"}, {Port: "8080"}, {Port: "9090"},
					}}},
				}),
			},
			want: []int{8080, 9090},
		},
		"no extra ports": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{
						{Port: "80"}, {Port: "443"},
					}}},
				}),
			},
		},
		"nil egress": {
			cfg: &config.Config{},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.cfg.ExtraPorts())
		})
	}
}

func TestResolveCIDRRules(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg      *config.Config
		wantIPv4 []config.ResolvedCIDR
		wantIPv6 []config.ResolvedCIDR
		validate bool
	}{
		"mixed IPv4 and IPv6": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{
						{CIDR: "0.0.0.0/0", Except: []string{"10.0.0.0/8", "172.16.0.0/12"}},
						{CIDR: "::/0", Except: []string{"fc00::/7"}},
					},
				}),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "0.0.0.0/0", Except: []string{"10.0.0.0/8", "172.16.0.0/12"}},
			},
			wantIPv6: []config.ResolvedCIDR{
				{CIDR: "::/0", Except: []string{"fc00::/7"}},
			},
		},
		"no CIDR rules": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
		"port-scoped CIDR": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "8.8.8.0/24"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "443"}, {Port: "80"}}}},
				}),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "8.8.8.0/24", Ports: []config.ResolvedPortProto{
					{Port: 80, Protocol: "TCP"},
					{Port: 80, Protocol: "UDP"},
					{Port: 443, Protocol: "TCP"},
					{Port: 443, Protocol: "UDP"},
				}},
			},
		},
		"empty Ports list means any port": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "8.8.8.0/24"}},
					ToPorts: []config.PortRule{{Rules: &config.L7Rules{
						HTTP: []config.HTTPRule{{Path: "/v1/"}},
					}}},
				}),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "8.8.8.0/24"},
			},
		},
		"no toPorts means any port": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "8.8.8.0/24"}},
				}),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "8.8.8.0/24"},
			},
		},
		"multiple rules with different ports": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToCIDRSet: []config.CIDRRule{{CIDR: "8.8.8.0/24"}},
						ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "53"}}}},
					},
					config.EgressRule{
						ToCIDRSet: []config.CIDRRule{{CIDR: "1.1.1.0/24"}},
						ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "8.8.8.0/24", Ports: []config.ResolvedPortProto{
					{Port: 53, Protocol: "TCP"},
					{Port: 53, Protocol: "UDP"},
				}, RuleIndex: 0},
				{CIDR: "1.1.1.0/24", Ports: []config.ResolvedPortProto{
					{Port: 443, Protocol: "TCP"},
					{Port: 443, Protocol: "UDP"},
				}, RuleIndex: 1},
			},
		},
		"toCIDR without except": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR: []string{"8.8.8.0/24"},
				}),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "8.8.8.0/24"},
			},
		},
		"toCIDR and toCIDRSet in same rule share RuleIndex": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR:    []string{"10.0.0.0/8"},
					ToCIDRSet: []config.CIDRRule{{CIDR: "192.168.0.0/16", Except: []string{"192.168.1.0/24"}}},
				}),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "10.0.0.0/8", RuleIndex: 0},
				{CIDR: "192.168.0.0/16", Except: []string{"192.168.1.0/24"}, RuleIndex: 0},
			},
		},
		"toCIDR and toCIDRSet in separate rules": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{ToCIDR: []string{"1.1.1.0/24"}},
					config.EgressRule{
						ToCIDRSet: []config.CIDRRule{{CIDR: "8.8.8.0/24", Except: []string{"8.8.8.8/32"}}},
					},
				),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "1.1.1.0/24", RuleIndex: 0},
				{CIDR: "8.8.8.0/24", Except: []string{"8.8.8.8/32"}, RuleIndex: 1},
			},
		},
		"UDP port-scoped CIDR": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "8.8.8.0/24"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "53", Protocol: "UDP"}}}},
				}),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "8.8.8.0/24", Ports: []config.ResolvedPortProto{{Port: 53, Protocol: "UDP"}}},
			},
		},
		"ANY protocol CIDR": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "8.8.8.0/24"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "53", Protocol: "ANY"}}}},
				}),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "8.8.8.0/24", Ports: []config.ResolvedPortProto{
					{Port: 53, Protocol: "TCP"},
					{Port: 53, Protocol: "UDP"},
				}},
			},
		},
		"port range propagated": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "8.8.8.0/24"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "8000", EndPort: 9000}}}},
				}),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "8.8.8.0/24", Ports: []config.ResolvedPortProto{
					{Port: 8000, EndPort: 9000, Protocol: "TCP"},
					{Port: 8000, EndPort: 9000, Protocol: "UDP"},
				}},
			},
		},
		// IPv4-mapped IPv6 CIDRs are now rejected at validation time
		// (ErrCIDRIPv4MappedIPv6), so they never reach ResolveCIDRRules.
		// See TestValidate for the rejection tests.
		"separate FQDN and CIDR rules contribute CIDRs": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
					config.EgressRule{
						ToCIDR:  []string{"10.0.0.0/8"},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "10.0.0.0/8", Ports: []config.ResolvedPortProto{
					{Port: 443, Protocol: "TCP"},
					{Port: 443, Protocol: "UDP"},
				}, RuleIndex: 0},
			},
		},
		"port 0 CIDR rule has no port restriction": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "10.0.0.0/8"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "0"}}}},
				}),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "10.0.0.0/8"},
			},
		},
		"ANY omits SCTP": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "8.8.8.0/24"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "53"}}}},
				}),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "8.8.8.0/24", Ports: []config.ResolvedPortProto{
					{Port: 53, Protocol: "TCP"},
					{Port: 53, Protocol: "UDP"},
				}},
			},
		},
		"explicit SCTP preserved": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDRSet: []config.CIDRRule{{CIDR: "8.8.8.0/24"}},
					ToPorts:   []config.PortRule{{Ports: []config.Port{{Port: "3868", Protocol: "SCTP"}}}},
				}),
			},
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "8.8.8.0/24", Ports: []config.ResolvedPortProto{
					{Port: 3868, Protocol: "SCTP"},
				}},
			},
		},
		"bare IPv4 toCIDR normalizes to /32": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR: []string{"8.8.8.8"},
				}),
			},
			validate: true,
			wantIPv4: []config.ResolvedCIDR{
				{CIDR: "8.8.8.8/32"},
			},
		},
		"bare IPv6 toCIDR normalizes to /128": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR: []string{"fd00::1"},
				}),
			},
			validate: true,
			wantIPv6: []config.ResolvedCIDR{
				{CIDR: "fd00::1/128"},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if tt.validate {
				require.NoError(t, tt.cfg.Validate())
			}

			ipv4, ipv6 := tt.cfg.ResolveCIDRRules()
			assert.Equal(t, tt.wantIPv4, ipv4)
			assert.Equal(t, tt.wantIPv6, ipv6)
		})
	}
}

func TestCompileFQDNPatterns(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		match       map[string]bool
		noMatch     map[string]bool
		want        []string
		wantIndices []int
		cfg         config.Config
	}{
		"matchName exact": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"api.example.com"},
			wantIndices: []int{0},
			match:       map[string]bool{"api.example.com.": true},
			noMatch:     map[string]bool{"evil.api.example.com.": true, "example.com.": true},
		},
		"single-star wildcard": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"*.example.com"},
			wantIndices: []int{0},
			match:       map[string]bool{"sub.example.com.": true},
			noMatch:     map[string]bool{"a.b.example.com.": true, "example.com.": true},
		},
		"double-star wildcard": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "**.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"**.example.com"},
			wantIndices: []int{0},
			match:       map[string]bool{"sub.example.com.": true, "a.b.example.com.": true},
			noMatch:     map[string]bool{"example.com.": true},
		},
		"bare wildcard": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "*"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"*"},
			wantIndices: []int{0},
			match:       map[string]bool{"anything.com.": true, "a.b.c.": true, ".": true},
			noMatch:     map[string]bool{"": true},
		},
		"triple-star bare wildcard": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "***"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"***"},
			wantIndices: []int{0},
			match:       map[string]bool{"anything.com.": true, ".": true},
		},
		"triple-star suffix wildcard": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "***.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"***.example.com"},
			wantIndices: []int{0},
			match:       map[string]bool{"sub.example.com.": true, "a.b.example.com.": true},
			noMatch:     map[string]bool{"example.com.": true},
		},
		"mid-position double-star falls back to single-label": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchPattern: "test.**.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"test.**.example.com"},
			wantIndices: []int{0},
			match:       map[string]bool{"test.sub.example.com.": true},
			noMatch:     map[string]bool{"test.a.b.example.com.": true},
		},
		"excludes TCPForward hosts": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
				TCPForwards: []config.TCPForward{{Port: 22, Host: "git.example.com"}},
			},
			want:        []string{"api.example.com"},
			wantIndices: []int{0},
		},
		"same pattern in two rules produces two entries": {
			cfg: config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "8080", Protocol: "UDP"}}}},
					},
				),
			},
			want:        []string{"api.example.com", "api.example.com"},
			wantIndices: []int{0, 1},
		},
		"deduplicates within same rule": {
			cfg: config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{
						{MatchName: "api.example.com"},
						{MatchName: "api.example.com"},
					},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"api.example.com"},
			wantIndices: []int{0},
		},
		"skips TCP-only FQDN rules": {
			cfg: config.Config{
				Egress: egressRules(
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "tcp-only.example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "TCP"}}}},
					},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "udp.example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "5353", Protocol: "UDP"}}}},
					},
				),
			},
			want:        []string{"udp.example.com"},
			wantIndices: []int{0},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			patterns := tt.cfg.CompileFQDNPatterns()

			var originals []string

			var indices []int

			for _, p := range patterns {
				originals = append(originals, p.Original)
				indices = append(indices, p.RuleIndex)
			}

			assert.Equal(t, tt.want, originals)

			if tt.wantIndices != nil {
				assert.Equal(t, tt.wantIndices, indices)
			}

			for qname := range tt.match {
				matched := false

				for _, p := range patterns {
					if p.Regex.MatchString(qname) {
						matched = true

						break
					}
				}

				assert.True(t, matched, "expected %q to match", qname)
			}

			for qname := range tt.noMatch {
				matched := false

				for _, p := range patterns {
					if p.Regex.MatchString(qname) {
						matched = true

						break
					}
				}

				assert.False(t, matched, "expected %q not to match", qname)
			}
		})
	}
}

func TestResolveCIDRRulesWithServerNames(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToCIDR: []string{"10.0.0.0/8"},
			ToPorts: []config.PortRule{{
				Ports:       []config.Port{{Port: "443", Protocol: "TCP"}},
				ServerNames: []string{"api.internal.example.com"},
			}},
		}),
	}

	v4, _ := cfg.ResolveCIDRRules()
	require.Len(t, v4, 1)
	assert.Equal(t, []string{"api.internal.example.com"}, v4[0].ServerNames)
}

func TestResolveServerNameRulesForPort(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToCIDR: []string{"10.0.0.0/8"},
			ToPorts: []config.PortRule{{
				Ports:       []config.Port{{Port: "443", Protocol: "TCP"}},
				ServerNames: []string{"api.internal.example.com", "db.internal.example.com"},
			}},
		}),
	}

	rules := cfg.ResolveServerNameRulesForPort(443)
	require.Len(t, rules, 2)
	assert.Equal(t, "api.internal.example.com", rules[0].Domain)
	assert.Equal(t, "db.internal.example.com", rules[1].Domain)
	assert.False(t, rules[0].IsRestricted())

	// Port 80 should not match.
	rules80 := cfg.ResolveServerNameRulesForPort(80)
	assert.Empty(t, rules80)
}

func TestResolveDenyCIDRRules(t *testing.T) {
	t.Parallel()

	denyRules := func(rules ...config.EgressDenyRule) *[]config.EgressDenyRule {
		return &rules
	}

	tests := map[string]struct {
		cfg    *config.Config
		wantV4 []config.ResolvedCIDR
		wantV6 []config.ResolvedCIDR
	}{
		"nil egressDeny": {
			cfg: &config.Config{},
		},
		"deny CIDR v4": {
			cfg: &config.Config{
				EgressDeny: denyRules(config.EgressDenyRule{
					ToCIDR: []string{"10.0.0.0/8"},
				}),
			},
			wantV4: []config.ResolvedCIDR{
				{CIDR: "10.0.0.0/8", RuleIndex: 0},
			},
		},
		"deny CIDR v6": {
			cfg: &config.Config{
				EgressDeny: denyRules(config.EgressDenyRule{
					ToCIDR: []string{"fd00::/8"},
				}),
			},
			wantV6: []config.ResolvedCIDR{
				{CIDR: "fd00::/8", RuleIndex: 0},
			},
		},
		"deny CIDR with ports": {
			cfg: &config.Config{
				EgressDeny: denyRules(config.EgressDenyRule{
					ToCIDR:  []string{"10.0.0.0/8"},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "TCP"}}}},
				}),
			},
			wantV4: []config.ResolvedCIDR{
				{
					CIDR:      "10.0.0.0/8",
					RuleIndex: 0,
					Ports: []config.ResolvedPortProto{
						{Port: 443, Protocol: "TCP"},
					},
				},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			v4, v6 := tt.cfg.ResolveDenyCIDRRules()
			assert.Equal(t, tt.wantV4, v4)
			assert.Equal(t, tt.wantV6, v6)
		})
	}
}

func TestResolveDenyPortOnlyRules(t *testing.T) {
	t.Parallel()

	denyRules := func(rules ...config.EgressDenyRule) *[]config.EgressDenyRule {
		return &rules
	}

	tests := map[string]struct {
		cfg  *config.Config
		want []config.ResolvedPortProto
	}{
		"nil egressDeny": {
			cfg: &config.Config{},
		},
		"port-only deny rule": {
			cfg: &config.Config{
				EgressDeny: denyRules(config.EgressDenyRule{
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "6379", Protocol: "TCP"}}}},
				}),
			},
			want: []config.ResolvedPortProto{
				{Port: 6379, Protocol: "TCP"},
			},
		},
		"CIDR+port deny rule not included": {
			cfg: &config.Config{
				EgressDeny: denyRules(config.EgressDenyRule{
					ToCIDR:  []string{"10.0.0.0/8"},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443", Protocol: "TCP"}}}},
				}),
			},
		},
		"port-only with ANY expands": {
			cfg: &config.Config{
				EgressDeny: denyRules(config.EgressDenyRule{
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "53"}}}},
				}),
			},
			want: []config.ResolvedPortProto{
				{Port: 53, Protocol: "TCP"},
				{Port: 53, Protocol: "UDP"},
			},
		},
		"empty ports list means wildcard": {
			cfg: &config.Config{
				EgressDeny: denyRules(config.EgressDenyRule{
					ToPorts: []config.PortRule{{}},
				}),
			},
			want: []config.ResolvedPortProto{
				{},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tt.cfg.ResolveDenyPortOnlyRules()
			if tt.want == nil {
				assert.Empty(t, got)
			} else {
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestResolveICMPRules(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *config.Config
		want []config.ResolvedICMP
	}{
		"single IPv4 ICMP rule": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ICMPs: []config.ICMPRule{{
						Fields: []config.ICMPField{
							{Family: "IPv4", Type: "8"},
						},
					}},
				}),
			},
			want: []config.ResolvedICMP{
				{Family: "IPv4", Type: 8, RuleIndex: 0},
			},
		},
		"mixed IPv4 and IPv6": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ICMPs: []config.ICMPRule{{
						Fields: []config.ICMPField{
							{Family: "IPv4", Type: "8"},
							{Family: "IPv6", Type: "128"},
						},
					}},
				}),
			},
			want: []config.ResolvedICMP{
				{Family: "IPv4", Type: 8, RuleIndex: 0},
				{Family: "IPv6", Type: 128, RuleIndex: 0},
			},
		},
		"multiple rules": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{
						ICMPs: []config.ICMPRule{{
							Fields: []config.ICMPField{
								{Family: "IPv4", Type: "8"},
							},
						}},
					},
					config.EgressRule{
						ICMPs: []config.ICMPRule{{
							Fields: []config.ICMPField{
								{Family: "IPv4", Type: "0"},
							},
						}},
					},
				),
			},
			want: []config.ResolvedICMP{
				{Family: "IPv4", Type: 8, RuleIndex: 0},
				{Family: "IPv4", Type: 0, RuleIndex: 1},
			},
		},
		"no ICMP rules": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToCIDR: []string{"10.0.0.0/8"},
				}),
			},
			want: nil,
		},
		"nil egress": {
			cfg:  &config.Config{},
			want: nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tt.cfg.ResolveICMPRules()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveDenyICMPRules(t *testing.T) {
	t.Parallel()

	denyRules := func(rules ...config.EgressDenyRule) *[]config.EgressDenyRule {
		return &rules
	}

	tests := map[string]struct {
		cfg  *config.Config
		want []config.ResolvedICMP
	}{
		"deny ICMP rule": {
			cfg: &config.Config{
				EgressDeny: denyRules(config.EgressDenyRule{
					ICMPs: []config.ICMPRule{{
						Fields: []config.ICMPField{
							{Family: "IPv4", Type: "8"},
						},
					}},
				}),
			},
			want: []config.ResolvedICMP{
				{Family: "IPv4", Type: 8, RuleIndex: 0},
			},
		},
		"no deny rules": {
			cfg:  &config.Config{},
			want: nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tt.cfg.ResolveDenyICMPRules()
			assert.Equal(t, tt.want, got)
		})
	}
}
