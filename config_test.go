package terrarium_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium"
)

// egressRules is a test helper that returns a pointer to a slice of terrarium.EgressRule.
func egressRules(rules ...terrarium.EgressRule) *[]terrarium.EgressRule {
	return &rules
}

func TestParseConfig(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		yaml           string
		wantRules      int
		wantDomains    []string
		notWantDomains []string
		err            error
	}{
		"FQDN and CIDR rules": {
			yaml: `
egress:
  - toCIDRSet:
      - cidr: 0.0.0.0/0
        except:
          - 10.0.0.0/8
  - toFQDNs:
      - matchName: "github.com"
      - matchPattern: "*.github.com"
    toPorts:
      - ports:
          - port: "443"
          - port: "80"
  - toFQDNs:
      - matchName: api.company.com
      - matchPattern: "*.internal.company.com"
    toPorts:
      - ports:
          - port: "443"
          - port: "80"
`,
			wantRules:   3,
			wantDomains: []string{"github.com", "*.github.com", "api.company.com", "*.internal.company.com"},
		},
		"single FQDN rule": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: custom.example.com
    toPorts:
      - ports:
          - port: "443"
`,
			wantRules:   1,
			wantDomains: []string{"custom.example.com"},
		},
		"FQDN with L7 path restrictions": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: api.example.com
    toPorts:
      - ports:
          - port: "443"
        rules:
          http:
            - path: /v1/completions
            - path: /v1/models
  - toFQDNs:
      - matchName: cdn.example.com
    toPorts:
      - ports:
          - port: "443"
`,
			wantRules:   2,
			wantDomains: []string{"api.example.com", "cdn.example.com"},
		},
		"FQDN with L7 method restrictions": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: api.example.com
    toPorts:
      - ports:
          - port: "443"
        rules:
          http:
            - method: GET
            - method: POST
  - toFQDNs:
      - matchName: cdn.example.com
    toPorts:
      - ports:
          - port: "443"
`,
			wantRules:   2,
			wantDomains: []string{"api.example.com", "cdn.example.com"},
		},
		"FQDN without toPorts rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
`,
			err: terrarium.ErrFQDNRequiresPorts,
		},
		"FQDN with wildcard port 0 rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "0"
`,
			err: terrarium.ErrFQDNWildcardPort,
		},
		"FQDN selector empty": {
			yaml: `
egress:
  - toFQDNs:
      - {}
`,
			err: terrarium.ErrFQDNSelectorEmpty,
		},
		"empty egress rule is valid (deny-all)": {
			yaml: `
egress:
  - {}
`,
			wantRules: 1,
		},
		"absent egress means unrestricted": {
			yaml:      `logging: false`,
			wantRules: 0,
		},
		"empty egress list parses as unrestricted": {
			yaml:      `egress: []`,
			wantRules: 0,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := terrarium.ParseConfig(t.Context(), []byte(tt.yaml))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}

			require.NoError(t, err)

			if tt.wantRules > 0 {
				assert.Len(t, cfg.EgressRules(), tt.wantRules)
			}

			domains := cfg.ResolveDomains()

			for _, d := range tt.wantDomains {
				assert.Contains(t, domains, d)
			}

			for _, d := range tt.notWantDomains {
				assert.NotContains(t, domains, d)
			}
		})
	}
}

func TestParseConfigEgressSemantics(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		yaml             string
		wantUnrestricted bool
		wantBlocked      bool
	}{
		"absent egress": {
			yaml:             `logging: false`,
			wantUnrestricted: true,
		},
		"null egress": {
			yaml:             `egress: null`,
			wantUnrestricted: true,
		},
		"empty egress list is unrestricted": {
			yaml:             `egress: []`,
			wantUnrestricted: true,
		},
		"empty rule is deny-all": {
			yaml: `
egress:
  - {}
`,
			wantBlocked: true,
		},
		"rules with selectors": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := terrarium.ParseConfig(t.Context(), []byte(tt.yaml))
			require.NoError(t, err)
			assert.Equal(t, tt.wantUnrestricted, cfg.IsEgressUnrestricted())
			assert.Equal(t, tt.wantBlocked, cfg.IsEgressBlocked())
		})
	}
}

func TestEmptyRuleWithFQDNSemantics(t *testing.T) {
	t.Parallel()

	// Empty rule + FQDN rule under default-deny: the empty rule
	// contributes nothing (no selectors), but the FQDN rule applies.
	cfg := &terrarium.Config{Egress: egressRules(
		terrarium.EgressRule{},
		terrarium.EgressRule{
			ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
			ToPorts: []terrarium.PortRule{{
				Ports: []terrarium.Port{{Port: "443"}},
				Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
			}},
		},
	)}

	assert.False(t, cfg.IsEgressUnrestricted(), "empty rule triggers default-deny, not unrestricted")
	assert.False(t, cfg.IsEgressBlocked(), "FQDN sibling prevents blocked state")
	assert.Equal(t, []int{443}, cfg.ResolvePorts(), "FQDN rule contributes ports")
	assert.Equal(t, []string{"api.example.com"}, cfg.ResolveDomains(), "FQDN rule contributes domains")
}

func TestParseTCPForwards(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		yaml string
		want []terrarium.TCPForward
	}{
		"single forward": {
			yaml: `
tcpForwards:
  - port: 22
    host: github.com
`,
			want: []terrarium.TCPForward{{Port: 22, Host: "github.com"}},
		},
		"multiple forwards": {
			yaml: `
tcpForwards:
  - port: 22
    host: github.com
  - port: 3306
    host: db.internal.com
`,
			want: []terrarium.TCPForward{
				{Port: 22, Host: "github.com"},
				{Port: 3306, Host: "db.internal.com"},
			},
		},
		"no forwards": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := terrarium.ParseConfig(t.Context(), []byte(tt.yaml))
			require.NoError(t, err)
			assert.Equal(t, tt.want, cfg.TCPForwards)
		})
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg *terrarium.Config
		err error
	}{
		"valid with forwards": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
				TCPForwards: []terrarium.TCPForward{{Port: 22, Host: "github.com"}},
			},
		},
		"valid no forwards": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"valid FQDN with L7 paths": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Path: "/v1/"},
							{Path: "/v2/"},
						}},
					}},
				}),
			},
		},
		"FQDN selector empty": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{}},
				}),
			},
			err: terrarium.ErrFQDNSelectorEmpty,
		},
		"FQDN without toPorts rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				}),
			},
			err: terrarium.ErrFQDNRequiresPorts,
		},
		"FQDN with empty Ports list rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: terrarium.ErrFQDNRequiresPorts,
		},
		"FQDN with wildcard port 0 rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "0"}},
					}},
				}),
			},
			err: terrarium.ErrFQDNWildcardPort,
		},
		"empty egress rule is valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{}),
			},
		},
		"nil egress is valid": {
			cfg: &terrarium.Config{},
		},
		"empty egress slice is valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(),
			},
		},
		"invalid path regex": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Path: "[unclosed"},
						}},
					}},
				}),
			},
			err: terrarium.ErrPathInvalidRegex,
		},
		"valid regex paths": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Path: "/v1/.*"},
							{Path: "/api/v[12]/.*"},
						}},
					}},
				}),
			},
		},
		"duplicate forward port": {
			cfg: &terrarium.Config{
				TCPForwards: []terrarium.TCPForward{
					{Port: 22, Host: "github.com"},
					{Port: 22, Host: "gitlab.com"},
				},
			},
			err: terrarium.ErrDuplicateTCPForwardPort,
		},
		"forward port conflicts with resolved port": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}},
				}),
				TCPForwards: []terrarium.TCPForward{{Port: 8080, Host: "example.com"}},
			},
			err: terrarium.ErrTCPForwardPortConflict,
		},
		"invalid zero port": {
			cfg: &terrarium.Config{
				TCPForwards: []terrarium.TCPForward{{Port: 0, Host: "example.com"}},
			},
			err: terrarium.ErrInvalidTCPForward,
		},
		"invalid negative port": {
			cfg: &terrarium.Config{
				TCPForwards: []terrarium.TCPForward{{Port: -1, Host: "example.com"}},
			},
			err: terrarium.ErrInvalidTCPForward,
		},
		"invalid empty host": {
			cfg: &terrarium.Config{
				TCPForwards: []terrarium.TCPForward{{Port: 22, Host: ""}},
			},
			err: terrarium.ErrInvalidTCPForward,
		},
		"tcp forwards with blocked egress": {
			cfg: &terrarium.Config{
				Egress:      egressRules(terrarium.EgressRule{}),
				TCPForwards: []terrarium.TCPForward{{Port: 22, Host: "github.com"}},
			},
			err: terrarium.ErrTCPForwardRequiresEgress,
		},
		"port exceeds proxy range": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "50536"}}}},
				}),
			},
			err: terrarium.ErrPortExceedsProxyRange,
		},
		"tcp forward port exceeds proxy range": {
			cfg: &terrarium.Config{
				TCPForwards: []terrarium.TCPForward{{Port: 50536, Host: "example.com"}},
			},
			err: terrarium.ErrPortExceedsProxyRange,
		},
		"valid methods": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Method: "GET"},
							{Method: "POST"},
						}},
					}},
				}),
			},
		},
		"lowercase method is valid regex": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Method: "get"},
						}},
					}},
				}),
			},
		},
		"custom method is valid regex": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Method: "FOOBAR"},
						}},
					}},
				}),
			},
		},
		"method regex pattern": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Method: "GET|POST"},
						}},
					}},
				}),
			},
		},
		"invalid method regex": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Method: "[unclosed"},
						}},
					}},
				}),
			},
			err: terrarium.ErrMethodInvalidRegex,
		},
		"invalid empty method string": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Method: ""},
						}},
					}},
				}),
			},
			// Empty method is allowed (means "all methods").
		},
		"FQDN with toCIDR rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					ToCIDR:  []string{"10.0.0.0/8"},
				}),
			},
			err: terrarium.ErrFQDNWithCIDR,
		},
		"toCIDR with toCIDRSet rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDR:    []string{"10.0.0.0/8"},
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
				}),
			},
			err: terrarium.ErrCIDRAndCIDRSetMixed,
		},
		"toCIDR and toCIDRSet in separate rules valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{ToCIDR: []string{"10.0.0.0/8"}},
					terrarium.EgressRule{ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}}},
				),
			},
		},
		"FQDN with toCIDR and L7 rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToCIDR:  []string{"10.0.0.0/8"},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: terrarium.ErrFQDNWithCIDR,
		},
		"FQDN with toCIDRSet rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs:   []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: terrarium.ErrFQDNWithCIDR,
		},
		"FQDN selector both matchName and matchPattern": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com", MatchPattern: "*.example.com"}},
				}),
			},
			err: terrarium.ErrFQDNSelectorAmbiguous,
		},
		"deep wildcard accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "**.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"triple star wildcard accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "***.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"bare double star accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "**"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"mid-pattern double star accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "test.**.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"bare wildcard accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"bare wildcard with specific ports": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				}),
			},
		},
		"partial wildcard mid-label rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "api.*-staging.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			err: terrarium.ErrFQDNPatternPartialWildcard,
		},
		"partial wildcard suffix rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "example.com.*"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			err: terrarium.ErrFQDNPatternPartialWildcard,
		},
		"multiple wildcards rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.*.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			err: terrarium.ErrFQDNPatternPartialWildcard,
		},
		"valid leading wildcard prefix": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"valid toCIDR": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDR: []string{"10.0.0.0/8"},
				}),
			},
		},
		"bare IPv4 in toCIDR accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDR: []string{"10.0.0.1"},
				}),
			},
		},
		"bare IPv6 in toCIDR accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDR: []string{"fd00::1"},
				}),
			},
		},
		"bare IPv4-mapped IPv6 in toCIDR rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDR: []string{"::ffff:10.0.0.1"},
				}),
			},
			err: terrarium.ErrCIDRIPv4MappedIPv6,
		},
		"IPv4-mapped IPv6 CIDR in toCIDR rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDR: []string{"::ffff:10.0.0.0/104"},
				}),
			},
			err: terrarium.ErrCIDRIPv4MappedIPv6,
		},
		"IPv4-mapped IPv6 parent in toCIDRSet rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "::ffff:10.0.0.0/104"}},
				}),
			},
			err: terrarium.ErrCIDRIPv4MappedIPv6,
		},
		"IPv4-mapped IPv6 except entry rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{
						CIDR:   "fd00::/8",
						Except: []string{"::ffff:10.0.0.0/104"},
					}},
				}),
			},
			err: terrarium.ErrCIDRIPv4MappedIPv6,
		},
		"cross-family except IPv4 parent IPv6 except rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{
						CIDR:   "10.0.0.0/8",
						Except: []string{"fd00::/16"},
					}},
				}),
			},
			err: terrarium.ErrExceptAddressFamilyMismatch,
		},
		"cross-family except IPv6 parent IPv4 except rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{
						CIDR:   "fd00::/8",
						Except: []string{"10.0.0.0/16"},
					}},
				}),
			},
			err: terrarium.ErrExceptAddressFamilyMismatch,
		},
		"invalid toCIDR": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDR: []string{"not-a-cidr"},
				}),
			},
			err: terrarium.ErrCIDRInvalid,
		},
		"valid protocol TCP/UDP/ANY": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{
						{Port: "80", Protocol: "TCP"},
						{Port: "53", Protocol: "UDP"},
						{Port: "443", Protocol: "ANY"},
					}}},
				}),
			},
		},
		"SCTP protocol": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80", Protocol: "SCTP"}}}},
				}),
			},
		},
		"invalid protocol": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80", Protocol: "ICMP"}}}},
				}),
			},
			err: terrarium.ErrProtocolInvalid,
		},
		"valid endPort": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8000", EndPort: 9000}}}},
				}),
			},
		},
		"endPort less than port": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "9000", EndPort: 8000}}}},
				}),
			},
			err: terrarium.ErrEndPortInvalid,
		},
		"endPort with toFQDNs valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8000", EndPort: 9000}}}},
				}),
			},
		},
		"invalid CIDR": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "not-a-cidr"}},
				}),
			},
			err: terrarium.ErrCIDRInvalid,
		},
		"invalid CIDR except": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0", Except: []string{"bad"}}},
				}),
			},
			err: terrarium.ErrCIDRInvalid,
		},
		"valid CIDR rule": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{
						CIDR:   "0.0.0.0/0",
						Except: []string{"10.0.0.0/8", "172.16.0.0/12"},
					}},
				}),
			},
		},
		"port empty string": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: ""}}}},
				}),
			},
			err: terrarium.ErrPortEmpty,
		},
		"port invalid string": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "abc"}}}},
				}),
			},
			err: terrarium.ErrPortInvalid,
		},
		"except not subnet of parent": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{
						CIDR:   "10.0.0.0/8",
						Except: []string{"192.168.0.0/16"},
					}},
				}),
			},
			err: terrarium.ErrExceptNotSubnet,
		},
		"except subnet valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{
						CIDR:   "10.0.0.0/8",
						Except: []string{"10.1.0.0/16"},
					}},
				}),
			},
		},
		"except equal to parent valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{
						CIDR:   "10.0.0.0/8",
						Except: []string{"10.0.0.0/8"},
					}},
				}),
			},
		},
		"except broader than parent": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{
						CIDR:   "10.0.0.0/16",
						Except: []string{"10.0.0.0/8"},
					}},
				}),
			},
			err: terrarium.ErrExceptNotSubnet,
		},
		"except different address family": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{
						CIDR:   "10.0.0.0/8",
						Except: []string{"fd00::/8"},
					}},
				}),
			},
			err: terrarium.ErrExceptAddressFamilyMismatch,
		},
		"L7 on toPorts-only rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: terrarium.ErrL7RequiresFQDN,
		},
		"empty HTTP on toPorts-only valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{}},
					}},
				}),
			},
		},
		"toPorts-only without L7 valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}},
				}),
			},
		},
		"empty ports on non-FQDN rule valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToPorts: []terrarium.PortRule{{}},
				}),
			},
		},
		"empty ports with CIDR valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{}},
				}),
			},
		},
		"wildcard matchPattern with L7 rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: terrarium.ErrWildcardWithL7,
		},
		"wildcard matchPattern without L7 allowed": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"path regex too long rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Path: strings.Repeat("a", 1001)},
						}},
					}},
				}),
			},
			err: terrarium.ErrPathInvalidRegex,
		},
		"except CIDR with host bits uses network base": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{
						CIDR:   "10.0.0.0/8",
						Except: []string{"10.1.2.3/16"},
					}},
				}),
			},
		},
		"lowercase protocol tcp normalized": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "tcp"}}}},
				}),
			},
		},
		"mixed case protocol Tcp normalized": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "Tcp"}}}},
				}),
			},
		},
		"matchName case normalized": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "GitHub.COM"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"matchName trailing dot stripped": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com."}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"matchPattern case normalized": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.Example.COM"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"matchPattern trailing dot stripped": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example.com."}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"matchName only dot rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "."}},
				}),
			},
			err: terrarium.ErrFQDNSelectorEmpty,
		},
		"HTTP host field accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Path: "/v1/", Host: "api\\.example\\.com"},
						}},
					}},
				}),
			},
		},
		"host invalid regex rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Host: "["},
						}},
					}},
				}),
			},
			err: terrarium.ErrHostInvalidRegex,
		},
		"HTTP headers valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Path: "/v1/", Headers: []string{"X-Custom"}},
						}},
					}},
				}),
			},
		},
		"HTTP headers empty name rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Path: "/v1/", Headers: []string{""}},
						}},
					}},
				}),
			},
			err: terrarium.ErrHTTPHeaderEmpty,
		},
		"headerMatches valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{HeaderMatches: []terrarium.HeaderMatch{{Name: "X-Token", Value: "secret"}}},
						}},
					}},
				}),
			},
		},
		"headerMatches empty name rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{HeaderMatches: []terrarium.HeaderMatch{{Name: ""}}},
						}},
					}},
				}),
			},
			err: terrarium.ErrHeaderMatchNameEmpty,
		},
		"headerMatches mismatch action rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{HeaderMatches: []terrarium.HeaderMatch{{Name: "X-Token", Mismatch: terrarium.MismatchLOG}}},
						}},
					}},
				}),
			},
			err: terrarium.ErrHeaderMatchMismatchAction,
		},
		"L7 on port 8443 valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "8443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
		},
		"L7 on port 80 valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "80"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
		},
		"L7 with UDP protocol rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: terrarium.ErrL7RequiresTCP,
		},
		"L7 with SCTP protocol rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "80", Protocol: "SCTP"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: terrarium.ErrL7RequiresTCP,
		},
		"L7 with ANY protocol rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443", Protocol: "ANY"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: terrarium.ErrL7RequiresTCP,
		},
		"L7 with explicit TCP protocol valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443", Protocol: "TCP"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
		},
		"L7 with empty protocol valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
		},
		"L7 with mixed TCP and UDP ports rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{
							{Port: "80", Protocol: "TCP"},
							{Port: "443", Protocol: "UDP"},
						},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: terrarium.ErrL7RequiresTCP,
		},
		"L7 with lowercase udp normalized then rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443", Protocol: "udp"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: terrarium.ErrL7RequiresTCP,
		},
		"empty HTTP rules with UDP protocol valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{}},
					}},
				}),
			},
		},
		"matchName with spaces rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example .com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			err: terrarium.ErrFQDNNameInvalidChars,
		},
		"matchName with colon rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example:8080.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			err: terrarium.ErrFQDNNameInvalidChars,
		},
		"matchName with slash rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com/path"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			err: terrarium.ErrFQDNNameInvalidChars,
		},
		"matchName with semicolon rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example;.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			err: terrarium.ErrFQDNNameInvalidChars,
		},
		"matchPattern with spaces rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example .com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			err: terrarium.ErrFQDNPatternInvalidChars,
		},
		"matchPattern with semicolon rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example;.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			err: terrarium.ErrFQDNPatternInvalidChars,
		},
		"matchPattern with colon rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example:8080.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			err: terrarium.ErrFQDNPatternInvalidChars,
		},
		"matchPattern with slash rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example.com/path"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			err: terrarium.ErrFQDNPatternInvalidChars,
		},
		"matchName exceeding 255 chars rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: strings.Repeat("a", 256)}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			err: terrarium.ErrFQDNTooLong,
		},
		"matchPattern exceeding 255 chars rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*." + strings.Repeat("a", 254)}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			err: terrarium.ErrFQDNTooLong,
		},
		"matchName at exactly 255 chars valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: strings.Repeat("a", 255)}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"matchName with underscore valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "_dmarc.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"matchName with hyphen valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "my-service.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"punycode IDN matchName valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "xn--n3h.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"raw unicode matchName rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "\u2603.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			err: terrarium.ErrFQDNNameInvalidChars,
		},
		"port 0 without L7 accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "0"}}}},
				}),
			},
		},
		"port 0 with FQDN rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "0"}}}},
				}),
			},
			err: terrarium.ErrFQDNWildcardPort,
		},
		"port 0 with FQDN and L7 rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "0"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
			err: terrarium.ErrFQDNWildcardPort,
		},
		"empty ports with L7 rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{
						{Ports: []terrarium.Port{{Port: "443"}}},
						{Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}}},
					},
				}),
			},
			err: terrarium.ErrL7WithWildcardPort,
		},
		"port 0 with endPort silently ignored": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "0", EndPort: 443}}}},
				}),
			},
		},
		"port 0 with UDP accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "0", Protocol: "UDP"}}}},
				}),
			},
		},
		"negative endPort rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", EndPort: -1}}}},
				}),
			},
			err: terrarium.ErrEndPortNegative,
		},
		"more than 40 ports rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(func() terrarium.EgressRule {
					ports := make([]terrarium.Port, 41)
					for i := range ports {
						ports[i] = terrarium.Port{Port: "443"}
					}

					return terrarium.EgressRule{
						ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
						ToPorts:   []terrarium.PortRule{{Ports: ports}},
					}
				}()),
			},
			err: terrarium.ErrPortsTooMany,
		},
		"exactly 40 ports accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(func() terrarium.EgressRule {
					ports := make([]terrarium.Port, 40)
					for i := range ports {
						ports[i] = terrarium.Port{Port: "443"}
					}

					return terrarium.EgressRule{
						ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
						ToPorts:   []terrarium.PortRule{{Ports: ports}},
					}
				}()),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate()
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestTCPForwardHosts(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		forwards []terrarium.TCPForward
		want     []string
	}{
		"deduplicated and sorted": {
			forwards: []terrarium.TCPForward{
				{Port: 22, Host: "github.com"},
				{Port: 3306, Host: "db.example.com"},
				{Port: 5432, Host: "github.com"},
			},
			want: []string{"db.example.com", "github.com"},
		},
		"empty": {},
		"single": {
			forwards: []terrarium.TCPForward{{Port: 22, Host: "gitlab.com"}},
			want:     []string{"gitlab.com"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := &terrarium.Config{TCPForwards: tt.forwards}
			assert.Equal(t, tt.want, cfg.TCPForwardHosts())
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := terrarium.DefaultConfig()

	rules := cfg.EgressRules()
	// Single egress rule with FQDNs only (no CIDRs).
	require.Len(t, rules, 1)
	assert.Empty(t, rules[0].ToCIDRSet)
	assert.NotEmpty(t, rules[0].ToFQDNs)

	// Check some expected domains.
	domains := cfg.ResolveDomains()

	for _, want := range []string{"github.com", "golang.org", "anthropic.com"} {
		assert.Contains(t, domains, want)
	}

	assert.Nil(t, cfg.TCPForwards)
}

func TestResolveDomains(t *testing.T) {
	t.Parallel()

	cfg := &terrarium.Config{
		Egress: egressRules(
			terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{
					{MatchName: "github.com"},
					{MatchName: "extra.com"},
				},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
			},
			terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{
					{MatchName: "github.com"},
				},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
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
		cfg      *terrarium.Config
		want     []terrarium.ResolvedRule
		wantNone bool
	}{
		"simple FQDN rule": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "registry.npmjs.org"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			want: []terrarium.ResolvedRule{{Domain: "registry.npmjs.org"}},
		},
		"FQDN with L7 paths": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{
						{MatchName: "api.example.com"},
						{MatchName: "cdn.example.com"},
					},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Path: "/v1/"},
							{Path: "/v2/"},
						}},
					}},
				}),
			},
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []terrarium.ResolvedHTTPRule{{Path: "/v1/"}, {Path: "/v2/"}}},
				{Domain: "cdn.example.com", HTTPRules: []terrarium.ResolvedHTTPRule{{Path: "/v1/"}, {Path: "/v2/"}}},
			},
		},
		"merge L7 across rules": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []terrarium.PortRule{{
							Ports: []terrarium.Port{{Port: "443"}},
							Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
						}},
					},
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []terrarium.PortRule{{
							Ports: []terrarium.Port{{Port: "443"}},
							Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v2/"}}},
						}},
					},
				),
			},
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []terrarium.ResolvedHTTPRule{{Path: "/v1/"}, {Path: "/v2/"}}},
			},
		},
		"plain L4 wins over L7 paths": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []terrarium.PortRule{{
							Ports: []terrarium.Port{{Port: "443"}},
							Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
						}},
					},
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
				),
			},
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com"},
			},
		},
		"deduplicate paths": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Path: "/v1/"},
							{Path: "/v1/"},
						}},
					}},
				}),
			},
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []terrarium.ResolvedHTTPRule{{Path: "/v1/"}}},
			},
		},
		"methods merge across rules": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []terrarium.PortRule{{
							Ports: []terrarium.Port{{Port: "443"}},
							Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Method: "GET"}}},
						}},
					},
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []terrarium.PortRule{{
							Ports: []terrarium.Port{{Port: "443"}},
							Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Method: "POST"}}},
						}},
					},
				),
			},
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []terrarium.ResolvedHTTPRule{{Method: "GET"}, {Method: "POST"}}},
			},
		},
		"plain L4 wins over methods": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []terrarium.PortRule{{
							Ports: []terrarium.Port{{Port: "443"}},
							Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Method: "GET"}}},
						}},
					},
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
				),
			},
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com"},
			},
		},
		"dedup methods": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Method: "GET"},
							{Method: "GET"},
						}},
					}},
				}),
			},
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []terrarium.ResolvedHTTPRule{{Method: "GET"}}},
			},
		},
		"paths and methods paired": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Path: "/v1/", Method: "GET"},
							{Path: "/v1/", Method: "POST"},
						}},
					}},
				}),
			},
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []terrarium.ResolvedHTTPRule{
					{Method: "GET", Path: "/v1/"},
					{Method: "POST", Path: "/v1/"},
				}},
			},
		},
		"HTTP rules are paired not cross-producted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
							{Method: "GET", Path: "/api"},
							{Method: "POST", Path: "/submit"},
						}},
					}},
				}),
			},
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []terrarium.ResolvedHTTPRule{
					{Method: "GET", Path: "/api"},
					{Method: "POST", Path: "/submit"},
				}},
			},
		},
		"CIDR-only rule skipped": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}}},
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
				),
			},
			want: []terrarium.ResolvedRule{{Domain: "example.com"}},
		},
		"matchPattern used as domain": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			want: []terrarium.ResolvedRule{{Domain: "*.example.com"}},
		},
		"nil egress returns empty": {
			cfg:      &terrarium.Config{},
			wantNone: true,
		},
		"empty egress returns empty": {
			cfg:      &terrarium.Config{Egress: egressRules()},
			wantNone: true,
		},
		"empty HTTP propagates as unrestricted through ResolveRules": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{}},
					}},
				}),
			},
			want: []terrarium.ResolvedRule{{Domain: "api.example.com"}},
		},
		"cross-domain L7 isolation": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []terrarium.PortRule{{
							Ports: []terrarium.Port{{Port: "443"}},
							Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{
								{Method: "GET", Path: "/v1/"},
							}},
						}},
					},
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "cdn.example.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
				),
			},
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []terrarium.ResolvedHTTPRule{
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
		cfg      *terrarium.Config
		port     int
		want     []terrarium.ResolvedRule
		wantNone bool
	}{
		"domain scoped to port 443 only - matching": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "github.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
			})},
			port: 443,
			want: []terrarium.ResolvedRule{{Domain: "github.com"}},
		},
		"domain scoped to port 443 only - non-matching": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "github.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
			})},
			port:     80,
			wantNone: true,
		},
		"domain with multiple ports matches each": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "github.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}, {Port: "8080"}}}},
			})},
			port: 8080,
			want: []terrarium.ResolvedRule{{Domain: "github.com"}},
		},
		"per-port L7 scoping": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "8080"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v2/"}}},
					}},
				},
			)},
			port: 443,
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []terrarium.ResolvedHTTPRule{{Path: "/v1/"}}},
			},
		},
		"per-port L7 scoping - other port": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "8080"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v2/"}}},
					}},
				},
			)},
			port: 8080,
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []terrarium.ResolvedHTTPRule{{Path: "/v2/"}}},
			},
		},
		"same domain same port merges L7": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v2/"}}},
					}},
				},
			)},
			port: 443,
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []terrarium.ResolvedHTTPRule{{Path: "/v1/"}, {Path: "/v2/"}}},
			},
		},
		"empty Ports list matches all ports": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{
					{Ports: []terrarium.Port{{Port: "443"}}},
					{Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}}},
				},
			})},
			port: 9999,
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []terrarium.ResolvedHTTPRule{{Path: "/v1/"}}},
			},
		},
		"plain L4 nullifies sibling L7 on same port": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{
					{Ports: []terrarium.Port{{Port: "443"}}},
					{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Method: "GET"}}},
					},
				},
			})},
			port: 443,
			want: []terrarium.ResolvedRule{{Domain: "api.example.com"}},
		},
		"ANY plain L4 nullifies TCP L7 on same port": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{
					{Ports: []terrarium.Port{{Port: "443"}}},
					{
						Ports: []terrarium.Port{{Port: "443", Protocol: "TCP"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/api"}}},
					},
				},
			})},
			port: 443,
			want: []terrarium.ResolvedRule{{Domain: "api.example.com"}},
		},
		"UDP plain L4 does not nullify TCP L7 on same port": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{
					{Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}}},
					{
						Ports: []terrarium.Port{{Port: "443", Protocol: "TCP"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/api"}}},
					},
				},
			})},
			port: 443,
			want: []terrarium.ResolvedRule{
				{Domain: "api.example.com", HTTPRules: []terrarium.ResolvedHTTPRule{{Path: "/api"}}},
			},
		},
		"TCP plain L4 still nullifies TCP L7 on same port": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{
					{Ports: []terrarium.Port{{Port: "443", Protocol: "TCP"}}},
					{
						Ports: []terrarium.Port{{Port: "443", Protocol: "TCP"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/api"}}},
					},
				},
			})},
			port: 443,
			want: []terrarium.ResolvedRule{{Domain: "api.example.com"}},
		},
		"toPorts-only rule excluded": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}},
			})},
			port:     8080,
			wantNone: true,
		},
		"mixed rules per port": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "always.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "80"}, {Port: "443"}}}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "only443.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				},
			)},
			port: 80,
			want: []terrarium.ResolvedRule{{Domain: "always.com"}},
		},
		"empty HTTP list produces unrestricted rule": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "443"}},
					Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{}},
				}},
			})},
			port: 443,
			want: []terrarium.ResolvedRule{{Domain: "api.example.com"}},
		},
		"empty HTTP merged with L7 rules is unrestricted": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{}},
					}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				},
			)},
			port: 443,
			want: []terrarium.ResolvedRule{{Domain: "api.example.com"}},
		},
		"empty HTTP plus plain L4 is unrestricted": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "443"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{}},
					}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				},
			)},
			port: 443,
			want: []terrarium.ResolvedRule{{Domain: "api.example.com"}},
		},
		"rules nil HTTP is plain L4": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{
					Ports: []terrarium.Port{{Port: "443"}},
					Rules: &terrarium.L7Rules{},
				}},
			})},
			port: 443,
			want: []terrarium.ResolvedRule{{Domain: "api.example.com"}},
		},
		"separate FQDN and CIDR rules contribute domains": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				},
				terrarium.EgressRule{
					ToCIDR:  []string{"10.0.0.0/8"},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				},
			)},
			port: 443,
			want: []terrarium.ResolvedRule{{Domain: "api.example.com"}},
		},
		"endPort range matches port within range": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "400", EndPort: 500}}}},
			})},
			port: 450,
			want: []terrarium.ResolvedRule{{Domain: "api.example.com"}},
		},
		"endPort range does not match port outside range": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "400", EndPort: 500}}}},
			})},
			port:     501,
			wantNone: true,
		},
		"endPort range matches start port": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "400", EndPort: 500}}}},
			})},
			port: 400,
			want: []terrarium.ResolvedRule{{Domain: "api.example.com"}},
		},
		"endPort range matches end port": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "400", EndPort: 500}}}},
			})},
			port: 500,
			want: []terrarium.ResolvedRule{{Domain: "api.example.com"}},
		},
		"deep wildcard preserves double-star domain": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "**.example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
			})},
			port: 443,
			want: []terrarium.ResolvedRule{{Domain: "**.example.com"}},
		},
		"bare double star resolves as single star": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "**"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
			})},
			port: 443,
			want: []terrarium.ResolvedRule{{Domain: "*"}},
		},
		"port 0 matches all target ports": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "wildcard.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "0"}}}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "specific.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				},
			)},
			port: 443,
			want: []terrarium.ResolvedRule{
				{Domain: "specific.example.com"},
				{Domain: "wildcard.example.com"},
			},
		},
		"port 0 matches non-standard ports": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "wildcard.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "0"}}}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "specific.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}},
				},
			)},
			port: 8080,
			want: []terrarium.ResolvedRule{
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
		cfg  *terrarium.Config
		want []int
	}{
		"toPorts-only rule produces open ports": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}},
			})},
			want: []int{8080},
		},
		"rule with toFQDNs not open": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}},
			})},
		},
		"rule with toCIDRSet not open": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
				ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}},
			})},
		},
		"rule with toCIDR not open": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToCIDR:  []string{"0.0.0.0/0"},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}},
			})},
		},
		"no toPorts-only rules": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
			})},
		},
		"multiple open ports": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}, {Port: "9090"}}}},
			})},
			want: []int{8080, 9090},
		},
		"mixed open and domain rules": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				},
				terrarium.EgressRule{ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "3000"}}}}},
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
		cfg  *terrarium.Config
		want []terrarium.ResolvedOpenPort
	}{
		"TCP open port": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080", Protocol: "TCP"}}}},
			})},
			want: []terrarium.ResolvedOpenPort{{Port: 8080, Protocol: "tcp"}},
		},
		"UDP open port": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "5353", Protocol: "UDP"}}}},
			})},
			want: []terrarium.ResolvedOpenPort{{Port: 5353, Protocol: "udp"}},
		},
		"SCTP open port": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "3868", Protocol: "SCTP"}}}},
			})},
			want: []terrarium.ResolvedOpenPort{{Port: 3868, Protocol: "sctp"}},
		},
		"ANY protocol open port expands": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080", Protocol: "ANY"}}}},
			})},
			want: []terrarium.ResolvedOpenPort{
				{Port: 8080, Protocol: "tcp"},
				{Port: 8080, Protocol: "udp"},
			},
		},
		"empty protocol open port expands": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}},
			})},
			want: []terrarium.ResolvedOpenPort{
				{Port: 8080, Protocol: "tcp"},
				{Port: 8080, Protocol: "udp"},
			},
		},
		"rule with toFQDNs not open": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}},
			})},
		},
		"TCP open port with endPort": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8000", EndPort: 9000, Protocol: "TCP"}}}},
			})},
			want: []terrarium.ResolvedOpenPort{
				{Port: 8000, EndPort: 9000, Protocol: "tcp"},
			},
		},
		"UDP open port with endPort": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "5000", EndPort: 6000, Protocol: "UDP"}}}},
			})},
			want: []terrarium.ResolvedOpenPort{
				{Port: 5000, EndPort: 6000, Protocol: "udp"},
			},
		},
		"ANY protocol open port with endPort expands": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8000", EndPort: 9000}}}},
			})},
			want: []terrarium.ResolvedOpenPort{
				{Port: 8000, EndPort: 9000, Protocol: "tcp"},
				{Port: 8000, EndPort: 9000, Protocol: "udp"},
			},
		},
		"endPort equal to port": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8000", EndPort: 8000, Protocol: "TCP"}}}},
			})},
			want: []terrarium.ResolvedOpenPort{
				{Port: 8000, EndPort: 8000, Protocol: "tcp"},
			},
		},
		"dedup across rules with same range": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToPorts: []terrarium.PortRule{
						{Ports: []terrarium.Port{{Port: "8000", EndPort: 9000, Protocol: "TCP"}}},
					},
				},
				terrarium.EgressRule{
					ToPorts: []terrarium.PortRule{
						{Ports: []terrarium.Port{{Port: "8000", EndPort: 9000, Protocol: "TCP"}}},
					},
				},
			)},
			want: []terrarium.ResolvedOpenPort{
				{Port: 8000, EndPort: 9000, Protocol: "tcp"},
			},
		},
		"mixed single and range for same start port": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8000", Protocol: "TCP"}}}},
				},
				terrarium.EgressRule{
					ToPorts: []terrarium.PortRule{
						{Ports: []terrarium.Port{{Port: "8000", EndPort: 9000, Protocol: "TCP"}}},
					},
				},
			)},
			want: []terrarium.ResolvedOpenPort{
				{Port: 8000, Protocol: "tcp"},
				{Port: 8000, EndPort: 9000, Protocol: "tcp"},
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
		cfg  *terrarium.Config
		want bool
	}{
		"empty Ports list is unrestricted": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{}},
			})},
			want: true,
		},
		"port 0 counts as unrestricted": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "0"}}}},
			})},
			want: true,
		},
		"specific port is not unrestricted": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
			})},
			want: false,
		},
		"FQDN rule with port 0 not unrestricted": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "0"}}}},
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
		cfg  *terrarium.Config
		want []terrarium.FQDNRulePorts
	}{
		"FQDN UDP port": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}}}},
			})},
			want: []terrarium.FQDNRulePorts{
				{RuleIndex: 0, Ports: []terrarium.ResolvedOpenPort{{Port: 443, Protocol: "udp"}}},
			},
		},
		"FQDN SCTP port": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "3868", Protocol: "SCTP"}}}},
			})},
			want: []terrarium.FQDNRulePorts{
				{RuleIndex: 0, Ports: []terrarium.ResolvedOpenPort{{Port: 3868, Protocol: "sctp"}}},
			},
		},
		"FQDN ANY port expands to udp": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
			})},
			want: []terrarium.FQDNRulePorts{
				{RuleIndex: 0, Ports: []terrarium.ResolvedOpenPort{{Port: 443, Protocol: "udp"}}},
			},
		},
		"FQDN TCP-only returns nil": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "TCP"}}}},
			})},
		},
		"CIDR rule with UDP returns nil": {
			cfg: &terrarium.Config{Egress: egressRules(terrarium.EgressRule{
				ToCIDRSet: []terrarium.CIDRRule{{CIDR: "8.8.8.0/24"}},
				ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "53", Protocol: "UDP"}}}},
			})},
		},
		"unrestricted returns nil": {
			cfg: &terrarium.Config{},
		},
		"two FQDN rules get separate indices": {
			cfg: &terrarium.Config{Egress: egressRules(
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "a.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}}}},
				},
				terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "b.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080", Protocol: "UDP"}}}},
				},
			)},
			want: []terrarium.FQDNRulePorts{
				{RuleIndex: 0, Ports: []terrarium.ResolvedOpenPort{{Port: 443, Protocol: "udp"}}},
				{RuleIndex: 1, Ports: []terrarium.ResolvedOpenPort{{Port: 8080, Protocol: "udp"}}},
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

func TestIsDefaultDenyEnabled(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *terrarium.Config
		want bool
	}{
		"nil egress": {
			cfg: &terrarium.Config{},
		},
		"empty egress": {
			cfg: &terrarium.Config{Egress: egressRules()},
		},
		"rules present": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
			want: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.cfg.IsDefaultDenyEnabled())
		})
	}
}

func TestResolvePorts(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *terrarium.Config
		want []int
	}{
		"explicit ports": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{
						{Port: "80"},
						{Port: "443"},
						{Port: "8080"},
					}}},
				}),
			},
			want: []int{80, 443, 8080},
		},
		"FQDN with explicit ports": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				}),
			},
			want: []int{80, 443},
		},
		"nil egress returns nil": {
			cfg: &terrarium.Config{},
		},
		"empty egress returns nil": {
			cfg: &terrarium.Config{Egress: egressRules()},
		},
		"deduplication": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "a.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "b.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
				),
			},
			want: []int{443},
		},
		"toCIDR-only rule excluded from ports": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToCIDR:  []string{"10.0.0.0/8"},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}},
					},
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
				),
			},
			want: []int{443},
		},
		"CIDR-only rule excluded from ports": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
						ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080"}}}},
					},
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
				),
			},
			want: []int{443},
		},
		"empty rule returns nil ports": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{}),
			},
		},
		"CIDR-only rule returns nil": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
				}),
			},
		},
		"UDP-only port excluded": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{
						{Port: "443", Protocol: "TCP"},
						{Port: "5353", Protocol: "UDP"},
					}}},
				}),
			},
			want: []int{443},
		},
		"SCTP-only port excluded": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{
						{Port: "443", Protocol: "TCP"},
						{Port: "3868", Protocol: "SCTP"},
					}}},
				}),
			},
			want: []int{443},
		},
		"ANY protocol port included": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{
						{Port: "8080", Protocol: "ANY"},
					}}},
				}),
			},
			want: []int{8080},
		},
		"separate FQDN and CIDR rules contribute FQDN ports": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
					terrarium.EgressRule{
						ToCIDR:  []string{"10.0.0.0/8"},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
				),
			},
			want: []int{443},
		},
		"open-port range excluded from Envoy listeners": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToPorts: []terrarium.PortRule{
							{Ports: []terrarium.Port{{Port: "8000", EndPort: 9000, Protocol: "TCP"}}},
						},
					},
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
				),
			},
			want: []int{443},
		},
		"open-port single port included in Envoy listeners": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080", Protocol: "TCP"}}}},
					},
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
				),
			},
			want: []int{443, 8080},
		},
		"port 0 does not appear in resolved ports": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "0"}}}},
				}),
			},
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
		cfg  *terrarium.Config
		want []int
	}{
		"extra ports present": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{
						{Port: "80"}, {Port: "443"}, {Port: "8080"}, {Port: "9090"},
					}}},
				}),
			},
			want: []int{8080, 9090},
		},
		"no extra ports": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{
						{Port: "80"}, {Port: "443"},
					}}},
				}),
			},
		},
		"nil egress": {
			cfg: &terrarium.Config{},
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
		cfg      *terrarium.Config
		validate bool
		wantIPv4 []terrarium.ResolvedCIDR
		wantIPv6 []terrarium.ResolvedCIDR
	}{
		"mixed IPv4 and IPv6": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{
						{CIDR: "0.0.0.0/0", Except: []string{"10.0.0.0/8", "172.16.0.0/12"}},
						{CIDR: "::/0", Except: []string{"fc00::/7"}},
					},
				}),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "0.0.0.0/0", Except: []string{"10.0.0.0/8", "172.16.0.0/12"}},
			},
			wantIPv6: []terrarium.ResolvedCIDR{
				{CIDR: "::/0", Except: []string{"fc00::/7"}},
			},
		},
		"no CIDR rules": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
		"port-scoped CIDR": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "8.8.8.0/24"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}, {Port: "80"}}}},
				}),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "8.8.8.0/24", Ports: []terrarium.ResolvedPortProto{
					{Port: 80, Protocol: "tcp"},
					{Port: 80, Protocol: "udp"},
					{Port: 443, Protocol: "tcp"},
					{Port: 443, Protocol: "udp"},
				}},
			},
		},
		"empty Ports list means any port": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "8.8.8.0/24"}},
					ToPorts:   []terrarium.PortRule{{Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}}}},
				}),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "8.8.8.0/24"},
			},
		},
		"no toPorts means any port": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "8.8.8.0/24"}},
				}),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "8.8.8.0/24"},
			},
		},
		"multiple rules with different ports": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToCIDRSet: []terrarium.CIDRRule{{CIDR: "8.8.8.0/24"}},
						ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "53"}}}},
					},
					terrarium.EgressRule{
						ToCIDRSet: []terrarium.CIDRRule{{CIDR: "1.1.1.0/24"}},
						ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
				),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "8.8.8.0/24", Ports: []terrarium.ResolvedPortProto{
					{Port: 53, Protocol: "tcp"},
					{Port: 53, Protocol: "udp"},
				}, RuleIndex: 0},
				{CIDR: "1.1.1.0/24", Ports: []terrarium.ResolvedPortProto{
					{Port: 443, Protocol: "tcp"},
					{Port: 443, Protocol: "udp"},
				}, RuleIndex: 1},
			},
		},
		"toCIDR without except": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDR: []string{"8.8.8.0/24"},
				}),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "8.8.8.0/24"},
			},
		},
		"toCIDR and toCIDRSet in same rule share RuleIndex": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDR:    []string{"10.0.0.0/8"},
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "192.168.0.0/16", Except: []string{"192.168.1.0/24"}}},
				}),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "10.0.0.0/8", RuleIndex: 0},
				{CIDR: "192.168.0.0/16", Except: []string{"192.168.1.0/24"}, RuleIndex: 0},
			},
		},
		"toCIDR and toCIDRSet in separate rules": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{ToCIDR: []string{"1.1.1.0/24"}},
					terrarium.EgressRule{
						ToCIDRSet: []terrarium.CIDRRule{{CIDR: "8.8.8.0/24", Except: []string{"8.8.8.8/32"}}},
					},
				),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "1.1.1.0/24", RuleIndex: 0},
				{CIDR: "8.8.8.0/24", Except: []string{"8.8.8.8/32"}, RuleIndex: 1},
			},
		},
		"UDP port-scoped CIDR": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "8.8.8.0/24"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "53", Protocol: "UDP"}}}},
				}),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "8.8.8.0/24", Ports: []terrarium.ResolvedPortProto{{Port: 53, Protocol: "udp"}}},
			},
		},
		"ANY protocol CIDR": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "8.8.8.0/24"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "53", Protocol: "ANY"}}}},
				}),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "8.8.8.0/24", Ports: []terrarium.ResolvedPortProto{
					{Port: 53, Protocol: "tcp"},
					{Port: 53, Protocol: "udp"},
				}},
			},
		},
		"port range propagated": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "8.8.8.0/24"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8000", EndPort: 9000}}}},
				}),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "8.8.8.0/24", Ports: []terrarium.ResolvedPortProto{
					{Port: 8000, EndPort: 9000, Protocol: "tcp"},
					{Port: 8000, EndPort: 9000, Protocol: "udp"},
				}},
			},
		},
		// IPv4-mapped IPv6 CIDRs are now rejected at validation time
		// (ErrCIDRIPv4MappedIPv6), so they never reach ResolveCIDRRules.
		// See TestValidate for the rejection tests.
		"separate FQDN and CIDR rules contribute CIDRs": {
			cfg: &terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
					terrarium.EgressRule{
						ToCIDR:  []string{"10.0.0.0/8"},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
					},
				),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "10.0.0.0/8", Ports: []terrarium.ResolvedPortProto{
					{Port: 443, Protocol: "tcp"},
					{Port: 443, Protocol: "udp"},
				}, RuleIndex: 0},
			},
		},
		"port 0 CIDR rule has no port restriction": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "10.0.0.0/8"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "0"}}}},
				}),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "10.0.0.0/8"},
			},
		},
		"ANY omits SCTP": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "8.8.8.0/24"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "53"}}}},
				}),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "8.8.8.0/24", Ports: []terrarium.ResolvedPortProto{
					{Port: 53, Protocol: "tcp"},
					{Port: 53, Protocol: "udp"},
				}},
			},
		},
		"explicit SCTP preserved": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "8.8.8.0/24"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "3868", Protocol: "SCTP"}}}},
				}),
			},
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "8.8.8.0/24", Ports: []terrarium.ResolvedPortProto{
					{Port: 3868, Protocol: "sctp"},
				}},
			},
		},
		"bare IPv4 toCIDR normalizes to /32": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDR: []string{"8.8.8.8"},
				}),
			},
			validate: true,
			wantIPv4: []terrarium.ResolvedCIDR{
				{CIDR: "8.8.8.8/32"},
			},
		},
		"bare IPv6 toCIDR normalizes to /128": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDR: []string{"fd00::1"},
				}),
			},
			validate: true,
			wantIPv6: []terrarium.ResolvedCIDR{
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

func TestResolvePort(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input string
		want  uint16
		err   bool
	}{
		"numeric":            {input: "443", want: 443},
		"numeric zero":       {input: "0", want: 0},
		"named https":        {input: "https", want: 443},
		"named http":         {input: "http", want: 80},
		"named dns":          {input: "dns", want: 53},
		"named domain":       {input: "domain", want: 53},
		"named dns-tcp":      {input: "dns-tcp", want: 53},
		"case insensitive":   {input: "HTTP", want: 80},
		"mixed case":         {input: "Https", want: 443},
		"unknown name":       {input: "redis", err: true},
		"invalid syntax":     {input: "abc!!", err: true},
		"leading hyphen":     {input: "-http", err: true},
		"trailing hyphen":    {input: "http-", err: true},
		"consecutive hyphen": {input: "dns--tcp", err: true},
		"empty":              {input: "", err: true},
		"digits only":        {input: "123", want: 123},
		"port 65535":         {input: "65535", want: 65535},
		"port 65536":         {input: "65536", err: true},
		"port 70000":         {input: "70000", err: true},
		"large port":         {input: "100000", err: true},
		"negative":           {input: "-1", err: true},
		"negative zero":      {input: "-0", err: true},
		"hex rejected":       {input: "0x1BB", err: true},
		"octal rejected":     {input: "0o777", err: true},
		"max int rejected":   {input: "2147483647", err: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := terrarium.ResolvePort(tt.input)
			if tt.err {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestNamedPortValidation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg *terrarium.Config
		err error
	}{
		"named port https accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "https"}}}},
				}),
			},
		},
		"named port http accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "http"}}}},
				}),
			},
		},
		"named port dns accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "dns"}}}},
				}),
			},
		},
		"named port domain accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "domain"}}}},
				}),
			},
		},
		"unknown named port rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "redis"}}}},
				}),
			},
			err: terrarium.ErrPortInvalid,
		},
		"invalid syntax rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "abc!!"}}}},
				}),
			},
			err: terrarium.ErrPortInvalid,
		},
		"negative port rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "-1"}}}},
				}),
			},
			err: terrarium.ErrPortInvalid,
		},
		"endPort with named port silently ignored": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "https", EndPort: 500}}}},
				}),
			},
		},
		"L7 on named port http accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "http"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
		},
		"L7 on named port https accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "https"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
		},
		"L7 on named port dns valid": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "dns.example.com"}},
					ToPorts: []terrarium.PortRule{{
						Ports: []terrarium.Port{{Port: "dns"}},
						Rules: &terrarium.L7Rules{HTTP: []terrarium.HTTPRule{{Path: "/v1/"}}},
					}},
				}),
			},
		},
		"uppercase named port normalized": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "HTTPS"}}}},
				}),
			},
		},
		"port 65536 rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "65536"}}}},
				}),
			},
			err: terrarium.ErrPortInvalid,
		},
		"port 70000 rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "70000"}}}},
				}),
			},
			err: terrarium.ErrPortInvalid,
		},
		"port 65535 accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "65535"}}}},
				}),
			},
		},
		"endPort 70000 rejected": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", EndPort: 70000}}}},
				}),
			},
			err: terrarium.ErrEndPortInvalid,
		},
		"port 0 accepted": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToCIDRSet: []terrarium.CIDRRule{{CIDR: "0.0.0.0/0"}},
					ToPorts:   []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "0"}}}},
				}),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := tt.cfg.Validate()
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestNamedPortResolution(t *testing.T) {
	t.Parallel()

	t.Run("ResolvePorts with named port", func(t *testing.T) {
		t.Parallel()

		cfg := &terrarium.Config{
			Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "https"}}}},
			}),
		}
		require.NoError(t, cfg.Validate())
		assert.Equal(t, []int{443}, cfg.ResolvePorts())
	})

	t.Run("ResolveOpenPorts with named port", func(t *testing.T) {
		t.Parallel()

		cfg := &terrarium.Config{
			Egress: egressRules(terrarium.EgressRule{
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "http"}}}},
			}),
		}
		require.NoError(t, cfg.Validate())
		assert.Equal(t, []int{80}, cfg.ResolveOpenPorts())
	})

	t.Run("ResolveRulesForPort with named port", func(t *testing.T) {
		t.Parallel()

		cfg := &terrarium.Config{
			Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "https"}}}},
			}),
		}
		require.NoError(t, cfg.Validate())

		rules := cfg.ResolveRulesForPort(443)
		require.Len(t, rules, 1)
		assert.Equal(t, "example.com", rules[0].Domain)
	})

	t.Run("case insensitivity in resolution", func(t *testing.T) {
		t.Parallel()

		cfg := &terrarium.Config{
			Egress: egressRules(terrarium.EgressRule{
				ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
				ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "HTTPS"}}}},
			}),
		}
		require.NoError(t, cfg.Validate())
		assert.Equal(t, []int{443}, cfg.ResolvePorts())
	})
}

func TestUnsupportedSelectors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		yaml      string
		err       error
		wantRules int
	}{
		"toEndpoints rejected": {
			yaml: `
egress:
  - toEndpoints:
      - matchLabels:
          role: backend
    toPorts:
      - ports:
          - port: "443"
`,
			err: terrarium.ErrUnsupportedSelector,
		},
		"toEntities world rejected": {
			yaml: `
egress:
  - toEntities:
      - world
`,
			err: terrarium.ErrUnsupportedSelector,
		},
		"toServices rejected": {
			yaml: `
egress:
  - toServices:
      - k8sService:
          serviceName: my-svc
          namespace: default
`,
			err: terrarium.ErrUnsupportedSelector,
		},
		"toNodes rejected": {
			yaml: `
egress:
  - toNodes:
      - matchLabels:
          node-role: worker
`,
			err: terrarium.ErrUnsupportedSelector,
		},
		"toGroups rejected": {
			yaml: `
egress:
  - toGroups:
      - aws:
          securityGroupsIds:
            - sg-123
`,
			err: terrarium.ErrUnsupportedSelector,
		},
		"toRequires rejected": {
			yaml: `
egress:
  - toRequires:
      - something
`,
			err: terrarium.ErrUnsupportedSelector,
		},
		"icmps rejected": {
			yaml: `
egress:
  - icmps:
      - fields:
          - type: 8
`,
			err: terrarium.ErrUnsupportedSelector,
		},
		"authentication rejected": {
			yaml: `
egress:
  - authentication:
      mode: required
`,
			err: terrarium.ErrUnsupportedSelector,
		},
		"empty toEntities not rejected": {
			yaml: `
egress:
  - toEntities: []
    toCIDR:
      - 10.0.0.0/8
`,
			wantRules: 1,
		},
		"null toEntities not rejected": {
			yaml: `
egress:
  - toEntities: null
    toCIDR:
      - 10.0.0.0/8
`,
			wantRules: 1,
		},
		"absent toEntities not rejected": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
`,
			wantRules: 1,
		},
		"error message includes field name and rule index": {
			yaml: `
egress:
  - toCIDR:
      - 10.0.0.0/8
  - toEntities:
      - world
`,
			err: terrarium.ErrUnsupportedSelector,
		},
		"unknown field rejected at parse time": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
    someFutureField: true
`,
		},
		"unknown top-level field rejected": {
			yaml: `
egressPolicy:
  - toFQDNs:
      - matchName: example.com
`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := terrarium.ParseConfig(t.Context(), []byte(tt.yaml))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}

			if tt.wantRules > 0 {
				require.NoError(t, err)
				assert.Len(t, cfg.EgressRules(), tt.wantRules)

				return
			}

			// Unknown field cases: expect a parse error (not a sentinel)
			require.Error(t, err)
		})
	}

	// Verify the error message format includes field name and rule index.
	t.Run("error format", func(t *testing.T) {
		t.Parallel()

		_, err := terrarium.ParseConfig(t.Context(), []byte(`
egress:
  - toCIDR:
      - 10.0.0.0/8
  - toEntities:
      - world
`))
		require.ErrorIs(t, err, terrarium.ErrUnsupportedSelector)
		assert.ErrorContains(t, err, "rule 1 has toEntities")
	})
}

func TestUnsupportedFeatures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		yaml string
		err  error
	}{
		"terminatingTLS rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        terminatingTLS:
          secret:
            name: my-secret
`,
			err: terrarium.ErrUnsupportedFeature,
		},
		"originatingTLS rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        originatingTLS:
          secret:
            name: my-secret
`,
			err: terrarium.ErrUnsupportedFeature,
		},
		"serverNames rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        serverNames:
          - example.com
`,
			err: terrarium.ErrUnsupportedFeature,
		},
		"listener rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        listener:
          envoyConfig:
            name: my-listener
`,
			err: terrarium.ErrUnsupportedFeature,
		},
		"cidrGroupRef rejected": {
			yaml: `
egress:
  - toCIDRSet:
      - cidr: 10.0.0.0/8
        cidrGroupRef: my-cidr-group
`,
			err: terrarium.ErrUnsupportedFeature,
		},
		"cidrGroupSelector rejected": {
			yaml: `
egress:
  - toCIDRSet:
      - cidr: 10.0.0.0/8
        cidrGroupSelector:
          matchLabels:
            env: prod
`,
			err: terrarium.ErrUnsupportedFeature,
		},
		"kafka L7 rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: kafka.example.com
    toPorts:
      - ports:
          - port: "9092"
        rules:
          kafka:
            - topic: my-topic
`,
			err: terrarium.ErrUnsupportedFeature,
		},
		"dns L7 rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: dns.example.com
    toPorts:
      - ports:
          - port: "53"
        rules:
          dns:
            - matchPattern: "*.example.com"
`,
			err: terrarium.ErrUnsupportedFeature,
		},
		"l7proto rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        rules:
          l7proto: envoy.filters.network.my_filter
`,
			err: terrarium.ErrUnsupportedFeature,
		},
		"l7 generic rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        rules:
          l7:
            - action: allow
`,
			err: terrarium.ErrUnsupportedFeature,
		},
		"empty serverNames not rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        serverNames: []
`,
		},
		"null terminatingTLS not rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        terminatingTLS: null
`,
		},
		"empty kafka not rejected": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
        rules:
          kafka: []
`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := terrarium.ParseConfig(t.Context(), []byte(tt.yaml))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)

				return
			}

			require.NoError(t, err)
		})
	}

	// Verify the error message format includes field name and rule index.
	t.Run("error format includes context", func(t *testing.T) {
		t.Parallel()

		_, err := terrarium.ParseConfig(t.Context(), []byte(`
egress:
  - toCIDR:
      - 10.0.0.0/8
  - toCIDRSet:
      - cidr: 10.0.0.0/8
        cidrGroupRef: my-group
`))
		require.ErrorIs(t, err, terrarium.ErrUnsupportedFeature)
		require.ErrorContains(t, err, "rule 1")
		require.ErrorContains(t, err, "cidrGroupRef")
	})
}

func TestMarshalConfigRoundtrip(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg              *terrarium.Config
		wantUnrestricted bool
		wantBlocked      bool
	}{
		"nil egress roundtrips as unrestricted": {
			cfg:              &terrarium.Config{},
			wantUnrestricted: true,
		},
		"empty egress roundtrips as unrestricted": {
			cfg:              &terrarium.Config{Egress: egressRules()},
			wantUnrestricted: true,
		},
		"empty rule roundtrips as blocked": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{}),
			},
			wantBlocked: true,
		},
		"rules roundtrip": {
			cfg: &terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443"}}}},
				}),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data, err := terrarium.MarshalConfig(tt.cfg)
			require.NoError(t, err)

			cfg2, err := terrarium.ParseConfig(t.Context(), data)
			require.NoError(t, err)
			assert.Equal(t, tt.wantUnrestricted, cfg2.IsEgressUnrestricted())
			assert.Equal(t, tt.wantBlocked, cfg2.IsEgressBlocked())
		})
	}
}

func TestCompileFQDNPatterns(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg         terrarium.Config
		want        []string
		wantIndices []int
		match       map[string]bool
		noMatch     map[string]bool
	}{
		"matchName exact": {
			cfg: terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"api.example.com"},
			wantIndices: []int{0},
			match:       map[string]bool{"api.example.com.": true},
			noMatch:     map[string]bool{"evil.api.example.com.": true, "example.com.": true},
		},
		"single-star wildcard": {
			cfg: terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"*.example.com"},
			wantIndices: []int{0},
			match:       map[string]bool{"sub.example.com.": true},
			noMatch:     map[string]bool{"a.b.example.com.": true, "example.com.": true},
		},
		"double-star wildcard": {
			cfg: terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "**.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"**.example.com"},
			wantIndices: []int{0},
			match:       map[string]bool{"sub.example.com.": true, "a.b.example.com.": true},
			noMatch:     map[string]bool{"example.com.": true},
		},
		"bare wildcard": {
			cfg: terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "*"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"*"},
			wantIndices: []int{0},
			match:       map[string]bool{"anything.com.": true, "a.b.c.": true, ".": true},
			noMatch:     map[string]bool{"": true},
		},
		"triple-star bare wildcard": {
			cfg: terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "***"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"***"},
			wantIndices: []int{0},
			match:       map[string]bool{"anything.com.": true, ".": true},
		},
		"triple-star suffix wildcard": {
			cfg: terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "***.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"***.example.com"},
			wantIndices: []int{0},
			match:       map[string]bool{"sub.example.com.": true, "a.b.example.com.": true},
			noMatch:     map[string]bool{"example.com.": true},
		},
		"mid-position double-star falls back to single-label": {
			cfg: terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchPattern: "test.**.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"test.**.example.com"},
			wantIndices: []int{0},
			match:       map[string]bool{"test.sub.example.com.": true},
			noMatch:     map[string]bool{"test.a.b.example.com.": true},
		},
		"excludes TCPForward hosts": {
			cfg: terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
				TCPForwards: []terrarium.TCPForward{{Port: 22, Host: "git.example.com"}},
			},
			want:        []string{"api.example.com"},
			wantIndices: []int{0},
		},
		"same pattern in two rules produces two entries": {
			cfg: terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}}}},
					},
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "api.example.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "8080", Protocol: "UDP"}}}},
					},
				),
			},
			want:        []string{"api.example.com", "api.example.com"},
			wantIndices: []int{0, 1},
		},
		"deduplicates within same rule": {
			cfg: terrarium.Config{
				Egress: egressRules(terrarium.EgressRule{
					ToFQDNs: []terrarium.FQDNSelector{
						{MatchName: "api.example.com"},
						{MatchName: "api.example.com"},
					},
					ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "UDP"}}}},
				}),
			},
			want:        []string{"api.example.com"},
			wantIndices: []int{0},
		},
		"skips TCP-only FQDN rules": {
			cfg: terrarium.Config{
				Egress: egressRules(
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "tcp-only.example.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "443", Protocol: "TCP"}}}},
					},
					terrarium.EgressRule{
						ToFQDNs: []terrarium.FQDNSelector{{MatchName: "udp.example.com"}},
						ToPorts: []terrarium.PortRule{{Ports: []terrarium.Port{{Port: "5353", Protocol: "UDP"}}}},
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
