package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
)

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
		"FQDN without toPorts accepted": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
`,
			wantRules: 1,
		},
		"FQDN with wildcard port 0 accepted": {
			yaml: `
egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "0"
`,
			wantRules: 1,
		},
		"FQDN selector empty": {
			yaml: `
egress:
  - toFQDNs:
      - {}
`,
			err: config.ErrFQDNSelectorEmpty,
		},
		"empty egress rule is valid (deny-all)": {
			yaml: `
egress:
  - {}
`,
			wantRules: 1,
		},
		"absent egress means unrestricted": {
			yaml:      `{}`,
			wantRules: 0,
		},
		"empty egress list parses as blocked": {
			yaml:      `egress: []`,
			wantRules: 0,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.ParseConfig(t.Context(), []byte(tt.yaml))
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				return
			}

			require.NoError(t, err)

			if tt.wantRules > 0 {
				assert.Len(t, cfg.EgressRules(), tt.wantRules)
			}

			domains := cfg.ResolveDomains(t.Context())

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
			yaml:             `{}`,
			wantUnrestricted: true,
		},
		"null egress": {
			yaml:             `egress: null`,
			wantUnrestricted: true,
		},
		"empty egress list is blocked": {
			yaml:        `egress: []`,
			wantBlocked: true,
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
		"egressDeny only activates default-deny": {
			yaml: `
egressDeny:
  - toCIDR:
      - 10.0.0.0/8
`,
			wantBlocked: true,
		},
		"empty egressDeny list is blocked": {
			yaml:        `egressDeny: []`,
			wantBlocked: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.ParseConfig(t.Context(), []byte(tt.yaml))
			require.NoError(t, err)
			assert.Equal(t, tt.wantUnrestricted, cfg.IsEgressUnrestricted())
			assert.Equal(t, tt.wantBlocked, cfg.IsEgressBlocked())
		})
	}
}

func TestParseTCPForwards(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		yaml string
		want []config.TCPForward
	}{
		"single forward": {
			yaml: `
tcpForwards:
  - port: 22
    host: github.com
`,
			want: []config.TCPForward{{Port: 22, Host: "github.com"}},
		},
		"multiple forwards": {
			yaml: `
tcpForwards:
  - port: 22
    host: github.com
  - port: 3306
    host: db.internal.com
`,
			want: []config.TCPForward{
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

			cfg, err := config.ParseConfig(t.Context(), []byte(tt.yaml))
			require.NoError(t, err)
			assert.Equal(t, tt.want, cfg.TCPForwards)
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := config.DefaultConfig()

	rules := cfg.EgressRules()
	// Single egress rule with FQDNs only (no CIDRs).
	require.Len(t, rules, 1)
	assert.Empty(t, rules[0].ToCIDRSet)
	assert.NotEmpty(t, rules[0].ToFQDNs)

	// Check some expected domains.
	domains := cfg.ResolveDomains(t.Context())

	for _, want := range []string{"github.com", "golang.org", "anthropic.com"} {
		assert.Contains(t, domains, want)
	}

	assert.Nil(t, cfg.TCPForwards)
}

func TestMarshalConfigRoundtrip(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg              *config.Config
		wantUnrestricted bool
		wantBlocked      bool
	}{
		"nil egress roundtrips as unrestricted": {
			cfg:              &config.Config{},
			wantUnrestricted: true,
		},
		"empty egress roundtrips as blocked": {
			cfg:         &config.Config{Egress: egressRules()},
			wantBlocked: true,
		},
		"empty rule roundtrips as blocked": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{}),
			},
			wantBlocked: true,
		},
		"rules roundtrip": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
				}),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			data, err := config.MarshalConfig(tt.cfg)
			require.NoError(t, err)

			cfg2, err := config.ParseConfig(t.Context(), data)
			require.NoError(t, err)
			assert.Equal(t, tt.wantUnrestricted, cfg2.IsEgressUnrestricted())
			assert.Equal(t, tt.wantBlocked, cfg2.IsEgressBlocked())
		})
	}
}

func TestParseEnvoySettings(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		yaml string
		want config.EnvoySettings
	}{
		"all fields": {
			yaml: `
envoy:
  drainTimeout: "10s"
  startupTimeout: "30s"
  maxDownstreamConnections: 1024
`,
			want: config.EnvoySettings{
				DrainTimeout:             config.Duration{Duration: 10 * time.Second},
				StartupTimeout:           config.Duration{Duration: 30 * time.Second},
				MaxDownstreamConnections: 1024,
				UDPIdleTimeout:           config.Duration{Duration: config.DefaultEnvoyUDPIdleTimeout},
			},
		},
		"partial fields use defaults": {
			yaml: `
envoy:
  drainTimeout: "5s"
`,
			want: config.EnvoySettings{
				DrainTimeout:             config.Duration{Duration: 5 * time.Second},
				StartupTimeout:           config.Duration{Duration: config.DefaultEnvoyStartupTimeout},
				MaxDownstreamConnections: config.DefaultEnvoyMaxDownstreamConnections,
				UDPIdleTimeout:           config.Duration{Duration: config.DefaultEnvoyUDPIdleTimeout},
			},
		},
		"absent envoy uses all defaults": {
			yaml: `{}`,
			want: config.EnvoySettings{
				DrainTimeout:             config.Duration{Duration: config.DefaultEnvoyDrainTimeout},
				StartupTimeout:           config.Duration{Duration: config.DefaultEnvoyStartupTimeout},
				MaxDownstreamConnections: config.DefaultEnvoyMaxDownstreamConnections,
				UDPIdleTimeout:           config.Duration{Duration: config.DefaultEnvoyUDPIdleTimeout},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.ParseConfig(t.Context(), []byte(tt.yaml))
			require.NoError(t, err)
			assert.Equal(t, tt.want, cfg.EnvoyDefaults())
		})
	}
}
