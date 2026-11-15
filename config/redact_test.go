package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
)

// headerMatchPolicy holds header values in two egress rules and in
// several HTTP rules. The value of each entry that has one starts
// with "hunter2".
const headerMatchPolicy = `
egress:
  - toFQDNs:
      - matchName: first.example.com
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
  - toFQDNs:
      - matchName: api.example.com
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
        rules:
          http:
            - method: GET
              path: /v1/.*
              headerMatches:
                - name: Authorization
                  value: hunter2-add
                  mismatch: ADD
                - name: X-Token
                  value: hunter2-replace
                  mismatch: REPLACE
                - name: X-Present
            - method: POST
              headerMatches:
                - name: X-Plain
                  value: hunter2-plain
      - ports:
          - port: "8443"
            protocol: TCP
        rules:
          http:
            - headerMatches:
                - name: X-Other
                  value: hunter2-other
                  mismatch: LOG
  - toCIDR:
      - 192.0.2.0/24
egressDeny:
  - toCIDR:
      - 198.51.100.0/24
  - toCIDR:
      - 203.0.113.0/24
`

func TestConfig_Redacted(t *testing.T) {
	t.Parallel()

	cfg, err := config.ParseConfig(t.Context(), []byte(headerMatchPolicy))
	require.NoError(t, err)

	// A second parse gives a config that the call cannot reach.
	untouched, err := config.ParseConfig(t.Context(), []byte(headerMatchPolicy))
	require.NoError(t, err)

	redacted := cfg.Redacted()

	assert.Equal(t, untouched, cfg, "Redacted changed its receiver")

	data, err := config.MarshalConfig(redacted)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "hunter2")

	// The redacted document is a valid policy.
	parsed, err := config.ParseConfig(t.Context(), data)
	require.NoError(t, err)
	assert.Equal(t, redacted, parsed)

	// The redacted config differs from the source only in the
	// values. Every rule keeps its index.
	matches := func(c *config.Config, rule, port, http int) []config.HeaderMatch {
		return (*c.Egress)[rule].ToPorts[port].Rules.HTTP[http].HeaderMatches
	}

	assert.Equal(t, []config.HeaderMatch{
		{Name: "Authorization", Value: config.RedactedValue, Mismatch: config.MismatchADD},
		{Name: "X-Token", Value: config.RedactedValue, Mismatch: config.MismatchREPLACE},
		{Name: "X-Present"},
	}, matches(redacted, 1, 0, 0))
	assert.Equal(t, []config.HeaderMatch{
		{Name: "X-Plain", Value: config.RedactedValue},
	}, matches(redacted, 1, 0, 1))
	assert.Equal(t, []config.HeaderMatch{
		{Name: "X-Other", Value: config.RedactedValue, Mismatch: config.MismatchLOG},
	}, matches(redacted, 1, 1, 0))

	for _, at := range [][3]int{{1, 0, 0}, {1, 0, 1}, {1, 1, 0}} {
		got := matches(redacted, at[0], at[1], at[2])
		for i := range got {
			got[i].Value = matches(cfg, at[0], at[1], at[2])[i].Value
		}
	}

	assert.Equal(t, cfg, redacted, "Redacted changed more than the header values")
}

// TestConfig_Redacted_RoundTrip checks the document that the stats
// event store holds for a policy. [config.ParseConfig] must read it
// back as the config that the process applied.
func TestConfig_Redacted_RoundTrip(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		yaml             string
		wantUnrestricted bool
		wantBlocked      bool
	}{
		"no egress": {
			yaml:             "{}\n",
			wantUnrestricted: true,
		},
		"empty egress": {
			yaml:        "egress: []\n",
			wantBlocked: true,
		},
		"empty rule": {
			yaml:        "egress:\n  - {}\n",
			wantBlocked: true,
		},
		"deny rules only": {
			yaml: `
egressDeny:
  - toCIDR:
      - 198.51.100.0/24
`,
			wantBlocked: true,
		},
		"filtered": {
			yaml: `
egress:
  - toEntities:
      - world
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
  - toFQDNs:
      - matchName: API.Example.com
      - matchPattern: "*.example.org"
    toPorts:
      - ports:
          - port: "443"
          - port: "8000"
            endPort: 8010
            protocol: TCP
        rules:
          http:
            - method: GET|POST
              path: /v1/.*
              host: api\.example\.com
              headers:
                - X-Request-ID
              headerMatches:
                - name: X-Present
  - toCIDRSet:
      - cidr: 10.0.0.0/8
        except:
          - 10.1.0.0/16
    toPorts:
      - ports:
          - port: "53"
            protocol: UDP
  - toCIDR:
      - 192.0.2.1/32
    icmps:
      - fields:
          - family: IPv4
            type: 8
egressDeny:
  - toEntities:
      - world
    toPorts:
      - ports:
          - port: "25"
            protocol: TCP
  - toCIDR:
      - 203.0.113.0/24
envoy:
  drainTimeout: 7s
  maxDownstreamConnections: 100
logging:
  dns:
    enabled: true
stats:
  enabled: true
  retention:
    maxAge: 48h
    maxRows: 1000
tcpForwards:
  - host: db.example.com
    port: 5432
`,
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := config.ParseConfig(t.Context(), []byte(tc.yaml))
			require.NoError(t, err)

			data, err := config.MarshalConfig(cfg.Redacted())
			require.NoError(t, err)

			got, err := config.ParseConfig(t.Context(), data)
			require.NoError(t, err, "stored document:\n%s", data)

			assert.Equal(t, cfg, got, "stored document:\n%s", data)
			assert.Equal(t, cfg.EgressRules(), got.EgressRules())
			assert.Equal(t, cfg.EgressDenyRules(), got.EgressDenyRules())
			assert.Equal(t, tc.wantUnrestricted, got.IsEgressUnrestricted())
			assert.Equal(t, tc.wantBlocked, got.IsEgressBlocked())
		})
	}
}

// TestConfig_Redacted_WithoutHeaderMatches checks that the copy of a
// config without header values equals the config. A nil slice must
// stay nil and an empty slice must stay empty, because the two mean
// different policies.
func TestConfig_Redacted_WithoutHeaderMatches(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		cfg *config.Config
	}{
		"zero config": {cfg: &config.Config{}},
		"empty egress": {
			cfg: &config.Config{Egress: egressRules()},
		},
		"rules without HTTP": {
			cfg: &config.Config{
				Egress: egressRules(
					config.EgressRule{},
					config.EgressRule{
						ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
						ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
					},
				),
				EgressDeny: egressDenyRules(config.EgressDenyRule{ToCIDR: []string{"10.0.0.0/8"}}),
			},
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := tc.cfg.Redacted()

			assert.NotSame(t, tc.cfg, got)
			assert.Equal(t, tc.cfg, got)
		})
	}
}
