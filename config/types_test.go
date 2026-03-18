package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
)

func TestEmptyRuleWithFQDNSemantics(t *testing.T) {
	t.Parallel()

	// Empty rule + FQDN rule under default-deny: the empty rule
	// contributes nothing (no selectors), but the FQDN rule applies.
	cfg := &config.Config{Egress: egressRules(
		config.EgressRule{},
		config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
			ToPorts: []config.PortRule{{
				Ports: []config.Port{{Port: "443"}},
				Rules: &config.L7Rules{HTTP: []config.HTTPRule{{Path: "/v1/"}}},
			}},
		},
	)}

	assert.False(t, cfg.IsEgressUnrestricted(), "empty rule triggers default-deny, not unrestricted")
	assert.False(t, cfg.IsEgressBlocked(), "FQDN sibling prevents blocked state")
	assert.Equal(t, []int{443}, cfg.ResolvePorts(t.Context()), "FQDN rule contributes ports")
	assert.Equal(t, []string{"api.example.com"}, cfg.ResolveDomains(t.Context()), "FQDN rule contributes domains")
}

func TestIsDefaultDenyEnabled(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *config.Config
		want bool
	}{
		"nil egress": {
			cfg: &config.Config{},
		},
		"empty egress": {
			cfg: &config.Config{Egress: egressRules()},
		},
		"rules present": {
			cfg: &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
					ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
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

func TestEnvoyDefaults(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *config.Config
		want config.EnvoySettings
	}{
		"nil envoy returns all defaults": {
			cfg: &config.Config{},
			want: config.EnvoySettings{
				LogLevel:                 config.DefaultEnvoyLogLevel,
				DrainTimeout:             config.Duration{Duration: config.DefaultEnvoyDrainTimeout},
				StartupTimeout:           config.Duration{Duration: config.DefaultEnvoyStartupTimeout},
				MaxDownstreamConnections: config.DefaultEnvoyMaxDownstreamConnections,
				UDPIdleTimeout:           config.Duration{Duration: config.DefaultEnvoyUDPIdleTimeout},
			},
		},
		"partial override fills remaining defaults": {
			cfg: &config.Config{
				Envoy: &config.EnvoySettings{
					LogLevel: "debug",
				},
			},
			want: config.EnvoySettings{
				LogLevel:                 "debug",
				DrainTimeout:             config.Duration{Duration: config.DefaultEnvoyDrainTimeout},
				StartupTimeout:           config.Duration{Duration: config.DefaultEnvoyStartupTimeout},
				MaxDownstreamConnections: config.DefaultEnvoyMaxDownstreamConnections,
				UDPIdleTimeout:           config.Duration{Duration: config.DefaultEnvoyUDPIdleTimeout},
			},
		},
		"full override returns user values": {
			cfg: &config.Config{
				Envoy: &config.EnvoySettings{
					LogLevel:                 "info",
					DrainTimeout:             config.Duration{Duration: 30 * time.Second},
					StartupTimeout:           config.Duration{Duration: 20 * time.Second},
					MaxDownstreamConnections: 1024,
					UDPIdleTimeout:           config.Duration{Duration: 120 * time.Second},
				},
			},
			want: config.EnvoySettings{
				LogLevel:                 "info",
				DrainTimeout:             config.Duration{Duration: 30 * time.Second},
				StartupTimeout:           config.Duration{Duration: 20 * time.Second},
				MaxDownstreamConnections: 1024,
				UDPIdleTimeout:           config.Duration{Duration: 120 * time.Second},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.cfg.EnvoyDefaults())
		})
	}
}

func TestDurationUnmarshalYAML(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input string
		want  time.Duration
		err   bool
	}{
		"seconds":      {input: "5s", want: 5 * time.Second},
		"minutes":      {input: "1m30s", want: 90 * time.Second},
		"milliseconds": {input: "100ms", want: 100 * time.Millisecond},
		"invalid":      {input: "not-a-duration", err: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var d config.Duration

			err := d.UnmarshalYAML(func(v any) error {
				ptr, ok := v.(*string)
				require.True(t, ok)

				*ptr = tt.input

				return nil
			})
			if tt.err {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, d.Duration)
		})
	}
}
