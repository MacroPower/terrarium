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
			cfg:  &config.Config{Egress: egressRules()},
			want: true,
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
		"deny rules only": {
			cfg: &config.Config{
				EgressDeny: egressDenyRules(config.EgressDenyRule{
					ToCIDR: []string{"10.0.0.0/8"},
				}),
			},
			want: true,
		},
		"empty deny list only": {
			cfg:  &config.Config{EgressDeny: egressDenyRules()},
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

func TestDenyOnlySemantics(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		EgressDeny: egressDenyRules(config.EgressDenyRule{
			ToCIDR: []string{"10.0.0.0/8"},
		}),
	}

	assert.True(t, cfg.IsDefaultDenyEnabled(), "deny rules activate default-deny")
	assert.False(t, cfg.IsEgressUnrestricted(), "deny rules are not unrestricted")
	assert.True(t, cfg.IsEgressBlocked(), "deny-only config with no allow rules is blocked")
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
				DrainTimeout:             config.Duration{Duration: config.DefaultEnvoyDrainTimeout},
				StartupTimeout:           config.Duration{Duration: config.DefaultEnvoyStartupTimeout},
				MaxDownstreamConnections: config.DefaultEnvoyMaxDownstreamConnections,
				UDPIdleTimeout:           config.Duration{Duration: config.DefaultEnvoyUDPIdleTimeout},
			},
		},
		"partial override fills remaining defaults": {
			cfg: &config.Config{
				Envoy: &config.EnvoySettings{
					DrainTimeout: config.Duration{Duration: 15 * time.Second},
				},
			},
			want: config.EnvoySettings{
				DrainTimeout:             config.Duration{Duration: 15 * time.Second},
				StartupTimeout:           config.Duration{Duration: config.DefaultEnvoyStartupTimeout},
				MaxDownstreamConnections: config.DefaultEnvoyMaxDownstreamConnections,
				UDPIdleTimeout:           config.Duration{Duration: config.DefaultEnvoyUDPIdleTimeout},
			},
		},
		"full override returns user values": {
			cfg: &config.Config{
				Envoy: &config.EnvoySettings{
					DrainTimeout:             config.Duration{Duration: 30 * time.Second},
					StartupTimeout:           config.Duration{Duration: 20 * time.Second},
					MaxDownstreamConnections: 1024,
					UDPIdleTimeout:           config.Duration{Duration: 120 * time.Second},
				},
			},
			want: config.EnvoySettings{
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

func TestLoggingConvenienceMethods(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg                  *config.Config
		wantFirewall         bool
		wantDNS              bool
		wantDNSFormat        string
		wantDNSPath          string
		wantAccessLog        bool
		wantEnvoyLevel       string
		wantAccessLogFormat  string
		wantEnvoyPath        string
		wantAccessLogPath    string
		envoyPathFallback    string
		accessLogPathFallack string
	}{
		"nil logging": {
			cfg:                  &config.Config{},
			wantDNSFormat:        "logfmt",
			wantDNSPath:          "/dev/stderr",
			wantEnvoyLevel:       "warning",
			wantAccessLogFormat:  "logfmt",
			wantEnvoyPath:        "/fallback/envoy.log",
			wantAccessLogPath:    "/fallback/access.log",
			envoyPathFallback:    "/fallback/envoy.log",
			accessLogPathFallack: "/fallback/access.log",
		},
		"empty logging": {
			cfg:                  &config.Config{Logging: &config.LoggingConfig{}},
			wantDNSFormat:        "logfmt",
			wantDNSPath:          "/dev/stderr",
			wantEnvoyLevel:       "warning",
			wantAccessLogFormat:  "logfmt",
			wantEnvoyPath:        "/fallback/envoy.log",
			wantAccessLogPath:    "/fallback/access.log",
			envoyPathFallback:    "/fallback/envoy.log",
			accessLogPathFallack: "/fallback/access.log",
		},
		"fully populated": {
			cfg: &config.Config{Logging: &config.LoggingConfig{
				DNS: &config.DNSLogging{
					Enabled: true, Format: "json", Path: "/var/log/dns.log",
				},
				Envoy: &config.EnvoyLogging{
					Level: "debug",
					Path:  "/var/log/envoy.log",
					AccessLog: &config.EnvoyAccessLog{
						Enabled: true, Format: "json", Path: "/var/log/access.log",
					},
				},
				Firewall: &config.FirewallLogging{Enabled: true},
			}},
			wantFirewall:         true,
			wantDNS:              true,
			wantDNSFormat:        "json",
			wantDNSPath:          "/var/log/dns.log",
			wantAccessLog:        true,
			wantEnvoyLevel:       "debug",
			wantAccessLogFormat:  "json",
			wantEnvoyPath:        "/var/log/envoy.log",
			wantAccessLogPath:    "/var/log/access.log",
			envoyPathFallback:    "/ignored",
			accessLogPathFallack: "/ignored",
		},
		"yaml path overrides fallback": {
			cfg: &config.Config{Logging: &config.LoggingConfig{
				Envoy: &config.EnvoyLogging{
					Path:      "/yaml/envoy.log",
					AccessLog: &config.EnvoyAccessLog{Path: "/yaml/access.log"},
				},
			}},
			wantDNSFormat:        "logfmt",
			wantDNSPath:          "/dev/stderr",
			wantEnvoyLevel:       "warning",
			wantAccessLogFormat:  "logfmt",
			wantEnvoyPath:        "/yaml/envoy.log",
			wantAccessLogPath:    "/yaml/access.log",
			envoyPathFallback:    "/cli/envoy.log",
			accessLogPathFallack: "/cli/access.log",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.wantFirewall, tt.cfg.FirewallLoggingEnabled())
			assert.Equal(t, tt.wantDNS, tt.cfg.DNSLoggingEnabled())
			assert.Equal(t, tt.wantDNSFormat, tt.cfg.DNSLogFormat())
			assert.Equal(t, tt.wantDNSPath, tt.cfg.DNSLogPath())
			assert.Equal(t, tt.wantAccessLog, tt.cfg.EnvoyAccessLogEnabled())
			assert.Equal(t, tt.wantEnvoyLevel, tt.cfg.EnvoyLogLevel())
			assert.Equal(t, tt.wantAccessLogFormat, tt.cfg.EnvoyAccessLogFormat())
			assert.Equal(t, tt.wantEnvoyPath, tt.cfg.EnvoyLogPath(tt.envoyPathFallback))
			assert.Equal(t, tt.wantAccessLogPath, tt.cfg.EnvoyAccessLogPath(tt.accessLogPathFallack))
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
