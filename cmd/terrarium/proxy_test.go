package main

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoy"
)

// parseProxyConfig parses a policy YAML for proxy bootstrap tests.
func parseProxyConfig(t *testing.T, yamlCfg string) *config.Config {
	t.Helper()

	cfg, err := config.ParseConfig(t.Context(), []byte(yamlCfg))
	require.NoError(t, err)

	return cfg
}

func TestGenerateProxyEnvoyFromConfig(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		yaml         string
		certsDir     string
		caBundlePath string
		want         []string
		wantAbsent   []string
		err          error
		useResolvers bool
	}{
		"fqdn only": {
			caBundlePath: "/etc/ssl/bundle.pem",
			yaml: "egress:\n" +
				"  - toFQDNs:\n" +
				"      - matchName: example.com\n" +
				"    toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"443\"\n",
			want: []string{
				"example.com:443",
				"connect_matcher:",
				"connect_config:",
				"name: tls_internal_443",
				"internal_listener:",
				"server_listener_name: tls_internal_443",
				"envoy.bootstrap.internal_listener",
				"sni_dynamic_forward_proxy",
				"status: 403",
			},
			wantAbsent: []string{
				"http_internal",
				"port_value: 53",
			},
		},
		"l7 restricted": {
			yaml: "egress:\n" +
				"  - toFQDNs:\n" +
				"      - matchName: api.example.com\n" +
				"    toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"443\"\n" +
				"        rules:\n" +
				"          http:\n" +
				"            - path: /v1/.*\n" +
				"              method: GET\n",
			certsDir:     "/state/certs",
			caBundlePath: "/etc/ssl/bundle.pem",
			want: []string{
				"/state/certs/api.example.com/cert.pem",
				"regex: /v1/.*",
				"name: mitm_forward_proxy_cluster",
				"trusted_ca:",
				"filename: /etc/ssl/bundle.pem",
			},
		},
		"l7 restricted without CA bundle": {
			yaml: "egress:\n" +
				"  - toFQDNs:\n" +
				"      - matchName: api.example.com\n" +
				"    toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"443\"\n" +
				"        rules:\n" +
				"          http:\n" +
				"            - path: /v1/.*\n" +
				"              method: GET\n",
			certsDir: "/state/certs",
			err:      envoy.ErrMITMCABundleMissing,
		},
		"port 80 rules": {
			caBundlePath: "/etc/ssl/bundle.pem",
			yaml: "egress:\n" +
				"  - toFQDNs:\n" +
				"      - matchName: plain.example.com\n" +
				"    toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"80\"\n",
			want: []string{
				"plain.example.com:80",
				"name: http_internal",
				"server_listener_name: http_internal",
				"regex: ^[^:]+(:80)?$",
			},
			wantAbsent: []string{
				"tls_internal_443",
			},
		},
		"open port": {
			caBundlePath: "/etc/ssl/bundle.pem",
			yaml: "egress:\n" +
				"  - toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"8443\"\n",
			want: []string{
				`"*:8443"`,
				"name: tls_internal_8443",
			},
		},
		"blocked": {
			yaml: "egress: []\n",
			want: []string{
				"name: deny",
				"status: 403",
			},
			wantAbsent: []string{
				"internal_listener:",
				"envoy.bootstrap.internal_listener",
				"dynamic_forward_proxy",
			},
		},
		"unrestricted": {
			yaml: "{}\n",
			want: []string{
				"name: open",
				"connect_config:",
				"cluster: dynamic_forward_proxy_cluster",
			},
			wantAbsent: []string{
				"internal_listener:",
				"status: 403",
			},
		},
		"unrestricted open ports override l7": {
			yaml: "egress:\n" +
				"  - toPorts:\n" +
				"      - {}\n",
			want: []string{
				"name: open",
			},
			wantAbsent: []string{
				"internal_listener:",
			},
		},
		"deny rules rejected": {
			yaml: "egress:\n" +
				"  - toFQDNs:\n" +
				"      - matchName: example.com\n" +
				"egressDeny:\n" +
				"  - toCIDR:\n" +
				"      - 10.0.0.0/8\n",
			err: ErrDenyRulesUnsupported,
		},
		"explicit resolvers": {
			caBundlePath: "/etc/ssl/bundle.pem",
			yaml: "egress:\n" +
				"  - toFQDNs:\n" +
				"      - matchName: example.com\n" +
				"    toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"443\"\n",
			useResolvers: true,
			want: []string{
				"address: 10.9.8.7",
				"port_value: 5353",
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := parseProxyConfig(t, tt.yaml)

			var resolvers []netip.AddrPort

			if tt.useResolvers {
				resolvers = []netip.AddrPort{netip.MustParseAddrPort("10.9.8.7:5353")}
			}

			out, err := GenerateProxyEnvoyFromConfig(
				t.Context(), cfg, tt.certsDir, tt.caBundlePath,
				"127.0.0.1", 8080, resolvers,
			)

			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)

				return
			}

			require.NoError(t, err)

			for _, want := range tt.want {
				assert.Contains(t, out, want)
			}

			for _, absent := range tt.wantAbsent {
				assert.NotContains(t, out, absent)
			}
		})
	}
}

func TestGenerateProxyEnvoyFromConfigDeterministic(t *testing.T) {
	t.Parallel()

	yamlCfg := "egress:\n" +
		"  - toFQDNs:\n" +
		"      - matchName: a.example.com\n" +
		"      - matchName: b.example.com\n" +
		"    toPorts:\n" +
		"      - ports:\n" +
		"          - port: \"443\"\n" +
		"          - port: \"8443\"\n" +
		"          - port: \"9443\"\n" +
		"          - port: \"80\"\n"

	cfg := parseProxyConfig(t, yamlCfg)

	first, err := GenerateProxyEnvoyFromConfig(
		t.Context(), cfg, "", "", "127.0.0.1", 8080, nil)
	require.NoError(t, err)

	for range 10 {
		out, err := GenerateProxyEnvoyFromConfig(
			t.Context(), cfg, "", "", "127.0.0.1", 8080, nil)
		require.NoError(t, err)
		assert.Equal(t, first, out)
	}
}

func TestParseResolvers(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		resolvers []string
		want      int
		wantErr   bool
	}{
		"empty":     {resolvers: nil, want: 0},
		"valid":     {resolvers: []string{"1.1.1.1:53", "[::1]:5353"}, want: 2},
		"no port":   {resolvers: []string{"1.1.1.1"}, wantErr: true},
		"not an ip": {resolvers: []string{"dns.example.com:53"}, wantErr: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := parseResolvers(tt.resolvers)

			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Len(t, got, tt.want)
		})
	}
}
