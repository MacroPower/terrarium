package main

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/certs"
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

func TestExportCA(t *testing.T) {
	t.Parallel()

	const caPEM = "-----BEGIN CERTIFICATE-----\nMITM\n-----END CERTIFICATE-----\n"

	tests := map[string]struct {
		roots       string
		existing    string
		wantCAOut   string
		wantBundle  string
		err         error
		noCA        bool
		noRoots     bool
		noCAOut     bool
		noBundleOut bool
	}{
		"MITM CA": {
			roots:      "ROOTS\n",
			wantCAOut:  caPEM,
			wantBundle: "ROOTS\n" + caPEM,
		},
		"roots without a trailing newline": {
			roots:      "ROOTS",
			wantCAOut:  caPEM,
			wantBundle: "ROOTS\n" + caPEM,
		},
		"no MITM CA": {
			roots:      "ROOTS\n",
			noCA:       true,
			wantBundle: "ROOTS\n",
		},
		"replaces an existing bundle": {
			roots:      "ROOTS\n",
			existing:   "STALE\n",
			wantCAOut:  caPEM,
			wantBundle: "ROOTS\n" + caPEM,
		},
		"no system bundle": {
			noRoots: true,
			err:     ErrSystemCABundleMissing,
		},
		"no system bundle without a bundle output": {
			noRoots:     true,
			noBundleOut: true,
			wantCAOut:   caPEM,
		},
		"no outputs": {
			roots:       "ROOTS\n",
			noCAOut:     true,
			noBundleOut: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			caPath := ""
			if !tt.noCA {
				caPath = filepath.Join(dir, "ca.pem")
				require.NoError(t, os.WriteFile(caPath, []byte(caPEM), 0o600))
			}

			systemBundle := ""
			if !tt.noRoots {
				systemBundle = filepath.Join(dir, "roots.pem")
				require.NoError(t, os.WriteFile(systemBundle, []byte(tt.roots), 0o600))
			}

			opts := proxyOptions{}
			if !tt.noCAOut {
				opts.caOut = filepath.Join(dir, "out", "ca.pem")
			}

			if !tt.noBundleOut {
				opts.caBundleOut = filepath.Join(dir, "out", "bundle.pem")
			}

			if tt.existing != "" {
				require.NoError(t, os.MkdirAll(filepath.Dir(opts.caBundleOut), 0o755))
				require.NoError(t, os.WriteFile(opts.caBundleOut, []byte(tt.existing), 0o600))
			}

			err := exportCA(t.Context(), caPath, systemBundle, opts)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)

				return
			}

			require.NoError(t, err)

			assertExported(t, opts.caOut, tt.wantCAOut)
			assertExported(t, opts.caBundleOut, tt.wantBundle)

			entries, err := os.ReadDir(filepath.Join(dir, "out"))
			if err == nil {
				for _, e := range entries {
					assert.NotContains(t, e.Name(), ".tmp-", "temp file left behind")
				}
			}
		})
	}
}

// assertExported checks that path holds want with mode 0o644, or that
// path does not exist when want is empty.
func assertExported(t *testing.T, path, want string) {
	t.Helper()

	if path == "" {
		return
	}

	if want == "" {
		_, err := os.Stat(path)
		require.ErrorIs(t, err, os.ErrNotExist)

		return
	}

	got, err := os.ReadFile(path) //nolint:gosec // test fixture path.
	require.NoError(t, err)
	assert.Equal(t, want, string(got))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())
}

func TestGenerateProxyReusesCA(t *testing.T) {
	t.Parallel()

	if certs.FindCABundle() == "" {
		t.Skip("no system CA bundle")
	}

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte("egress:\n"+
		"  - toFQDNs:\n"+
		"      - matchName: example.com\n"+
		"    toPorts:\n"+
		"      - ports:\n"+
		"          - port: \"443\"\n"+
		"        rules:\n"+
		"          http:\n"+
		"            - method: GET\n"), 0o600))

	usr := &config.User{
		ConfigPath:      policyPath,
		CADir:           filepath.Join(dir, "ca"),
		CertsDir:        filepath.Join(dir, "certs"),
		EnvoyConfigPath: filepath.Join(dir, "envoy.yaml"),
	}
	opts := proxyOptions{
		bindAddress: "127.0.0.1",
		httpPort:    8080,
		caOut:       filepath.Join(dir, "out", "ca.pem"),
		caBundleOut: filepath.Join(dir, "out", "bundle.pem"),
	}

	_, _, err := GenerateProxy(t.Context(), usr, opts)
	require.NoError(t, err)

	first, err := os.ReadFile(opts.caOut)
	require.NoError(t, err)

	_, _, err = GenerateProxy(t.Context(), usr, opts)
	require.NoError(t, err)

	second, err := os.ReadFile(opts.caOut)
	require.NoError(t, err)
	assert.Equal(t, first, second, "a restart must keep the CA")

	bundle, err := os.ReadFile(opts.caBundleOut)
	require.NoError(t, err)
	assert.True(t, bytes.HasSuffix(bundle, first), "bundle must end with the MITM CA")
}
