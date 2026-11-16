package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/accesslog"
	"go.jacobcolvin.com/terrarium/certs"
	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoy"
	"go.jacobcolvin.com/terrarium/envoybin"
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
			// With auto_host_rewrite, Envoy sends the upstream the
			// Host header with the port of the upstream.
			wantAbsent: []string{
				"auto_host_rewrite",
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
				"auto_host_rewrite",
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
				"auto_host_rewrite",
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
		"stats with explicit socket": {
			yaml: "stats:\n" +
				"  enabled: true\n" +
				"  socket: /tmp/als.sock\n" +
				"egress: []\n",
			want: []string{
				"terrarium_accesslog",
				"envoy.access_loggers.http_grpc",
				"path: /tmp/als.sock",
			},
		},
		"stats socket past the platform limit drops grpc accesslog": {
			yaml: "stats:\n" +
				"  enabled: true\n" +
				"  socket: /" + strings.Repeat("a", accesslog.MaxSocketPathLen) + "\n" +
				"egress: []\n",
			want: []string{
				"name: deny",
			},
			wantAbsent: []string{
				"terrarium_accesslog",
				"envoy.access_loggers.http_grpc",
			},
		},
		"cidr http rules on port opened by tcp rule": {
			yaml: "egress:\n" +
				"  - toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"443\"\n" +
				"            protocol: TCP\n" +
				"  - toCIDR:\n" +
				"      - 10.0.0.0/8\n" +
				"    toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"443\"\n" +
				"        rules:\n" +
				"          http:\n" +
				"            - method: GET\n",
			want: []string{
				"name: tls_internal_443",
			},
			wantAbsent: []string{
				"mitm_*",
			},
		},
		"cidr http rules on port opened by udp rule": {
			yaml: "egress:\n" +
				"  - toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"443\"\n" +
				"            protocol: UDP\n" +
				"  - toCIDR:\n" +
				"      - 10.0.0.0/8\n" +
				"    toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"443\"\n" +
				"        rules:\n" +
				"          http:\n" +
				"            - method: GET\n",
			err: config.ErrCIDRL7RequiresHTTPPort,
		},
		"cidr http rules on port opened by port range": {
			yaml: "egress:\n" +
				"  - toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"443\"\n" +
				"            endPort: 450\n" +
				"  - toCIDR:\n" +
				"      - 10.0.0.0/8\n" +
				"    toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"443\"\n" +
				"        rules:\n" +
				"          http:\n" +
				"            - method: GET\n",
			err: config.ErrCIDRL7RequiresHTTPPort,
		},
		"cidr http rules beside toPorts entry without ports": {
			yaml: "egress:\n" +
				"  - toPorts:\n" +
				"      - {}\n" +
				"  - toCIDR:\n" +
				"      - 10.0.0.0/8\n" +
				"    toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"443\"\n" +
				"        rules:\n" +
				"          http:\n" +
				"            - method: GET\n",
			wantAbsent: []string{
				"tls_internal_443",
				"mitm_*",
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
				"127.0.0.1", 8080, resolvers, "",
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

// TestGenerateProxyEnvoyFromConfigStatsSocketDefault uses t.Setenv,
// which is incompatible with t.Parallel().
//
//nolint:paralleltest // see comment above.
func TestGenerateProxyEnvoyFromConfigStatsSocketDefault(t *testing.T) {
	tests := map[string]struct {
		env         map[string]string
		bindAddress string
		want        string
		httpPort    int
	}{
		"runtime dir set": {
			env: map[string]string{
				"HOME":            "/Users/user",
				"XDG_STATE_HOME":  "",
				"XDG_RUNTIME_DIR": "/run/user/4242",
			},
			bindAddress: "127.0.0.1",
			httpPort:    8080,
			want:        "path: /run/user/4242/terrarium/accesslog-127.0.0.1-8080.sock\n",
		},
		"another port": {
			env: map[string]string{
				"HOME":            "/Users/user",
				"XDG_STATE_HOME":  "",
				"XDG_RUNTIME_DIR": "/run/user/4242",
			},
			bindAddress: "127.0.0.1",
			httpPort:    3128,
			want:        "path: /run/user/4242/terrarium/accesslog-127.0.0.1-3128.sock\n",
		},
		"IPv6 bind address": {
			env: map[string]string{
				"HOME":            "/Users/user",
				"XDG_STATE_HOME":  "",
				"XDG_RUNTIME_DIR": "/run/user/4242",
			},
			bindAddress: "::1",
			httpPort:    8080,
			want:        "path: /run/user/4242/terrarium/accesslog-::1-8080.sock\n",
		},
		"no runtime dir": {
			env: map[string]string{
				"HOME":            "/Users/user",
				"XDG_STATE_HOME":  "",
				"XDG_RUNTIME_DIR": "",
			},
			bindAddress: "127.0.0.1",
			httpPort:    8080,
			want:        "path: /Users/user/.local/state/terrarium/accesslog-127.0.0.1-8080.sock\n",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cfg := parseProxyConfig(t, "stats:\n  enabled: true\negress: []\n")

			out, err := GenerateProxyEnvoyFromConfig(
				t.Context(), cfg, "", "", tt.bindAddress, tt.httpPort, nil, "")
			require.NoError(t, err)

			assert.Contains(t, out, "terrarium_accesslog")
			assert.Contains(t, out, tt.want)
			assert.NotContains(t, out, config.DefaultStatsSocket)
		})
	}
}

// TestProxyAccessLogSocketPerListenAddress checks that proxies on
// different listen addresses each open their own access log socket.
// The proxies share one policy, which sets no stats.socket. The
// bootstrap of each proxy names the socket of that proxy.
//
// On one shared path, a proxy removes the socket of the proxy that
// started before it. Its shutdown then leaves no socket for the Envoy
// of the other proxy.
//
//nolint:paralleltest // sets XDG_RUNTIME_DIR for the whole process.
func TestProxyAccessLogSocketPerListenAddress(t *testing.T) {
	runtimeDir := shortTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	cfg := parseProxyConfig(t, "stats:\n"+
		"  enabled: true\n"+
		"  path: "+filepath.Join(t.TempDir(), "stats.db")+"\n"+
		"egress: []\n")

	store := openProxyEventStore(t.Context(), cfg, config.NewUser(), proxyOptions{})
	require.NotNil(t, store)

	t.Cleanup(func() {
		assert.NoError(t, store.Close())
	})

	listens := []proxyOptions{
		{bindAddress: "127.0.0.1", httpPort: 18080},
		{bindAddress: "127.0.0.1", httpPort: 18081},
		{bindAddress: "::1", httpPort: 18080},
	}

	sockets := make([]string, 0, len(listens))
	servers := make([]*accesslog.Server, 0, len(listens))

	for _, opts := range listens {
		socket := proxyStatsSocket(cfg, opts)

		assert.Equal(t, filepath.Join(runtimeDir, "terrarium"), filepath.Dir(socket))
		assert.NotContains(t, sockets, socket)

		srv := openProxyAccessLog(t.Context(), cfg, store, opts)
		require.NotNil(t, srv, "the proxy must open its access log socket")

		// The Envoy of the proxy sends its events to the socket that
		// the proxy opened.
		bootstrap, err := GenerateProxyEnvoyFromConfig(
			t.Context(), cfg, "", "", opts.bindAddress, opts.httpPort, nil, "")
		require.NoError(t, err)
		assert.Contains(t, bootstrap, "path: "+socket+"\n")

		sockets = append(sockets, socket)
		servers = append(servers, srv)
	}

	requireSockets := func(paths []string) {
		t.Helper()

		for _, path := range paths {
			fi, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, os.ModeSocket, fi.Mode().Type())
		}
	}

	// A proxy that starts later leaves the sockets of the running
	// proxies in place.
	requireSockets(sockets)

	// A proxy that exits removes only its own socket.
	for i, v := range slices.Backward(servers) {
		v.Shutdown(t.Context())

		assert.NoFileExists(t, sockets[i])
		requireSockets(sockets[:i])
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
		t.Context(), cfg, "", "", "127.0.0.1", 8080, nil, "")
	require.NoError(t, err)

	for range 10 {
		out, err := GenerateProxyEnvoyFromConfig(
			t.Context(), cfg, "", "", "127.0.0.1", 8080, nil, "")
		require.NoError(t, err)
		assert.Equal(t, first, out)
	}
}

// TestGenerateProxyEnvoyFromConfigProbe checks that the bootstrap
// answers the probe request for the probe token in every mode, and
// that the access loggers skip the probe request.
func TestGenerateProxyEnvoyFromConfigProbe(t *testing.T) {
	t.Parallel()

	const token = "0123456789abcdef0123456789abcdef"

	tests := map[string]struct {
		yaml string
	}{
		"blocked": {yaml: "egress: []\n"},
		"open":    {yaml: ""},
		"filtered": {
			yaml: "egress:\n" +
				"  - toFQDNs:\n" +
				"      - matchName: example.com\n" +
				"    toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"443\"\n",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := parseProxyConfig(t, "stats:\n  enabled: true\n"+tt.yaml)

			out, err := GenerateProxyEnvoyFromConfig(
				t.Context(), cfg, "", "/etc/ssl/bundle.pem", "127.0.0.1", 8080, nil, token)
			require.NoError(t, err)

			assert.Contains(t, out, "- "+envoy.ProxyProbeHost)
			assert.Contains(t, out, "path: /"+token)
			assert.Contains(t, out, "environment_variable: "+envoy.ProxyProbeTokenEnv)
			assert.Contains(t, out, "exact: "+envoy.ProxyProbeHost)
			assert.Contains(t, out, "invert_match: true")
			assert.Contains(t, out, "treat_missing_header_as_empty: true")

			out, err = GenerateProxyEnvoyFromConfig(
				t.Context(), cfg, "", "/etc/ssl/bundle.pem", "127.0.0.1", 8080, nil, "")
			require.NoError(t, err)

			assert.NotContains(t, out, envoy.ProxyProbeHost)
			assert.NotContains(t, out, envoy.ProxyProbeTokenEnv)
			assert.NotContains(t, out, "invert_match")
		})
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

	_, _, err := GenerateProxy(t.Context(), usr, opts, "")
	require.NoError(t, err)

	first, err := os.ReadFile(opts.caOut)
	require.NoError(t, err)

	_, _, err = GenerateProxy(t.Context(), usr, opts, "")
	require.NoError(t, err)

	second, err := os.ReadFile(opts.caOut)
	require.NoError(t, err)
	assert.Equal(t, first, second, "a restart must keep the CA")

	bundle, err := os.ReadFile(opts.caBundleOut)
	require.NoError(t, err)
	assert.True(t, bytes.HasSuffix(bundle, first), "bundle must end with the MITM CA")
}

// TestGenerateProxyWarnsICMPFamilyMismatch replaces the default
// logger, which is incompatible with t.Parallel().
//
//nolint:paralleltest // see comment above.
func TestGenerateProxyWarnsICMPFamilyMismatch(t *testing.T) {
	logs := captureLogs(t)

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(icmpFamilyMismatchPolicy), 0o600))

	usr := &config.User{
		ConfigPath:      policyPath,
		CADir:           filepath.Join(dir, "ca"),
		CertsDir:        filepath.Join(dir, "certs"),
		EnvoyConfigPath: filepath.Join(dir, "envoy.yaml"),
	}
	opts := proxyOptions{bindAddress: "127.0.0.1", httpPort: 8080}

	_, _, err := GenerateProxy(t.Context(), usr, opts, "")
	require.NoError(t, err)

	out := logs.String()
	assert.Contains(t, out, "level=WARN")
	assert.Contains(t, out, icmpFamilyMismatchWarning)
	assert.Contains(t, out, "list=egress rule_index=0 icmp_family=IPv6 cidr_family=IPv4")
}

// envoyCommand is the Envoy override of the tests that run the envoy on
// PATH. That envoy is the stub of [stubEnvoy] or, in the end-to-end
// tests, the Envoy of the host.
const envoyCommand = "envoy"

// stubEnvoy puts a stub envoy first on PATH, where a proxy with the
// override [envoyCommand] finds it. It returns the started file and the
// args file of the stub. See [stubEnvoyScript] for the stub.
func stubEnvoy(t *testing.T) (string, string) {
	t.Helper()

	binDir := t.TempDir()
	stub, started, args := stubEnvoyScript(binDir)

	require.NoError(t, os.WriteFile(filepath.Join(binDir, envoyCommand), []byte(stub), 0o755))

	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	return started, args
}

// stubEnvoyScript returns a shell script that stands for Envoy, and the
// paths of its started file and its args file in dir.
//
// The stub writes its arguments to the args file, one per line, and its
// probe token to the file that [stubProbeToken] reads. It then writes
// its process ID to the started file and sleeps. It never listens, so
// the proxy stays in startup until the test answers the probe request
// or cancels the context. See [serveProxyProbe] for the helper that
// answers it.
//
// The stub sets PATH to the value that the test process has during the
// call, so it finds its commands when the proxy runs with another PATH.
func stubEnvoyScript(dir string) (string, string, string) {
	started := filepath.Join(dir, "started")
	args := filepath.Join(dir, "args")

	stub := "#!/bin/sh\n" +
		"PATH='" + os.Getenv("PATH") + "'\n" +
		"printf '%s\\n' \"$@\" > '" + args + "'\n" +
		"printf '%s' \"$" + envoy.ProxyProbeTokenEnv + "\" > '" + started + ".token'\n" +
		// The rename makes the file appear with the process ID in it.
		"echo $$ > '" + started + ".tmp'\n" +
		"mv '" + started + ".tmp' '" + started + "'\n" +
		"exec sleep 60\n"

	return stub, started, args
}

// noManagedEnvoy returns an installer whose manifest holds no build. A
// proxy that runs without an Envoy override then returns an error, and
// it never downloads a build.
func noManagedEnvoy() *envoybin.Installer {
	return envoybin.NewInstaller("", envoybin.WithManifest(envoybin.Manifest{}))
}

// stubProxyUser writes policy to dir and returns a user whose paths
// all sit in dir.
func stubProxyUser(t *testing.T, dir, policy string) *config.User {
	t.Helper()

	policyPath := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(policy), 0o644))

	return &config.User{
		ConfigPath:      policyPath,
		CADir:           filepath.Join(dir, "ca"),
		CertsDir:        filepath.Join(dir, "certs"),
		EnvoyConfigPath: filepath.Join(dir, "envoy.yaml"),
	}
}

// requireStubStarted waits until the stub envoy creates its started
// file, which is the moment the proxy begins to wait for the listener.
func requireStubStarted(t *testing.T, started string) {
	t.Helper()

	require.Eventually(t, func() bool {
		_, err := os.Stat(started)

		return err == nil
	}, 15*time.Second, 10*time.Millisecond, "stub envoy did not start")
}

// requireStubStopped checks that the stub envoy process does not
// exist. The started file holds the process ID of the stub.
func requireStubStopped(t *testing.T, started string) {
	t.Helper()

	pid := stubPID(t, started)

	// Signal 0 finds a process that runs, and one that exited but
	// that the proxy did not reap.
	require.ErrorIs(t, syscall.Kill(pid, 0), syscall.ESRCH, "stub envoy must not outlive the proxy")
}

// stubPID returns the process ID of the stub envoy, which the started
// file holds.
func stubPID(t *testing.T, started string) int {
	t.Helper()

	data, err := os.ReadFile(started) //nolint:gosec // test fixture path.
	require.NoError(t, err)

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	require.NoError(t, err)

	return pid
}

// listenProxyPort opens the proxy listener, which the stub envoy
// never opens, and closes it when the test ends.
func listenProxyPort(t *testing.T, opts proxyOptions) {
	t.Helper()

	lc := net.ListenConfig{}

	ln, err := lc.Listen(t.Context(), "tcp", net.JoinHostPort(opts.bindAddress, strconv.Itoa(opts.httpPort)))
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, ln.Close())
	})
}

// probeTokenPattern matches the probe token in a proxy bootstrap.
var probeTokenPattern = regexp.MustCompile(`path: /([0-9a-f]{32})\n`)

// stubProbeToken returns the probe token that the proxy passed to the
// stub envoy in its environment. The started file belongs to that
// stub, see [stubEnvoy].
func stubProbeToken(t *testing.T, started string) string {
	t.Helper()

	token, err := os.ReadFile(started + ".token")
	require.NoError(t, err)

	return string(token)
}

// bootstrapProbeToken returns the probe token in the bootstrap that
// the proxy with opts wrote for usr.
func bootstrapProbeToken(t *testing.T, usr *config.User, opts proxyOptions) string {
	t.Helper()

	bootstrap, err := os.ReadFile(proxyBootstrapPath(usr, opts))
	require.NoError(t, err)

	m := probeTokenPattern.FindSubmatch(bootstrap)
	require.NotNil(t, m, "bootstrap holds no probe token")

	return string(m[1])
}

// serveProxyPort serves handler on the proxy listen address, which the
// stub envoy never opens, and stops when the test ends.
func serveProxyPort(t *testing.T, opts proxyOptions, handler http.HandlerFunc) {
	t.Helper()

	lc := net.ListenConfig{}

	ln, err := lc.Listen(t.Context(), "tcp", net.JoinHostPort(opts.bindAddress, strconv.Itoa(opts.httpPort)))
	require.NoError(t, err)

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}

	go func() {
		serveErr := srv.Serve(ln)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Logf("proxy port serve: %v", serveErr)
		}
	}()

	t.Cleanup(func() {
		assert.NoError(t, srv.Close())
	})
}

// serveProxyProbe answers the probe request on the proxy listen
// address as the Envoy of usr does. The stub envoy that wrote the
// started file stands for that Envoy. The answer has status 200 only
// for the path that the bootstrap of usr names, and its body is the
// probe token from the environment of the stub.
func serveProxyProbe(t *testing.T, started string, usr *config.User, opts proxyOptions) {
	t.Helper()

	path := "/" + bootstrapProbeToken(t, usr, opts)
	body := stubProbeToken(t, started)

	serveProxyPort(t, opts, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host != envoy.ProxyProbeHost:
			w.WriteHeader(http.StatusForbidden)

		case r.URL.Path != path:
			w.WriteHeader(http.StatusNotFound)

		default:
			_, err := w.Write([]byte(body))
			assert.NoError(t, err)
		}
	})
}

// requireLoopback skips the test when the host cannot listen on the
// loopback address ip, for example ::1 on a host without IPv6.
func requireLoopback(t *testing.T, ip string) {
	t.Helper()

	err := loopbackError(t, ip)
	if err != nil {
		t.Skip(err)
	}
}

// loopbackError returns an error when the host cannot listen on the
// loopback address ip, and nil otherwise.
func loopbackError(t *testing.T, ip string) error {
	t.Helper()

	lc := net.ListenConfig{}

	ln, err := lc.Listen(t.Context(), "tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		return fmt.Errorf("loopback address %s unavailable: %w", ip, err)
	}

	require.NoError(t, ln.Close())

	return nil
}

// loopbackInterface returns the name of a loopback interface that is
// up, for use as the zone of an IPv6 address. It skips the test when
// the host has no such interface.
func loopbackInterface(t *testing.T) string {
	t.Helper()

	ifaces, err := net.Interfaces()
	require.NoError(t, err)

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 && iface.Flags&net.FlagUp != 0 {
			return iface.Name
		}
	}

	t.Skip("no loopback interface is up")

	return ""
}

// requireReadyFile waits until the proxy creates the ready file.
func requireReadyFile(t *testing.T, path string) {
	t.Helper()

	require.Eventually(t, func() bool {
		_, err := os.Stat(path)

		return err == nil
	}, 15*time.Second, 10*time.Millisecond, "proxy did not create the ready file")
}

// requireProxyShutDown waits for [Proxy] to return nil on errCh.
func requireProxyShutDown(t *testing.T, errCh <-chan error) {
	t.Helper()

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(15 * time.Second):
		t.Fatal("proxy did not shut down")
	}
}

// TestProxyCancelDuringStartup checks that [Proxy] returns nil when
// its context ends before the listener accepts connections. A stub
// envoy that never listens holds the proxy in startup.
//
//nolint:paralleltest,tparallel // sets PATH for the whole process.
func TestProxyCancelDuringStartup(t *testing.T) {
	tests := map[string]struct {
		// beforeStart cancels the context before the call to Proxy,
		// so the cancellation arrives before Envoy starts.
		beforeStart bool
	}{
		"before envoy starts": {beforeStart: true},
		"after envoy starts":  {},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			started, _ := stubEnvoy(t)

			dir := t.TempDir()
			usr := stubProxyUser(t, dir, "egress: []\n")
			usr.ReadyFile = filepath.Join(dir, "ready")

			opts := proxyOptions{
				envoyPath:   envoyCommand,
				bindAddress: loopbackIPv4,
				httpPort:    freePort(t),
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			if tt.beforeStart {
				cancel()
			}

			errCh := make(chan error, 1)

			go func() {
				errCh <- Proxy(ctx, usr, noManagedEnvoy(), opts)
			}()

			if !tt.beforeStart {
				requireStubStarted(t, started)
				cancel()
			}

			requireProxyShutDown(t, errCh)

			if tt.beforeStart {
				assert.NoFileExists(t, started, "envoy must not start after the cancellation")
			}

			assert.NoFileExists(t, usr.ReadyFile, "a proxy that never became ready must not signal readiness")
		})
	}
}

// TestProxyReadyFile checks that [Proxy] creates the ready file only
// after the listener answers the probe request, and removes it on
// shutdown. The stub envoy never listens, so the test answers the
// probe itself.
//
//nolint:paralleltest,tparallel // sets PATH for the whole process.
func TestProxyReadyFile(t *testing.T) {
	tests := map[string]struct {
		bindAddress string
		// zone appends the name of the loopback interface to the
		// bind address as its zone.
		zone bool
	}{
		"IPv4 bind address":             {bindAddress: loopbackIPv4},
		"IPv6 bind address":             {bindAddress: loopbackIPv6},
		"IPv6 bind address with a zone": {bindAddress: loopbackIPv6, zone: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if tt.zone {
				tt.bindAddress += "%" + loopbackInterface(t)
			}

			requireLoopback(t, tt.bindAddress)

			started, _ := stubEnvoy(t)

			dir := t.TempDir()
			usr := stubProxyUser(t, dir, "egress: []\n")
			usr.ReadyFile = filepath.Join(dir, "ready")

			// An earlier run that did not shut down cleanly leaves its file.
			require.NoError(t, os.WriteFile(usr.ReadyFile, nil, 0o600))

			opts := proxyOptions{
				envoyPath:   envoyCommand,
				bindAddress: tt.bindAddress,
				httpPort:    freePort(t),
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			errCh := make(chan error, 1)

			go func() {
				errCh <- Proxy(ctx, usr, noManagedEnvoy(), opts)
			}()

			requireStubStarted(t, started)
			assert.NoFileExists(t, usr.ReadyFile, "the ready file must not exist before the listener is up")

			serveProxyProbe(t, started, usr, opts)
			requireReadyFile(t, usr.ReadyFile)

			cancel()
			requireProxyShutDown(t, errCh)

			assert.NoFileExists(t, usr.ReadyFile, "shutdown must remove the ready file")
		})
	}
}

// TestProxyShutdownFlushWait checks how long [Proxy] keeps Envoy
// running after its context ends. A proxy that records stats waits for
// the last flush of the access log, and at most for the drain timeout.
// A proxy without stats stops Envoy immediately. The stub envoy never
// listens, so the test answers the probe itself.
//
// The test replaces the default logger and sets PATH for the whole
// process, which is incompatible with t.Parallel().
//
//nolint:paralleltest,tparallel // see comment above.
func TestProxyShutdownFlushWait(t *testing.T) {
	tests := map[string]struct {
		// stats is true when the policy enables stats.
		stats bool
		// policy holds the lines of the policy after the paths of
		// the stats section.
		policy string
		// want is the wait that the proxy must log and keep. Zero
		// means that the proxy must not wait.
		want time.Duration
	}{
		"stats disabled": {
			policy: "egress: []\n",
		},
		"flush interval": {
			stats:  true,
			policy: "  flushIntervalMs: 200\negress: []\n",
			want:   200*time.Millisecond + accessLogFlushMargin,
		},
		"flush interval longer than the drain timeout": {
			stats: true,
			policy: "  flushIntervalMs: 600000\n" +
				"envoy:\n" +
				"  drainTimeout: 300ms\n" +
				"egress: []\n",
			want: 300 * time.Millisecond,
		},
	}

	const waitLog = "waiting for the last stats events"

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			logs := captureLogs(t)
			started, _ := stubEnvoy(t)

			dir := t.TempDir()

			policy := tt.policy
			if tt.stats {
				policy = "stats:\n" +
					"  enabled: true\n" +
					"  path: " + filepath.Join(dir, "stats.db") + "\n" +
					"  socket: " + filepath.Join(shortTempDir(t), "accesslog.sock") + "\n" +
					policy
			}

			usr := stubProxyUser(t, dir, policy)
			usr.ReadyFile = filepath.Join(dir, "ready")

			opts := proxyOptions{
				envoyPath:   envoyCommand,
				bindAddress: loopbackIPv4,
				httpPort:    freePort(t),
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			errCh := make(chan error, 1)

			go func() {
				errCh <- Proxy(ctx, usr, noManagedEnvoy(), opts)
			}()

			requireStubStarted(t, started)
			serveProxyProbe(t, started, usr, opts)
			requireReadyFile(t, usr.ReadyFile)

			start := time.Now()

			cancel()
			requireProxyShutDown(t, errCh)

			elapsed := time.Since(start)

			requireStubStopped(t, started)

			if tt.want == 0 {
				assert.NotContains(t, logs.String(), waitLog)

				return
			}

			assert.GreaterOrEqual(t, elapsed, tt.want,
				"envoy must keep running until its last flush")
			assert.Contains(t, logs.String(), waitLog)
			assert.Contains(t, logs.String(), "wait="+tt.want.String())
		})
	}
}

// TestProxyListenAddressInUse checks that [Proxy] returns
// [ErrListenAddressUnavailable] when another process holds the listen
// address. The proxy must not take the listener of that process for
// its own, so it starts no Envoy and creates no ready file.
//
// The other process can be a proxy with the same policy, which shares
// the stats paths. The refused proxy must leave the access log socket
// of that proxy in place, and it must not open the event store.
//
//nolint:paralleltest // sets PATH for the whole process.
func TestProxyListenAddressInUse(t *testing.T) {
	started, _ := stubEnvoy(t)

	dir := t.TempDir()
	statsDB := filepath.Join(dir, "stats.db")
	socket := filepath.Join(shortTempDir(t), "accesslog.sock")

	usr := stubProxyUser(t, dir, "stats:\n"+
		"  enabled: true\n"+
		"  path: "+statsDB+"\n"+
		"  socket: "+socket+"\n"+
		"egress: []\n")
	usr.ReadyFile = filepath.Join(dir, "ready")

	// An earlier run that did not shut down cleanly leaves its file.
	// The proxy removes the file although it does not start.
	require.NoError(t, os.WriteFile(usr.ReadyFile, nil, 0o600))

	lc := net.ListenConfig{}

	// The listener stands for the access log socket of the proxy that
	// holds the port.
	accessLog, err := lc.Listen(t.Context(), "unix", socket)
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, accessLog.Close())
	})

	opts := proxyOptions{
		envoyPath:   envoyCommand,
		bindAddress: loopbackIPv4,
		httpPort:    freePort(t),
	}

	listenProxyPort(t, opts)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		errCh <- Proxy(ctx, usr, noManagedEnvoy(), opts)
	}()

	select {
	case err = <-errCh:
		require.ErrorIs(t, err, ErrListenAddressUnavailable)
		require.ErrorIs(t, err, syscall.EADDRINUSE)
		require.ErrorContains(t, err, net.JoinHostPort(opts.bindAddress, strconv.Itoa(opts.httpPort)))

	case <-time.After(15 * time.Second):
		t.Fatal("proxy did not return")
	}

	assert.NoFileExists(t, started, "envoy must not start")
	assert.NoFileExists(t, usr.ReadyFile, "a proxy that cannot bind its address must not signal readiness")
	assert.NoFileExists(t, statsDB, "a proxy that cannot bind its address must not open the event store")

	fi, err := os.Stat(socket)
	require.NoError(t, err, "a proxy that cannot bind its address must keep the access log socket of the other proxy")
	assert.Equal(t, os.ModeSocket, fi.Mode().Type())
}

// TestProxyListenAddressTakenAfterStart checks that [Proxy] returns
// [ErrListenAddressUnavailable] when another process answers the probe
// request on the listen address. That process took the address after
// the listen address check, so the Envoy of the proxy runs. The proxy
// must stop it and must not signal readiness.
//
// The other process can be a proxy with the same policy, which shares
// the stats paths. The proxy that does not serve the address must
// leave the access log socket of that proxy in place, and it must not
// open the event store.
//
//nolint:paralleltest,tparallel // sets PATH for the whole process.
func TestProxyListenAddressTakenAfterStart(t *testing.T) {
	tests := map[string]struct {
		handler http.HandlerFunc
	}{
		// Both proxies wrote their bootstraps to one path, and the
		// Envoy of the other proxy loaded the bootstrap of this proxy.
		// It knows the path of the probe request, and it answers with
		// the token from its own environment.
		"envoy of another proxy with the bootstrap of this proxy": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, err := w.Write([]byte("ffffffffffffffffffffffffffffffff"))
				assert.NoError(t, err)
			},
		},
		// An Envoy whose bootstrap holds another token has no route
		// for the path of the probe request.
		"envoy with the bootstrap of another proxy": {
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			started, _ := stubEnvoy(t)

			dir := t.TempDir()
			statsDB := filepath.Join(dir, "stats.db")
			socket := filepath.Join(shortTempDir(t), "accesslog.sock")

			usr := stubProxyUser(t, dir, "stats:\n"+
				"  enabled: true\n"+
				"  path: "+statsDB+"\n"+
				"  socket: "+socket+"\n"+
				"egress: []\n")
			usr.ReadyFile = filepath.Join(dir, "ready")

			lc := net.ListenConfig{}

			// The listener stands for the access log socket of the
			// proxy that serves the address.
			accessLog, err := lc.Listen(t.Context(), "unix", socket)
			require.NoError(t, err)

			t.Cleanup(func() {
				assert.NoError(t, accessLog.Close())
			})

			opts := proxyOptions{
				envoyPath:   envoyCommand,
				bindAddress: loopbackIPv4,
				httpPort:    freePort(t),
			}

			errCh := make(chan error, 1)

			go func() {
				errCh <- Proxy(t.Context(), usr, noManagedEnvoy(), opts)
			}()

			requireStubStarted(t, started)
			serveProxyPort(t, opts, tt.handler)

			select {
			case err = <-errCh:
				require.ErrorIs(t, err, ErrListenAddressUnavailable)
				require.NotErrorIs(t, err, ErrEnvoyNotRunning)
				require.ErrorContains(t, err, net.JoinHostPort(opts.bindAddress, strconv.Itoa(opts.httpPort)))

			case <-time.After(15 * time.Second):
				t.Fatal("proxy did not return")
			}

			requireStubStopped(t, started)
			assert.NoFileExists(t, usr.ReadyFile, "a proxy that does not serve its address must not signal readiness")
			assert.NoFileExists(t, statsDB, "a proxy that does not serve its address must not open the event store")

			fi, err := os.Stat(socket)
			require.NoError(t, err,
				"a proxy that does not serve its address must keep the access log socket of the other proxy")
			assert.Equal(t, os.ModeSocket, fi.Mode().Type())
		})
	}
}

// TestProxyEnvoyExits checks that [Proxy] returns when its Envoy exits
// before it answers the probe request. Proxy does not wait for the
// startup timeout, and the error gives the exit status of Envoy.
func TestProxyEnvoyExits(t *testing.T) {
	t.Parallel()

	const startupTimeout = time.Minute

	tests := map[string]struct {
		// command exits when it starts, and stands for Envoy.
		command string
		want    string
	}{
		"exit status": {
			command: "false",
			want:    "exit status 1",
		},
		"exit without an error": {
			command: "true",
			want:    "exit status 0",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			usr := stubProxyUser(t, dir, "envoy:\n"+
				"  startupTimeout: "+startupTimeout.String()+"\n"+
				"egress: []\n")
			usr.ReadyFile = filepath.Join(dir, "ready")

			opts := proxyOptions{
				envoyPath:   tt.command,
				bindAddress: loopbackIPv4,
				httpPort:    freePort(t),
			}

			start := time.Now()

			err := Proxy(t.Context(), usr, noManagedEnvoy(), opts)

			elapsed := time.Since(start)

			require.ErrorIs(t, err, ErrEnvoyNotRunning)
			require.ErrorIs(t, err, ErrEnvoyExited)
			require.NotErrorIs(t, err, ErrListenerNotReady)
			require.ErrorContains(t, err, tt.want)
			require.ErrorContains(t, err, net.JoinHostPort(opts.bindAddress, strconv.Itoa(opts.httpPort)))

			assert.Less(t, elapsed, startupTimeout/2,
				"the proxy must not wait for the startup timeout")
			assert.NoFileExists(t, usr.ReadyFile, "a proxy whose envoy exited must not signal readiness")
		})
	}
}

// TestProxyProbeToken checks that [Proxy] gives its Envoy one probe
// token in two places. The bootstrap names the token in the path of
// the probe route, and the environment of Envoy holds the token for
// the body of the probe answer.
//
//nolint:paralleltest // sets PATH for the whole process.
func TestProxyProbeToken(t *testing.T) {
	started, _ := stubEnvoy(t)

	usr := stubProxyUser(t, t.TempDir(), "egress: []\n")

	opts := proxyOptions{
		envoyPath:   envoyCommand,
		bindAddress: loopbackIPv4,
		httpPort:    freePort(t),
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		errCh <- Proxy(ctx, usr, noManagedEnvoy(), opts)
	}()

	requireStubStarted(t, started)

	token := stubProbeToken(t, started)
	assert.Len(t, token, 32)
	assert.Equal(t, bootstrapProbeToken(t, usr, opts), token)

	cancel()
	requireProxyShutDown(t, errCh)
}

// TestProxyEnvoyProcessGroup checks that [Proxy] starts Envoy outside
// the process group of the proxy. The signals that a terminal sends to
// the group of the proxy, such as the SIGINT of a Ctrl-C, then do not
// reach Envoy. The proxy can therefore keep Envoy running until its
// last flush of the access log.
//
// With a guard, Envoy runs in the group that the guard process leads.
// Without one, Envoy leads its group. See [envoyGuard] for the guard.
//
//nolint:paralleltest // sets PATH for the whole process.
func TestProxyEnvoyProcessGroup(t *testing.T) {
	started, _ := stubEnvoy(t)

	usr := stubProxyUser(t, t.TempDir(), "egress: []\n")

	opts := proxyOptions{
		envoyPath:   envoyCommand,
		bindAddress: loopbackIPv4,
		httpPort:    freePort(t),
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		errCh <- Proxy(ctx, usr, noManagedEnvoy(), opts)
	}()

	requireStubStarted(t, started)

	pid := stubPID(t, started)

	pgid, err := syscall.Getpgid(pid)
	require.NoError(t, err)

	assert.NotEqual(t, syscall.Getpgrp(), pgid, "envoy must not run in the process group of the proxy")

	if proxyEnvoyGuarded {
		assert.NotEqual(t, pid, pgid, "envoy must run in the process group of its guard")
	} else {
		assert.Equal(t, pid, pgid, "envoy must lead a process group of its own")
	}

	cancel()
	requireProxyShutDown(t, errCh)
	requireStubStopped(t, started)
}

// TestProxyReadyFileError checks that [Proxy] stops Envoy and returns
// the error when it cannot create the ready file. The listener is up
// by then, so Envoy runs.
//
//nolint:paralleltest // sets PATH for the whole process.
func TestProxyReadyFileError(t *testing.T) {
	started, _ := stubEnvoy(t)

	dir := t.TempDir()
	usr := stubProxyUser(t, dir, "egress: []\n")

	// The proxy does not create the directory of the ready file.
	usr.ReadyFile = filepath.Join(dir, "missing", "ready")

	opts := proxyOptions{
		envoyPath:   envoyCommand,
		bindAddress: loopbackIPv4,
		httpPort:    freePort(t),
	}

	errCh := make(chan error, 1)

	go func() {
		errCh <- Proxy(t.Context(), usr, noManagedEnvoy(), opts)
	}()

	requireStubStarted(t, started)
	serveProxyProbe(t, started, usr, opts)

	select {
	case err := <-errCh:
		require.ErrorContains(t, err, "creating ready file")
		require.ErrorIs(t, err, os.ErrNotExist)

	case <-time.After(15 * time.Second):
		t.Fatal("proxy did not return")
	}

	requireStubStopped(t, started)
}

// TestProxyReadyFileIsDir checks that [Proxy] refuses a ready file
// path that names a directory, and leaves the directory in place.
//
//nolint:paralleltest,tparallel // sets PATH for the whole process.
func TestProxyReadyFileIsDir(t *testing.T) {
	tests := map[string]struct {
		// file is the name of a file to create in the directory.
		// An empty value leaves the directory empty.
		file string
	}{
		"empty directory":       {},
		"directory with a file": {file: "data"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			started, _ := stubEnvoy(t)

			dir := t.TempDir()
			usr := stubProxyUser(t, dir, "egress: []\n")
			usr.ReadyFile = filepath.Join(dir, "ready")

			require.NoError(t, os.Mkdir(usr.ReadyFile, 0o755))

			if tt.file != "" {
				require.NoError(t, os.WriteFile(filepath.Join(usr.ReadyFile, tt.file), nil, 0o600))
			}

			opts := proxyOptions{
				envoyPath:   envoyCommand,
				bindAddress: loopbackIPv4,
				httpPort:    freePort(t),
			}

			err := Proxy(t.Context(), usr, noManagedEnvoy(), opts)
			require.ErrorIs(t, err, ErrReadyFileIsDir)

			assert.DirExists(t, usr.ReadyFile)
			assert.NoFileExists(t, started, "envoy must not start")

			if tt.file != "" {
				assert.FileExists(t, filepath.Join(usr.ReadyFile, tt.file))
			}
		})
	}
}

// TestProxyReadyFileReplacedByDir checks that the shutdown of [Proxy]
// leaves a directory that replaced the ready file while the proxy ran.
//
//nolint:paralleltest // sets PATH for the whole process.
func TestProxyReadyFileReplacedByDir(t *testing.T) {
	started, _ := stubEnvoy(t)

	dir := t.TempDir()
	usr := stubProxyUser(t, dir, "egress: []\n")
	usr.ReadyFile = filepath.Join(dir, "ready")

	opts := proxyOptions{
		envoyPath:   envoyCommand,
		bindAddress: loopbackIPv4,
		httpPort:    freePort(t),
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		errCh <- Proxy(ctx, usr, noManagedEnvoy(), opts)
	}()

	requireStubStarted(t, started)
	serveProxyProbe(t, started, usr, opts)
	requireReadyFile(t, usr.ReadyFile)

	require.NoError(t, os.Remove(usr.ReadyFile))
	require.NoError(t, os.Mkdir(usr.ReadyFile, 0o755))

	cancel()
	requireProxyShutDown(t, errCh)

	assert.DirExists(t, usr.ReadyFile)
}

func TestRemoveReadyFile(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// setup creates the fixture in dir and returns the path of
		// the ready file.
		setup func(t *testing.T, dir string) string
		err   error
		// kept is a path relative to dir that must exist afterward.
		kept string
	}{
		"missing file": {
			setup: func(_ *testing.T, dir string) string {
				return filepath.Join(dir, "ready")
			},
		},
		"regular file": {
			setup: func(t *testing.T, dir string) string {
				t.Helper()

				path := filepath.Join(dir, "ready")
				require.NoError(t, os.WriteFile(path, nil, 0o600))

				return path
			},
		},
		"symbolic link to a directory": {
			setup: func(t *testing.T, dir string) string {
				t.Helper()

				path := filepath.Join(dir, "ready")
				require.NoError(t, os.Mkdir(filepath.Join(dir, "target"), 0o755))
				require.NoError(t, os.Symlink("target", path))

				return path
			},
			kept: "target",
		},
		"empty directory": {
			setup: func(t *testing.T, dir string) string {
				t.Helper()

				path := filepath.Join(dir, "ready")
				require.NoError(t, os.Mkdir(path, 0o755))

				return path
			},
			err:  ErrReadyFileIsDir,
			kept: "ready",
		},
		"parent is a regular file": {
			setup: func(t *testing.T, dir string) string {
				t.Helper()

				require.NoError(t, os.WriteFile(filepath.Join(dir, "blocker"), nil, 0o600))

				return filepath.Join(dir, "blocker", "ready")
			},
			err:  syscall.ENOTDIR,
			kept: "blocker",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			path := tt.setup(t, dir)

			err := removeReadyFile(path)

			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)

				_, statErr := os.Lstat(path)
				require.ErrorIs(t, statErr, os.ErrNotExist)
			}

			if tt.kept != "" {
				_, statErr := os.Lstat(filepath.Join(dir, tt.kept))
				require.NoError(t, statErr)
			}
		})
	}
}

// TestRemoveReadyFileRemoveError checks the error for a file that the
// proxy cannot remove. Procfs refuses to remove its files for every
// user, so the test does not depend on file permissions, which root
// bypasses.
func TestRemoveReadyFileRemoveError(t *testing.T) {
	t.Parallel()

	if runtime.GOOS != "linux" {
		t.Skip("needs procfs")
	}

	err := removeReadyFile("/proc/version")
	require.ErrorContains(t, err, "removing ready file")
	require.ErrorIs(t, err, os.ErrPermission)
}

// TestProxyEnvoyLog checks which --log-path [Proxy] passes to Envoy.
// The stub envoy records its arguments.
//
//nolint:paralleltest,tparallel // sets PATH for the whole process.
func TestProxyEnvoyLog(t *testing.T) {
	tests := map[string]struct {
		// flag and policy are paths relative to the test directory.
		// An empty value leaves the setting out.
		flag   string
		policy string
		want   string
	}{
		"flag path": {
			flag: "logs/envoy.log",
			want: "logs/envoy.log",
		},
		"policy path overrides the flag": {
			flag:   "flag.log",
			policy: "policy/envoy.log",
			want:   "policy/envoy.log",
		},
		"no path": {},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			started, argsPath := stubEnvoy(t)

			dir := t.TempDir()
			policy := "egress: []\n"

			if tt.policy != "" {
				policy += "logging:\n" +
					"  envoy:\n" +
					"    path: " + filepath.Join(dir, tt.policy) + "\n"
			}

			usr := stubProxyUser(t, dir, policy)

			if tt.flag != "" {
				usr.EnvoyLogPath = filepath.Join(dir, tt.flag)
			}

			opts := proxyOptions{
				envoyPath:   envoyCommand,
				bindAddress: loopbackIPv4,
				httpPort:    freePort(t),
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			errCh := make(chan error, 1)

			go func() {
				errCh <- Proxy(ctx, usr, noManagedEnvoy(), opts)
			}()

			requireStubStarted(t, started)
			cancel()
			requireProxyShutDown(t, errCh)

			data, err := os.ReadFile(argsPath) //nolint:gosec // test fixture path.
			require.NoError(t, err)

			args := strings.Split(strings.TrimSpace(string(data)), "\n")

			if tt.want == "" {
				assert.NotContains(t, args, "--log-path")

				return
			}

			want := filepath.Join(dir, tt.want)

			i := slices.Index(args, "--log-path")
			require.GreaterOrEqual(t, i, 0, "envoy args: %v", args)
			require.Less(t, i+1, len(args))
			assert.Equal(t, want, args[i+1])

			// Envoy does not create the directory of its log file.
			assert.FileExists(t, want)

			if tt.flag != tt.want {
				assert.NoFileExists(t, filepath.Join(dir, tt.flag))
			}
		})
	}
}

// TestProxyEnvoyArgs checks the Envoy arguments of a proxy on each
// operating system. Only the arguments for a system other than Linux
// set --concurrency. The Envoy of those systems logs a debug line to
// its stderr when it counts the CPUs itself.
func TestProxyEnvoyArgs(t *testing.T) {
	t.Parallel()

	const (
		bootstrapPath = "/run/envoy.yaml"
		logPath       = "/logs/envoy.log"
	)

	// The arguments for every system.
	common := []string{
		"-c", bootstrapPath,
		"--log-level", "info",
		"--disable-hot-restart",
	}

	cpus := strconv.Itoa(runtime.NumCPU())

	tests := map[string]struct {
		goos    string
		logPath string
		// want holds the arguments that follow the common ones.
		want []string
	}{
		"linux with a log file": {
			goos:    osLinux,
			logPath: logPath,
			want:    []string{"--log-path", logPath},
		},
		"linux without a log file": {
			goos: osLinux,
		},
		"darwin with a log file": {
			goos:    "darwin",
			logPath: logPath,
			want:    []string{"--log-path", logPath, "--concurrency", cpus},
		},
		"darwin without a log file": {
			goos: "darwin",
			want: []string{"--concurrency", cpus},
		},
		"freebsd without a log file": {
			goos: "freebsd",
			want: []string{"--concurrency", cpus},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := proxyEnvoyArgs(tt.goos, bootstrapPath, "info", tt.logPath)
			assert.Equal(t, append(slices.Clone(common), tt.want...), got)
		})
	}
}

// TestProxyEnvoyConcurrency checks that [Proxy] passes the
// --concurrency argument of the host system to Envoy. See
// [proxyEnvoyArgs] for the systems that get the argument. The stub
// envoy records its arguments.
//
//nolint:paralleltest // sets PATH for the whole process.
func TestProxyEnvoyConcurrency(t *testing.T) {
	started, argsPath := stubEnvoy(t)

	dir := t.TempDir()
	usr := stubProxyUser(t, dir, "egress: []\n")
	usr.EnvoyLogPath = filepath.Join(dir, "envoy.log")

	opts := proxyOptions{
		envoyPath:   envoyCommand,
		bindAddress: loopbackIPv4,
		httpPort:    freePort(t),
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		errCh <- Proxy(ctx, usr, noManagedEnvoy(), opts)
	}()

	requireStubStarted(t, started)
	cancel()
	requireProxyShutDown(t, errCh)

	data, err := os.ReadFile(argsPath) //nolint:gosec // test fixture path.
	require.NoError(t, err)

	args := strings.Split(strings.TrimSpace(string(data)), "\n")

	if runtime.GOOS == osLinux {
		assert.NotContains(t, args, "--concurrency")

		return
	}

	i := slices.Index(args, "--concurrency")
	require.GreaterOrEqual(t, i, 0, "envoy args: %v", args)
	require.Less(t, i+1, len(args))
	assert.Equal(t, strconv.Itoa(runtime.NumCPU()), args[i+1])
}

// TestProxyCmdEnvoyLog checks which --log-path the proxy command passes
// to Envoy. Without the --envoy-log flag, the path holds the listen
// address, so each proxy and container mode write their own log file.
// The stub envoy records its arguments.
//
//nolint:paralleltest,tparallel // sets PATH and XDG_RUNTIME_DIR for the whole process.
func TestProxyCmdEnvoyLog(t *testing.T) {
	tests := map[string]struct {
		// args builds the --envoy-log arguments from the test
		// directory.
		args func(dir string) []string
		// want builds the expected log path from the test directory,
		// the runtime directory, and the port. An empty result means
		// that Envoy gets no --log-path.
		want func(dir, runtimeDir string, port int) string
	}{
		"no flag": {
			args: func(string) []string { return nil },
			want: func(_, runtimeDir string, port int) string {
				return filepath.Join(runtimeDir, "terrarium",
					"envoy-proxy-127.0.0.1-"+strconv.Itoa(port)+".log")
			},
		},
		"flag path": {
			args: func(dir string) []string {
				return []string{"--envoy-log", filepath.Join(dir, "logs", "envoy.log")}
			},
			want: func(dir, _ string, _ int) string {
				return filepath.Join(dir, "logs", "envoy.log")
			},
		},
		"empty flag": {
			args: func(string) []string { return []string{"--envoy-log="} },
			want: func(string, string, int) string { return "" },
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			started, argsPath := stubEnvoy(t)

			dir := t.TempDir()
			runtimeDir := t.TempDir()
			t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

			port := freePort(t)

			// The command sets the default of every user field, so
			// the test sets the policy path after it.
			usr := config.NewUser()
			cmd := proxyCmd(usr, noManagedEnvoy())
			usr.ConfigPath = stubProxyUser(t, dir, "egress: []\n").ConfigPath

			cmd.SetArgs(append([]string{
				"--envoy-path", envoyCommand,
				"--http-port", strconv.Itoa(port),
				"--ca-dir", filepath.Join(dir, "ca"),
				"--certs-dir", filepath.Join(dir, "certs"),
				"--envoy-config", filepath.Join(dir, "envoy.yaml"),
			}, tt.args(dir)...))

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			errCh := make(chan error, 1)

			go func() {
				errCh <- cmd.ExecuteContext(ctx)
			}()

			requireStubStarted(t, started)
			cancel()
			requireProxyShutDown(t, errCh)

			data, err := os.ReadFile(argsPath) //nolint:gosec // test fixture path.
			require.NoError(t, err)

			args := strings.Split(strings.TrimSpace(string(data)), "\n")

			// The bootstrap sits in the --envoy-config directory, and
			// its name holds the listen address too.
			i := slices.Index(args, "-c")
			require.GreaterOrEqual(t, i, 0, "envoy args: %v", args)
			require.Less(t, i+1, len(args))
			assert.Equal(t,
				filepath.Join(dir, "envoy-proxy-127.0.0.1-"+strconv.Itoa(port)+".yaml"),
				args[i+1])

			want := tt.want(dir, runtimeDir, port)
			if want == "" {
				assert.NotContains(t, args, "--log-path")

				return
			}

			i = slices.Index(args, "--log-path")
			require.GreaterOrEqual(t, i, 0, "envoy args: %v", args)
			require.Less(t, i+1, len(args))
			assert.Equal(t, want, args[i+1])
			assert.FileExists(t, want)
		})
	}
}

func TestProxyInstanceName(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		opts proxyOptions
		want string
	}{
		"IPv4 address": {
			opts: proxyOptions{bindAddress: "127.0.0.1", httpPort: 8080},
			want: "127.0.0.1-8080",
		},
		"another port": {
			opts: proxyOptions{bindAddress: "127.0.0.1", httpPort: 3128},
			want: "127.0.0.1-3128",
		},
		"IPv6 address": {
			opts: proxyOptions{bindAddress: "::1", httpPort: 8080},
			want: "::1-8080",
		},
		"IPv6 address with a zone": {
			opts: proxyOptions{bindAddress: "fe80::1%lo", httpPort: 8080},
			want: "fe80::1%lo-8080",
		},
		"path separators": {
			opts: proxyOptions{bindAddress: "../../etc", httpPort: 8080},
			want: ".._.._etc-8080",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := proxyInstanceName(tt.opts)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, got, filepath.Base(got), "the name must be one path element")
		})
	}
}

// TestGenerateProxyBootstrapPerListenAddress checks that proxies on
// different listen addresses that share every path flag each keep
// their own bootstrap. A shared file holds only the bootstrap of the
// proxy that started last.
func TestGenerateProxyBootstrapPerListenAddress(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	usr := stubProxyUser(t, dir, "egress: []\n")

	listens := []proxyOptions{
		{bindAddress: "127.0.0.1", httpPort: 18080},
		{bindAddress: "127.0.0.1", httpPort: 18081},
		{bindAddress: "::1", httpPort: 18080},
	}

	paths := make([]string, 0, len(listens))

	for _, opts := range listens {
		_, path, err := GenerateProxy(t.Context(), usr, opts, "")
		require.NoError(t, err)

		assert.Equal(t, dir, filepath.Dir(path))
		assert.NotEqual(t, usr.EnvoyConfigPath, path, "the path must not be the container-mode bootstrap")
		assert.NotContains(t, paths, path)

		paths = append(paths, path)
	}

	// Each bootstrap still names the listen address of its proxy
	// after the other proxies wrote theirs.
	for i, opts := range listens {
		bootstrap, err := os.ReadFile(paths[i])
		require.NoError(t, err)

		assert.Contains(t, string(bootstrap), opts.bindAddress)
		assert.Contains(t, string(bootstrap), "port_value: "+strconv.Itoa(opts.httpPort)+"\n")
	}
}

// TestProxyEnvoyLogError checks that [Proxy] returns the error before
// it starts Envoy when it cannot create the Envoy log file.
//
//nolint:paralleltest // sets PATH for the whole process.
func TestProxyEnvoyLogError(t *testing.T) {
	started, _ := stubEnvoy(t)

	dir := t.TempDir()
	usr := stubProxyUser(t, dir, "egress: []\n")

	// A regular file takes the place of the log directory.
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))

	usr.EnvoyLogPath = filepath.Join(blocker, "envoy.log")

	opts := proxyOptions{
		envoyPath:   envoyCommand,
		bindAddress: loopbackIPv4,
		httpPort:    freePort(t),
	}

	err := Proxy(t.Context(), usr, noManagedEnvoy(), opts)
	require.ErrorContains(t, err, "creating envoy log directory")

	assert.NoFileExists(t, started, "envoy must not start")
}

func TestPrepareProxyEnvoyLog(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// before is the content of a log file from an earlier run.
		// An empty value means that no file exists.
		before string
	}{
		"new file":      {},
		"existing file": {before: "earlier run\n"},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "logs", "envoy.log")

			if tt.before != "" {
				require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
				require.NoError(t, os.WriteFile(path, []byte(tt.before), 0o600))
			}

			require.NoError(t, prepareProxyEnvoyLog(path))

			got, err := os.ReadFile(path) //nolint:gosec // test fixture path.
			require.NoError(t, err)
			assert.Equal(t, tt.before, string(got))

			info, err := os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		})
	}
}

func TestPrepareProxyEnvoyLogError(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// setup creates the fixture in dir and returns the path of
		// the log file.
		setup func(t *testing.T, dir string) string
		err   string
	}{
		"directory is a regular file": {
			setup: func(t *testing.T, dir string) string {
				t.Helper()

				require.NoError(t, os.WriteFile(filepath.Join(dir, "blocker"), nil, 0o600))

				return filepath.Join(dir, "blocker", "envoy.log")
			},
			err: "creating envoy log directory",
		},
		"path is a directory": {
			setup: func(t *testing.T, dir string) string {
				t.Helper()

				path := filepath.Join(dir, "envoy.log")
				require.NoError(t, os.Mkdir(path, 0o755))

				return path
			},
			err: "creating envoy log file",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := tt.setup(t, t.TempDir())

			require.ErrorContains(t, prepareProxyEnvoyLog(path), tt.err)
		})
	}
}

// proxyHelperDirEnv names the variable that makes [TestProxyHelper]
// run [Proxy]. Its value is the directory of the policy of that proxy.
const proxyHelperDirEnv = "TERRARIUM_TEST_PROXY_HELPER_DIR"

// TestProxyEnvoyParentDeath checks that Envoy does not outlive a proxy
// that a signal kills without a shutdown. Envoy runs outside the
// process group of the proxy, so a signal to the group of the proxy
// does not reach it. A helper process runs [Proxy] with the stub envoy,
// and the test kills the helper with SIGKILL.
func TestProxyEnvoyParentDeath(t *testing.T) {
	t.Parallel()

	binDir := t.TempDir()
	stub, started, _ := stubEnvoyScript(binDir)
	require.NoError(t, os.WriteFile(filepath.Join(binDir, envoyCommand), []byte(stub), 0o755))

	helper := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestProxyHelper$")
	helper.Env = append(os.Environ(),
		proxyHelperDirEnv+"="+t.TempDir(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)

	require.NoError(t, helper.Start())

	requireStubStarted(t, started)

	pid := stubPID(t, started)

	// A stub that the death of the helper does not kill runs on
	// after the test. The error is ESRCH when the stub has exited.
	t.Cleanup(func() {
		syscall.Kill(pid, syscall.SIGKILL) //nolint:errcheck,gosec // see comment above.
	})

	require.NoError(t, helper.Process.Signal(syscall.SIGKILL))

	err := helper.Wait()

	var exitErr *exec.ExitError

	require.ErrorAs(t, err, &exitErr)

	assert.Eventually(t, func() bool {
		return processEnded(pid)
	}, 5*time.Second, 10*time.Millisecond, "envoy must not outlive the proxy")
}

// TestProxyHelper runs [Proxy] with the envoy on PATH until a signal
// stops or kills its process. [TestProxyEnvoyParentDeath],
// [TestProxyEnvoyOutputPipes], and [TestProxyHangup] start it in a
// process of their own. It skips in every other run of the tests.
func TestProxyHelper(t *testing.T) {
	t.Parallel()

	dir := os.Getenv(proxyHelperDirEnv)
	if dir == "" {
		t.Skip("runs only in the helper process of another test")
	}

	usr := stubProxyUser(t, dir, "egress: []\n")

	opts := proxyOptions{
		envoyPath:   envoyCommand,
		bindAddress: loopbackIPv4,
		httpPort:    freePort(t),
	}

	// The stub never listens, so Proxy waits for the listener until
	// a signal reaches this process.
	err := Proxy(t.Context(), usr, noManagedEnvoy(), opts)
	require.NoError(t, err)
}
