package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
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

// TestGenerateProxyEnvoyFromConfigStatsSocketDefault uses t.Setenv,
// which is incompatible with t.Parallel().
//
//nolint:paralleltest // see comment above.
func TestGenerateProxyEnvoyFromConfigStatsSocketDefault(t *testing.T) {
	tests := map[string]struct {
		env  map[string]string
		want string
	}{
		"runtime dir set": {
			env: map[string]string{
				"HOME":            "/Users/user",
				"XDG_STATE_HOME":  "",
				"XDG_RUNTIME_DIR": "/run/user/4242",
			},
			want: "path: /run/user/4242/terrarium/accesslog.sock",
		},
		"no runtime dir": {
			env: map[string]string{
				"HOME":            "/Users/user",
				"XDG_STATE_HOME":  "",
				"XDG_RUNTIME_DIR": "",
			},
			want: "path: /Users/user/.local/state/terrarium/accesslog.sock",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cfg := parseProxyConfig(t, "stats:\n  enabled: true\negress: []\n")

			out, err := GenerateProxyEnvoyFromConfig(
				t.Context(), cfg, "", "", "127.0.0.1", 8080, nil)
			require.NoError(t, err)

			assert.Contains(t, out, "terrarium_accesslog")
			assert.Contains(t, out, tt.want)
			assert.NotContains(t, out, config.DefaultStatsSocket)
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

// stubEnvoy puts a stub envoy first on PATH. The stub writes its
// arguments to the args file, one per line, then writes its process
// ID to the started file and sleeps. It never listens, so the proxy
// stays in startup until the test opens the listener or cancels the
// context.
func stubEnvoy(t *testing.T) (string, string) {
	t.Helper()

	binDir := t.TempDir()
	started := filepath.Join(binDir, "started")
	args := filepath.Join(binDir, "args")

	stub := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > '" + args + "'\n" +
		// The rename makes the file appear with the process ID in it.
		"echo $$ > '" + started + ".tmp'\n" +
		"mv '" + started + ".tmp' '" + started + "'\n" +
		"exec sleep 60\n"
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "envoy"), []byte(stub), 0o755))

	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	return started, args
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

	data, err := os.ReadFile(started) //nolint:gosec // test fixture path.
	require.NoError(t, err)

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	require.NoError(t, err)

	// Signal 0 finds a process that runs, and one that exited but
	// that the proxy did not reap.
	require.ErrorIs(t, syscall.Kill(pid, 0), syscall.ESRCH, "stub envoy must not outlive the proxy")
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
				errCh <- Proxy(ctx, usr, opts)
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
// after the listener accepts connections, and removes it on shutdown.
// The stub envoy never listens, so the test opens the listener itself.
//
//nolint:paralleltest,tparallel // sets PATH for the whole process.
func TestProxyReadyFile(t *testing.T) {
	tests := map[string]struct {
		bindAddress string
	}{
		"IPv4 bind address": {bindAddress: loopbackIPv4},
		"IPv6 bind address": {bindAddress: loopbackIPv6},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			requireLoopback(t, tt.bindAddress)

			started, _ := stubEnvoy(t)

			dir := t.TempDir()
			usr := stubProxyUser(t, dir, "egress: []\n")
			usr.ReadyFile = filepath.Join(dir, "ready")

			// An earlier run that did not shut down cleanly leaves its file.
			require.NoError(t, os.WriteFile(usr.ReadyFile, nil, 0o600))

			opts := proxyOptions{
				bindAddress: tt.bindAddress,
				httpPort:    freePort(t),
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			errCh := make(chan error, 1)

			go func() {
				errCh <- Proxy(ctx, usr, opts)
			}()

			requireStubStarted(t, started)
			assert.NoFileExists(t, usr.ReadyFile, "the ready file must not exist before the listener is up")

			listenProxyPort(t, opts)
			requireReadyFile(t, usr.ReadyFile)

			cancel()
			requireProxyShutDown(t, errCh)

			assert.NoFileExists(t, usr.ReadyFile, "shutdown must remove the ready file")
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
		bindAddress: loopbackIPv4,
		httpPort:    freePort(t),
	}

	listenProxyPort(t, opts)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		errCh <- Proxy(ctx, usr, opts)
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
		bindAddress: loopbackIPv4,
		httpPort:    freePort(t),
	}

	errCh := make(chan error, 1)

	go func() {
		errCh <- Proxy(t.Context(), usr, opts)
	}()

	requireStubStarted(t, started)
	listenProxyPort(t, opts)

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
				bindAddress: loopbackIPv4,
				httpPort:    freePort(t),
			}

			err := Proxy(t.Context(), usr, opts)
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
		bindAddress: loopbackIPv4,
		httpPort:    freePort(t),
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		errCh <- Proxy(ctx, usr, opts)
	}()

	requireStubStarted(t, started)
	listenProxyPort(t, opts)
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
				bindAddress: loopbackIPv4,
				httpPort:    freePort(t),
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			errCh := make(chan error, 1)

			go func() {
				errCh <- Proxy(ctx, usr, opts)
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
		bindAddress: loopbackIPv4,
		httpPort:    freePort(t),
	}

	err := Proxy(t.Context(), usr, opts)
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
