package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/certs"
	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/dnstest"
)

// requireEnvoy skips the test when no envoy binary is on PATH.
func requireEnvoy(t *testing.T) {
	t.Helper()

	_, err := exec.LookPath("envoy")
	if err != nil {
		t.Skip("envoy binary not on PATH")
	}
}

// requireUDPLoopback skips the test when UDP datagrams do not flow
// over loopback (some sandboxes drop them), since Envoy's c-ares
// resolver queries the test DNS server over UDP.
func requireUDPLoopback(t *testing.T) {
	t.Helper()

	addr := dnstest.StartServer(t, "127.0.0.1")

	m := new(dns.Msg)
	m.SetQuestion("probe.example.", dns.TypeA)

	c := &dns.Client{Timeout: 2 * time.Second}

	_, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Skipf("UDP loopback unavailable: %v", err)
	}
}

// e2eCerts generates a CA and per-domain leaves in a temp dir and
// returns the CA path plus a TLS config serving the leaves by SNI.
func e2eCerts(t *testing.T, domains ...string) (string, *tls.Config) {
	t.Helper()

	caDir := t.TempDir()
	leafDir := t.TempDir()

	caPath, _, err := certs.GenerateCA(caDir)
	require.NoError(t, err)

	tlsCerts := make([]tls.Certificate, 0, len(domains))

	for _, d := range domains {
		require.NoError(t, certs.GenerateLeaf(caDir, leafDir, d))

		cert, err := tls.LoadX509KeyPair(
			filepath.Join(leafDir, d, "cert.pem"),
			filepath.Join(leafDir, d, "key.pem"),
		)
		require.NoError(t, err)

		tlsCerts = append(tlsCerts, cert)
	}

	return caPath, &tls.Config{Certificates: tlsCerts, MinVersion: tls.VersionTLS12}
}

// startTLSServer serves a fixed body over TLS on addr using cfg,
// failing the test if the port is taken.
func startTLSServer(t *testing.T, addr string, cfg *tls.Config, body string) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, err := io.WriteString(w, body)
		if err != nil {
			t.Logf("upstream write: %v", err)
		}
	})

	lc := net.ListenConfig{}

	ln, err := lc.Listen(t.Context(), "tcp", addr)
	require.NoError(t, err)

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	go func() {
		serveErr := srv.Serve(tls.NewListener(ln, cfg))
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			t.Logf("upstream serve: %v", serveErr)
		}
	}()

	t.Cleanup(func() {
		assert.NoError(t, srv.Close())
	})
}

// startProxy writes the policy, runs [Proxy] in the background on a
// fresh port, waits for readiness, and returns the proxy URL and the
// user state (for the generated MITM CA).
func startProxy(t *testing.T, policy, resolverAddr string) (*url.URL, *config.User) {
	t.Helper()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(policy), 0o644))

	usr := &config.User{
		ConfigPath:      policyPath,
		CADir:           filepath.Join(dir, "ca"),
		CertsDir:        filepath.Join(dir, "certs"),
		EnvoyConfigPath: filepath.Join(dir, "envoy.yaml"),
	}

	port := freePort(t)

	opts := proxyOptions{
		bindAddress: "127.0.0.1",
		httpPort:    port,
	}
	if resolverAddr != "" {
		opts.resolvers = []string{resolverAddr}
	}

	// context.Background, not t.Context: t.Context is canceled before
	// cleanup functions run, which would race the proxy's graceful
	// SIGTERM drain registered below. The explicit cancel owns the
	// proxy's lifetime.
	//nolint:usetesting // see comment above.
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)

	go func() {
		errCh <- Proxy(ctx, usr, opts)
	}()

	t.Cleanup(func() {
		cancel()

		select {
		case err := <-errCh:
			assert.NoError(t, err)
		case <-time.After(15 * time.Second):
			t.Error("proxy did not shut down")
		}
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	require.NoError(t, waitForListener(ctx, addr, 15*time.Second))

	proxyURL, err := url.Parse("http://" + addr)
	require.NoError(t, err)

	// waitForListener only confirms the socket accepts connections;
	// Envoy may still reset early requests while its workers warm up.
	// Probe at the HTTP layer until a real response (any status) comes
	// back so tests don't race the warmup.
	waitProxyReady(t, proxyURL)

	return proxyURL, usr
}

// waitProxyReady polls the proxy with a plain HTTP request until Envoy
// responds at the HTTP layer (any status), tolerating the connection
// resets Envoy emits before its workers finish warming up.
func waitProxyReady(t *testing.T, proxyURL *url.URL) {
	t.Helper()

	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	deadline := time.Now().Add(15 * time.Second)

	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(
			t.Context(), http.MethodGet, "http://proxy-readiness.invalid/", http.NoBody)
		require.NoError(t, err)

		resp, err := client.Do(req)
		if err == nil {
			assert.NoError(t, resp.Body.Close())

			return
		}

		time.Sleep(100 * time.Millisecond)
	}

	t.Fatal("proxy did not become ready")
}

// freePort reserves an ephemeral TCP port and returns it.
func freePort(t *testing.T) int {
	t.Helper()

	lc := net.ListenConfig{}

	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok)
	require.NoError(t, ln.Close())

	return addr.Port
}

// proxyClient returns an HTTP client routed through proxyURL that
// trusts roots for upstream TLS.
func proxyClient(t *testing.T, proxyURL *url.URL, roots *x509.CertPool) *http.Client {
	t.Helper()

	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				MinVersion: tls.VersionTLS12,
			},
		},
	}
}

// loadPool reads a PEM file into a cert pool.
func loadPool(t *testing.T, path string) *x509.CertPool {
	t.Helper()

	pem, err := os.ReadFile(path) //nolint:gosec // test fixture path.
	require.NoError(t, err)

	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pem))

	return pool
}

// getStatus performs a GET through client and returns the status
// code, requiring transport success.
func getStatus(t *testing.T, client *http.Client, rawURL string) int {
	t.Helper()

	resp, err := client.Get(rawURL) //nolint:noctx // test client has a timeout.
	require.NoError(t, err)

	defer func() {
		assert.NoError(t, resp.Body.Close())
	}()

	return resp.StatusCode
}

//nolint:paralleltest // e2e tests bind fixed ports and run envoy subprocesses.
func TestProxyE2EPassthrough(t *testing.T) {
	requireEnvoy(t)
	requireUDPLoopback(t)

	caPath, tlsCfg := e2eCerts(t, "test.example", "sub.wild.example")
	startTLSServer(t, "127.0.0.1:18443", tlsCfg, "hello from upstream")

	dnsAddr := dnstest.StartServer(t, "127.0.0.1")

	policy := "egress:\n" +
		"  - toFQDNs:\n" +
		"      - matchName: test.example\n" +
		"      - matchPattern: '*.wild.example'\n" +
		"    toPorts:\n" +
		"      - ports:\n" +
		"          - port: \"18443\"\n"

	proxyURL, _ := startProxy(t, policy, dnsAddr)
	client := proxyClient(t, proxyURL, loadPool(t, caPath))

	t.Run("allowed exact FQDN", func(t *testing.T) {
		assert.Equal(t, http.StatusOK,
			getStatus(t, client, "https://test.example:18443/"))
	})

	t.Run("allowed wildcard FQDN", func(t *testing.T) {
		assert.Equal(t, http.StatusOK,
			getStatus(t, client, "https://sub.wild.example:18443/"))
	})

	t.Run("wildcard depth enforced", func(t *testing.T) {
		// a.b.wild.example exceeds the single-label * depth; the
		// internal RBAC chain closes the tunnel mid-TLS rather than
		// returning an HTTP status.
		_, err := client.Get("https://a.b.wild.example:18443/") //nolint:noctx,bodyclose // error expected.
		require.Error(t, err)
	})

	t.Run("denied domain gets 403 at CONNECT", func(t *testing.T) {
		_, err := client.Get("https://denied.example:18443/") //nolint:noctx,bodyclose // error expected.
		require.ErrorContains(t, err, "Forbidden")
	})

	t.Run("denied port gets 403 at CONNECT", func(t *testing.T) {
		_, err := client.Get("https://test.example:19999/") //nolint:noctx,bodyclose // error expected.
		require.ErrorContains(t, err, "Forbidden")
	})

	t.Run("plain HTTP denied without port 80 rules", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden,
			getStatus(t, client, "http://test.example/"))
	})
}

//nolint:paralleltest // e2e tests bind fixed ports, set env, and run envoy subprocesses.
func TestProxyE2EMITM(t *testing.T) {
	requireEnvoy(t)
	requireUDPLoopback(t)

	// The MITM upstream connects on the TLS default port; binding 443
	// needs CAP_NET_BIND_SERVICE or a permissive
	// ip_unprivileged_port_start (macOS allows it unprivileged).
	lc := net.ListenConfig{}

	probe, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:443")
	if err != nil {
		t.Skipf("cannot bind 127.0.0.1:443: %v", err)
	}

	require.NoError(t, probe.Close())

	caPath, tlsCfg := e2eCerts(t, "test.example")
	startTLSServer(t, "127.0.0.1:443", tlsCfg, "mitm upstream")

	// The proxy validates its re-encrypted upstream connection against
	// the system bundle; point it at the test CA.
	t.Setenv("SSL_CERT_FILE", caPath)

	dnsAddr := dnstest.StartServer(t, "127.0.0.1")

	policy := "egress:\n" +
		"  - toFQDNs:\n" +
		"      - matchName: test.example\n" +
		"    toPorts:\n" +
		"      - ports:\n" +
		"          - port: \"443\"\n" +
		"        rules:\n" +
		"          http:\n" +
		"            - path: /allowed.*\n"

	proxyURL, usr := startProxy(t, policy, dnsAddr)

	// The client sees the proxy's MITM leaf, so it must trust the
	// generated terrarium CA, not the upstream's.
	client := proxyClient(t, proxyURL, loadPool(t, filepath.Join(usr.CADir, "ca.pem")))

	t.Run("allowed path", func(t *testing.T) {
		assert.Equal(t, http.StatusOK,
			getStatus(t, client, "https://test.example/allowed"))
	})

	t.Run("denied path", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden,
			getStatus(t, client, "https://test.example/forbidden"))
	})
}

//nolint:paralleltest // e2e tests run envoy subprocesses.
func TestProxyE2EBlocked(t *testing.T) {
	requireEnvoy(t)

	// Blocked mode performs no DNS resolution, so it runs even where
	// UDP loopback is unavailable.
	proxyURL, _ := startProxy(t, "egress: []\n", "")
	client := proxyClient(t, proxyURL, x509.NewCertPool())

	t.Run("CONNECT denied", func(t *testing.T) {
		_, err := client.Get("https://anything.example/") //nolint:noctx,bodyclose // error expected.
		require.ErrorContains(t, err, "Forbidden")
	})

	t.Run("plain HTTP denied", func(t *testing.T) {
		assert.Equal(t, http.StatusForbidden,
			getStatus(t, client, "http://anything.example/"))
	})
}
