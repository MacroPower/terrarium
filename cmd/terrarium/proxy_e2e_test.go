package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/accesslog"
	"go.jacobcolvin.com/terrarium/certs"
	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/dnstest"
	"go.jacobcolvin.com/terrarium/envoy"
	"go.jacobcolvin.com/terrarium/eventstore"
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
// user state (for the generated MITM CA). Each setOpts function edits
// the proxy options before the proxy starts.
func startProxy(
	t *testing.T, policy, resolverAddr string, setOpts ...func(*proxyOptions),
) (*url.URL, *config.User) {
	t.Helper()

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	require.NoError(t, os.WriteFile(policyPath, []byte(policy), 0o644))

	usr := &config.User{
		ConfigPath:      policyPath,
		CADir:           filepath.Join(dir, "ca"),
		CertsDir:        filepath.Join(dir, "certs"),
		EnvoyConfigPath: filepath.Join(dir, "envoy.yaml"),
		ReadyFile:       filepath.Join(dir, "ready"),
	}

	port := freePort(t)

	opts := proxyOptions{
		bindAddress: "127.0.0.1",
		httpPort:    port,
	}
	if resolverAddr != "" {
		opts.resolvers = []string{resolverAddr}
	}

	for _, set := range setOpts {
		set(&opts)
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

	// The proxy creates the ready file after its own Envoy answers on
	// the listen address and after it opens the access log socket.
	requireReadyFile(t, usr.ReadyFile)

	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	require.NoError(t, err)

	// Envoy can still reset early requests while its workers start.
	// Send requests until a response with any status comes back, so
	// that the tests do not race the workers.
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

	caPath, tlsCfg := e2eCerts(t, "test.example", "plain.example")
	startTLSServer(t, "127.0.0.1:443", tlsCfg, "mitm upstream")
	startTLSServer(t, "127.0.0.1:18444", tlsCfg, "tunneled upstream")

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
		"            - path: /allowed.*\n" +
		"  - toFQDNs:\n" +
		"      - matchName: plain.example\n" +
		"    toPorts:\n" +
		"      - ports:\n" +
		"          - port: \"18444\"\n"

	bundlePath := filepath.Join(t.TempDir(), "bundle.pem")

	proxyURL, usr := startProxy(t, policy, dnsAddr, func(o *proxyOptions) {
		o.caBundleOut = bundlePath
	})

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

	// A client that trusts only the exported bundle verifies both the
	// MITM leaf and the upstream certificate of a tunneled host.
	bundleClient := proxyClient(t, proxyURL, loadPool(t, bundlePath))

	t.Run("bundle trusts the MITM leaf", func(t *testing.T) {
		assert.Equal(t, http.StatusOK,
			getStatus(t, bundleClient, "https://test.example/allowed"))
	})

	t.Run("bundle trusts tunneled hosts", func(t *testing.T) {
		assert.Equal(t, http.StatusOK,
			getStatus(t, bundleClient, "https://plain.example:18444/"))
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

// TestProxyE2EListenAddressNotShared checks that a second Envoy cannot
// bind the listen address of a running proxy. A second proxy that
// passes the listen address check at the same moment as the first
// proxy starts such an Envoy. When both Envoys bind the address, the
// kernel shares the connections between two policies.
//
//nolint:paralleltest // e2e tests run envoy subprocesses.
func TestProxyE2EListenAddressNotShared(t *testing.T) {
	requireEnvoy(t)

	proxyURL, usr := startProxy(t, "egress: []\n", "")

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	// The bootstrap of the running proxy names the same listen address.
	cmd := exec.CommandContext(ctx, "envoy",
		"-c", proxyBootstrapPath(usr), "--disable-hot-restart")

	// Envoy rejects the bootstrap without the probe token variable.
	cmd.Env = append(os.Environ(), envoy.ProxyProbeTokenEnv+"=second")

	out, err := cmd.CombinedOutput()
	require.NoError(t, ctx.Err(), "the second envoy must exit, output:\n%s", out)

	var exitErr *exec.ExitError

	require.ErrorAs(t, err, &exitErr, string(out))
	assert.Contains(t, string(out), "cannot bind")

	// The first proxy still serves the address.
	client := proxyClient(t, proxyURL, x509.NewCertPool())
	assert.Equal(t, http.StatusForbidden,
		getStatus(t, client, "http://anything.example/"))
}

// TestProxyE2ESimultaneousStart checks that exactly one of two proxies
// that start on the same address at the same moment keeps running. The
// other proxy returns an error, whether the listen address check or
// its Envoy finds the address taken.
//
//nolint:paralleltest // e2e tests run envoy subprocesses.
func TestProxyE2ESimultaneousStart(t *testing.T) {
	requireEnvoy(t)

	opts := proxyOptions{
		bindAddress: loopbackIPv4,
		httpPort:    freePort(t),
	}

	// See startProxy for the reason not to use t.Context.
	//nolint:usetesting // see comment above.
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 2)
	running := 2

	for range running {
		usr := stubProxyUser(t, t.TempDir(), "egress: []\n")

		go func() {
			errCh <- Proxy(ctx, usr, opts)
		}()
	}

	t.Cleanup(func() {
		cancel()

		for range running {
			select {
			case err := <-errCh:
				assert.NoError(t, err)
			case <-time.After(15 * time.Second):
				t.Error("proxy did not shut down")
			}
		}
	})

	select {
	case err := <-errCh:
		running--

		require.Error(t, err)
		assert.True(t,
			errors.Is(err, ErrListenAddressUnavailable) || errors.Is(err, ErrEnvoyNotRunning),
			"unexpected error: %v", err)

	case <-time.After(20 * time.Second):
		t.Fatal("both proxies keep running on one address")
	}

	addr := net.JoinHostPort(opts.bindAddress, strconv.Itoa(opts.httpPort))

	proxyURL, err := url.Parse("http://" + addr)
	require.NoError(t, err)

	waitProxyReady(t, proxyURL)

	client := proxyClient(t, proxyURL, x509.NewCertPool())
	assert.Equal(t, http.StatusForbidden,
		getStatus(t, client, "http://anything.example/"))

	select {
	case err := <-errCh:
		running--

		t.Fatalf("no proxy keeps running, the second proxy returned: %v", err)

	default:
	}
}

// startProbeEnvoy starts Envoy with the bootstrap at bootstrapPath and with
// probeToken in its environment, as [Proxy] does. It stops Envoy when
// the test ends.
func startProbeEnvoy(t *testing.T, bootstrapPath, probeToken string) {
	t.Helper()

	// See startProxy for the reason not to use t.Context.
	//nolint:usetesting // see comment above.
	ctx, cancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, "envoy",
		"-c", bootstrapPath, "--log-level", "error", "--disable-hot-restart")

	cmd.Env = append(os.Environ(), envoy.ProxyProbeTokenEnv+"="+probeToken)
	cmd.Stderr = os.Stderr
	cmd.WaitDelay = 5 * time.Second
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}

	err := cmd.Start()
	if err != nil {
		cancel()
		require.NoError(t, err)
	}

	t.Cleanup(func() {
		cancel()

		// Envoy exits with status 0 after SIGTERM, and Wait then
		// returns the error of the canceled context.
		waitErr := cmd.Wait()
		if waitErr != nil && !errors.Is(waitErr, context.Canceled) {
			t.Errorf("envoy did not stop cleanly: %v", waitErr)
		}
	})
}

// TestProxyE2EProbeAnswer checks the probe answer of Envoy. The wait
// of a proxy must accept the answer only when the Envoy that the proxy
// started serves the address with the bootstrap of that proxy. Two
// proxies that write their bootstraps to one path produce the other
// combinations.
//
//nolint:paralleltest // e2e tests run envoy subprocesses.
func TestProxyE2EProbeAnswer(t *testing.T) {
	requireEnvoy(t)

	const (
		own   = "0123456789abcdef0123456789abcdef"
		other = "ffffffffffffffffffffffffffffffff"
	)

	tests := map[string]struct {
		// bootstrapToken is the probe token in the bootstrap that
		// Envoy loads.
		bootstrapToken string
		// envToken is the probe token in the environment of Envoy.
		envToken string
		err      error
	}{
		"own envoy with own bootstrap": {
			bootstrapToken: own,
			envToken:       own,
		},
		"envoy of another proxy with own bootstrap": {
			bootstrapToken: own,
			envToken:       other,
			err:            ErrListenAddressUnavailable,
		},
		"own envoy with the bootstrap of another proxy": {
			bootstrapToken: other,
			envToken:       own,
			err:            ErrListenAddressUnavailable,
		},
		"envoy of another proxy with its own bootstrap": {
			bootstrapToken: other,
			envToken:       other,
			err:            ErrListenAddressUnavailable,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			port := freePort(t)
			cfg := parseProxyConfig(t, "egress: []\n")

			bootstrap, err := GenerateProxyEnvoyFromConfig(
				t.Context(), cfg, "", "", loopbackIPv4, port, nil, tt.bootstrapToken)
			require.NoError(t, err)

			path := filepath.Join(t.TempDir(), "envoy-proxy.yaml")
			require.NoError(t, os.WriteFile(path, []byte(bootstrap), 0o644))

			startProbeEnvoy(t, path, tt.envToken)

			addr := net.JoinHostPort(loopbackIPv4, strconv.Itoa(port))

			err = waitForProxyListener(t.Context(), addr, own, 15*time.Second)
			if tt.err == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.err)
		})
	}
}

// TestProxyE2ESharedBootstrap checks two proxies that start on the
// same address at the same moment and write their bootstraps to one
// path. The Envoy of one proxy can then load the bootstrap of the
// other proxy, which holds the policy of the other proxy.
//
// A proxy must report that it is ready only when its own Envoy serves
// the address with its own policy. At most one proxy keeps running.
// Both proxies return an error when the Envoy that takes the address
// loaded the bootstrap of the other proxy.
//
//nolint:paralleltest // e2e tests run envoy subprocesses.
func TestProxyE2ESharedBootstrap(t *testing.T) {
	requireEnvoy(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	// The startup timeout bounds the wait of a proxy whose Envoy
	// never serves the address.
	const envoySettings = "envoy:\n  startupTimeout: 5s\n"

	// The proxies differ in the status of a request for the upstream,
	// so the status shows which policy serves the address.
	policies := []struct {
		policy string
		status int
	}{
		{policy: envoySettings + "egress: []\n", status: http.StatusForbidden},
		{policy: envoySettings, status: http.StatusOK},
	}

	type proxyRun struct {
		usr    *config.User
		errCh  chan error
		status int
		done   bool
	}

	// The outcome depends on the order in which the proxies and their
	// Envoys run, so the test starts the pair several times.
	for round := range 3 {
		t.Run(strconv.Itoa(round), func(t *testing.T) {
			opts := proxyOptions{
				bindAddress: loopbackIPv4,
				httpPort:    freePort(t),
			}

			// See startProxy for the reason not to use t.Context.
			//nolint:usetesting // see comment above.
			ctx, cancel := context.WithCancel(context.Background())

			bootstrapDir := t.TempDir()
			runs := make([]*proxyRun, 0, len(policies))

			for _, p := range policies {
				dir := t.TempDir()

				usr := stubProxyUser(t, dir, p.policy)
				usr.EnvoyConfigPath = filepath.Join(bootstrapDir, "envoy.yaml")
				usr.ReadyFile = filepath.Join(dir, "ready")

				runs = append(runs, &proxyRun{
					usr:    usr,
					errCh:  make(chan error, 1),
					status: p.status,
				})
			}

			for _, r := range runs {
				go func() {
					r.errCh <- Proxy(ctx, r.usr, opts)
				}()
			}

			t.Cleanup(func() {
				cancel()

				for _, r := range runs {
					if r.done {
						continue
					}

					select {
					case err := <-r.errCh:
						assert.NoError(t, err)
					case <-time.After(15 * time.Second):
						t.Error("proxy did not shut down")
					}
				}
			})

			// The start ends when each proxy either returned or
			// reports that it is ready, and at least one returned.
			require.Eventually(t, func() bool {
				returned := 0
				settled := 0

				for _, r := range runs {
					if !r.done {
						select {
						case err := <-r.errCh:
							r.done = true

							assert.True(t,
								errors.Is(err, ErrListenAddressUnavailable) || errors.Is(err, ErrEnvoyNotRunning),
								"unexpected error: %v", err)

						default:
						}
					}

					_, statErr := os.Stat(r.usr.ReadyFile)

					switch {
					case r.done:
						returned++
						settled++

					case statErr == nil:
						settled++
					}
				}

				return returned > 0 && settled == len(runs)
			}, 30*time.Second, 20*time.Millisecond, "both proxies keep running on one address")

			proxyURL, err := url.Parse("http://" + net.JoinHostPort(opts.bindAddress, strconv.Itoa(opts.httpPort)))
			require.NoError(t, err)

			client := proxyClient(t, proxyURL, x509.NewCertPool())

			for _, r := range runs {
				if r.done {
					assert.NoFileExists(t, r.usr.ReadyFile, "a proxy that returned must not signal readiness")

					continue
				}

				// The proxy reports that it is ready, so its Envoy
				// must serve the address with its policy.
				t.Logf("the proxy that answers the upstream request with status %d keeps running", r.status)
				assert.Equal(t, r.status, getStatus(t, client, upstream.URL))
			}
		})
	}
}

// TestProxyE2EEnvoyLog checks that Envoy writes its process log to
// the file that the proxy names.
//
//nolint:paralleltest // e2e tests run envoy subprocesses.
func TestProxyE2EEnvoyLog(t *testing.T) {
	requireEnvoy(t)

	logPath := filepath.Join(t.TempDir(), "logs", "envoy.log")

	// Envoy logs its startup at the info level.
	policy := "logging:\n" +
		"  envoy:\n" +
		"    level: info\n" +
		"    path: " + logPath + "\n" +
		"egress: []\n"

	startProxy(t, policy, "")

	assert.Eventually(t, func() bool {
		info, err := os.Stat(logPath)

		return err == nil && info.Size() > 0
	}, 15*time.Second, 100*time.Millisecond, "envoy did not write to its log file")
}

// shortTempDir creates a temp dir directly under /tmp and removes it
// when the test ends. A Unix socket path has a small length limit, and
// the [testing.T.TempDir] path on macOS uses most of it.
func shortTempDir(t *testing.T) string {
	t.Helper()

	//nolint:usetesting // t.TempDir is too long, see comment above.
	dir, err := os.MkdirTemp("/tmp", "terrarium-")
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, os.RemoveAll(dir))
	})

	return dir
}

// countEnvoyEvents returns the number of Envoy events for domain in
// the stats DB at dbPath, or zero when the DB is not readable yet.
func countEnvoyEvents(t *testing.T, dbPath, domain string) int {
	t.Helper()

	db, err := eventstore.OpenReadOnly(t.Context(), dbPath)
	if err != nil {
		return 0
	}

	defer func() {
		assert.NoError(t, db.Close())
	}()

	var n int

	err = db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM events WHERE source = 'envoy' AND domain = ?`, domain).Scan(&n)
	if err != nil {
		return 0
	}

	return n
}

// countEnvoyStatusEvents returns the number of Envoy events with the
// HTTP status in the stats DB at dbPath, or zero when the DB is not
// readable yet.
func countEnvoyStatusEvents(t *testing.T, dbPath string, status int) int {
	t.Helper()

	db, err := eventstore.OpenReadOnly(t.Context(), dbPath)
	if err != nil {
		return 0
	}

	defer func() {
		assert.NoError(t, db.Close())
	}()

	var n int

	err = db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM events WHERE source = 'envoy' AND http_status = ?`, status).Scan(&n)
	if err != nil {
		return 0
	}

	return n
}

// rawRequestStatus writes request to the proxy at proxyURL over a new
// connection and returns the status of the response.
func rawRequestStatus(t *testing.T, proxyURL *url.URL, request string) int {
	t.Helper()

	dialer := net.Dialer{Timeout: 5 * time.Second}

	conn, err := dialer.DialContext(t.Context(), "tcp", proxyURL.Host)
	require.NoError(t, err)

	defer func() {
		assert.NoError(t, conn.Close())
	}()

	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))

	_, err = io.WriteString(conn, request)
	require.NoError(t, err)

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)

	defer func() {
		assert.NoError(t, resp.Body.Close())
	}()

	return resp.StatusCode
}

// TestProxyE2EStatsDefaultSocket checks that the proxy records Envoy
// access events when the policy omits stats.socket. The default
// socket sits in a per-user directory, so the proxy can create it
// without root.
//
//nolint:paralleltest // e2e tests set env and run envoy subprocesses.
func TestProxyE2EStatsDefaultSocket(t *testing.T) {
	requireEnvoy(t)

	runtimeDir := shortTempDir(t)
	dbPath := filepath.Join(t.TempDir(), "stats.db")

	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	policy := "stats:\n" +
		"  enabled: true\n" +
		"  path: " + dbPath + "\n" +
		"  flushIntervalMs: 100\n" +
		"egress: []\n"

	proxyURL, _ := startProxy(t, policy, "")
	client := proxyClient(t, proxyURL, x509.NewCertPool())

	fi, err := os.Stat(filepath.Join(runtimeDir, "terrarium", "accesslog.sock"))
	require.NoError(t, err)
	assert.Equal(t, os.ModeSocket, fi.Mode().Type())

	// Only the owner can connect. The events counted at the end of the
	// test show that Envoy, which runs as the same user, still does.
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	assert.Equal(t, http.StatusForbidden,
		getStatus(t, client, "http://recorded.example/"))

	assert.Eventually(t, func() bool {
		return countEnvoyEvents(t, dbPath, "recorded.example") > 0
	}, 15*time.Second, 250*time.Millisecond)

	// The proxy sent its probe request before the request of the
	// client. The probe is not traffic of a client, so the access
	// loggers skip it.
	assert.Zero(t, countEnvoyEvents(t, dbPath, envoy.ProxyProbeHost))

	// A request without a Host header has no authority. The access
	// loggers must not take it for the probe request.
	assert.Zero(t, countEnvoyStatusEvents(t, dbPath, http.StatusBadRequest))
	assert.Equal(t, http.StatusBadRequest,
		rawRequestStatus(t, proxyURL, "GET / HTTP/1.1\r\n\r\n"))

	assert.Eventually(t, func() bool {
		return countEnvoyStatusEvents(t, dbPath, http.StatusBadRequest) > 0
	}, 15*time.Second, 250*time.Millisecond)
}

// TestProxyBootstrapStatsSocketTooLong checks that Envoy accepts the
// proxy bootstrap when stats.socket is longer than the platform limit.
// Envoy rejects a bootstrap that names such a path, so the bootstrap
// must leave the access loggers out.
func TestProxyBootstrapStatsSocketTooLong(t *testing.T) {
	t.Parallel()
	requireEnvoy(t)

	cfg := parseProxyConfig(t, "stats:\n"+
		"  enabled: true\n"+
		"  socket: /"+strings.Repeat("a", accesslog.MaxSocketPathLen)+"\n"+
		"egress: []\n")

	bootstrap, err := GenerateProxyEnvoyFromConfig(
		t.Context(), cfg, "", "", "127.0.0.1", 8080, nil, "0123456789abcdef")
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "envoy-proxy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(bootstrap), 0o644))

	cmd := exec.CommandContext(t.Context(), "envoy",
		"--mode", "validate", "-c", path, "--disable-hot-restart")

	// Envoy rejects the bootstrap without the probe token variable.
	cmd.Env = append(os.Environ(), envoy.ProxyProbeTokenEnv+"=0123456789abcdef")

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
}
