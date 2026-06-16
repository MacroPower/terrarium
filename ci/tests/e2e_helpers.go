package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"dagger/tests/internal/dagger"

	"golang.org/x/sync/errgroup"
)

const (
	nginxImage = "nginx:1-alpine"

	// testCAPath is where the test CA cert is mounted in the terrarium
	// container. The testrunner appends it to the system CA bundle at
	// runtime before terrarium init reads it.
	testCAPath = "/tmp/test-ca.pem"

	// envoyLogPath is the default Envoy process log file path inside
	// the container. With HOME=/root and no XDG_RUNTIME_DIR, the XDG
	// state fallback resolves to this path.
	envoyLogPath = "/root/.local/state/terrarium/envoy.log"

	// statsDBPath is the default SQLite event store path inside the
	// container. terrarium stats is invoked against this file to
	// assert access events were recorded.
	statsDBPath = "/root/.local/share/terrarium/stats.db"
)

// testCACert and testCAKey are a static CA used to sign upstream
// nginx certs in e2e tests. The testrunner installs the cert into
// the system CA bundle so Envoy's MITM DFP cluster validates
// upstream connections. Using static keys avoids Dagger cache
// identity issues with non-deterministic openssl output.
const testCACert = `-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUBC5S7BcMBCj2jX+HZBaxgKgRNGQwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjA0MTAyMTI0MDNaFw0zNjA0MDcy
MTI0MDNaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCdHmJODQHF0/yGiMycO4atR9fXGWzDiS1Xa5T1d/8tiiiWv80K
1klKXjXBACe8qacxW/TtyTa4DXtUtytdy4MhlTJpHCkWTIk6t83Pj3YXm0nCndOM
PQW/ZLwdrNDTWI1o3FPueQblI67QD1ceAfs3YCEGaRDp+xwqssgvgj5/boCMcibm
HTz5kiEgwxfyeF/nEfrgsQyVMB4fODYzBnfHtvUPWukXTNs1/aevZY3RQ5gPWjTa
bmvksCSByI0Ss9TOYSXRNryT9a7B76nBEsWfK3nHNfT2yYMBi62gN3XpzCZokaL9
dN3vZ7gV1PAh9SZojFZtZBQ3PWR7HnSWGKXdAgMBAAGjUzBRMB0GA1UdDgQWBBSh
73q9XcJxqUC4lDvy0+ighKDsvzAfBgNVHSMEGDAWgBSh73q9XcJxqUC4lDvy0+ig
hKDsvzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBe7xL1s9Yd
xCfaGp9MY/djnY7ooMw8tr8vv5jsJPv9ivGHyL+Pabxg9vRN821TLtuvqO3KB1Se
AhObGXF2acojtPsOt1at6D9wqCanEOKyIlx8dr1NCbQVmwsEReJC1YLe1z/o+Dsx
X0cpJ3Xy5WhHo3JWCoVdQY/I4qonhYCnLQzx6xnse1MKooeTkJbfRA9LikysuYB6
ZiLfLCRHsXaPNUX0aNC8eKzsq/QycVKk1v0b4L5p5ROraAAa5xIFz1xbfascp3pg
yVJKpXIx3Kad+LPXRo07ALfkuS/TxuIobzE1rQYlI/gLzVjodI7/fwbiUdKjTJzp
ssNR5atdtwy+
-----END CERTIFICATE-----`

const testCAKey = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCdHmJODQHF0/yG
iMycO4atR9fXGWzDiS1Xa5T1d/8tiiiWv80K1klKXjXBACe8qacxW/TtyTa4DXtU
tytdy4MhlTJpHCkWTIk6t83Pj3YXm0nCndOMPQW/ZLwdrNDTWI1o3FPueQblI67Q
D1ceAfs3YCEGaRDp+xwqssgvgj5/boCMcibmHTz5kiEgwxfyeF/nEfrgsQyVMB4f
ODYzBnfHtvUPWukXTNs1/aevZY3RQ5gPWjTabmvksCSByI0Ss9TOYSXRNryT9a7B
76nBEsWfK3nHNfT2yYMBi62gN3XpzCZokaL9dN3vZ7gV1PAh9SZojFZtZBQ3PWR7
HnSWGKXdAgMBAAECgf9uWLQHWC7tHXGs8KiBlJUb4si6vy2j/1FIcFNbqaLwgD8V
HZKVN9AaDvy4QQfBuni4gJSlMPrHDd7YmgDUfJAfbusMVsfm7ndlirgHkYwWnzsH
GCALfupI1p4m1s+EL83l14Kky5ZNwM74fxXQ9tt4jAr0dZrN57XGRyxECi6fhFii
deScuwwqCW6wfdqahdWT+1x901YHCmIuvw50lB46R4k7Xx3cCjB7HHLHOmhzLbLl
i29606G6UWR72dGr6GeFaomOruJ/sFeMnAT60tu9lTV5QmeXoEJX0nSGeVPPgXJl
zb2ljPjM61By0txo52A65ABERheCVjoYSY7h7xECgYEAymF0940cxs4UTUBKS7kL
cefRWi1sBQ+G4xyfBl9mJcdh/Hgt5WYJOQ/kD24it650KY/K43x3Rp7cNDZrUNnN
IqViJMNQ0sSphSgKLzBP7uQrVBj1M9CkWGomGAXetNIT+pF71wRcutHImX6diA1H
teVsj7cZidQaLOnwWF3YyN8CgYEAxr8D9Fr2I7M4hiyXa/YBQyNdqmUOqF7KYSLe
sBZMxla64AWscfLd7FLVYy68sYBZvAJQ/7wmaWl1ibs1l/SUlsnRSOemx9ph90gT
goZu8+/3o7z+MIeUgsSNVnWJhVL98C0lFFAeMXA2r9jPGSUTiAQPF1rreOFJMmzj
ZWWo3MMCgYBQdwkzd9auMLefs2UW0F79jecODKs7I95EpFeSCBIsCScrY3kUEUqv
dmL9w5NoJqOm9rX7Vrxxxq3U0KJAhihqkwj/huy2sFyaRb4u3u2ZFP0pNbcgP99o
C+RTftn6WOB6qqdraR+ZY9l3NgFaW7VcW/ia93je9QbnPqhB6iZMTwKBgQCioAai
WhPyXmIwGCjHJIMf5r5sAUkfKIE9PoUtXPHxkWJUkQ/sJajGCXmmMMYiED5dAyA4
QkLEGpEc5F0UPAOh5v4jQ7pK6j0jVIzyTwJXBNKD3s+38hjpb9+fEYo32BMGBkrC
9lPebE2zUhsUHix/LaMTn0fyn5V/d24SuD6WdQKBgQCMRTViy0HfOI+E51k47ZXC
OKM387ppeDLZ63OzI/NnZmZHVwJiuia7v1kieSqF9AZN4Ttam9xioBJZL3Kl9rsN
2VgYX/6X/yr0P4qQ3ncexVMpua6H6LlB1pdw76wMod/0sCBpT+xML5zJLeYVFBUP
OhAlU0aSuY8qaUtgUd9wxQ==
-----END PRIVATE KEY-----`

// serviceBinding pairs a hostname alias with a Dagger service for
// container service binding.
type serviceBinding struct {
	alias   string
	service *dagger.Service
}

// targetService creates an nginx service container that serves static content
// on ports 80 and 443 with a TLS cert signed by the shared test CA. The
// hostname parameter sets the service's discoverable hostname for DNS
// resolution within the Dagger network.
func targetService(hostname, nginxConf string) serviceBinding {
	svc := dag.Container().
		From(nginxImage).
		WithNewFile("/ca/ca.pem", testCACert).
		WithNewFile("/ca/ca-key.pem", testCAKey).
		WithNewFile("/docker-entrypoint.d/99-ca-signed-cert.sh",
			"#!/bin/sh\n"+
				"apk add --no-cache openssl >/dev/null 2>&1\n"+
				"openssl req -newkey rsa:2048 -keyout /etc/nginx/key.pem "+
				"-out /tmp/csr.pem -nodes -subj \"/CN="+hostname+"\" 2>/dev/null\n"+
				"echo \"subjectAltName=DNS:"+hostname+"\" > /tmp/ext.cnf\n"+
				"openssl x509 -req -in /tmp/csr.pem -CA /ca/ca.pem -CAkey /ca/ca-key.pem "+
				"-CAcreateserial -out /etc/nginx/cert.pem -days 1 "+
				"-extfile /tmp/ext.cnf 2>/dev/null\n",
			dagger.ContainerWithNewFileOpts{Permissions: 0o755},
		).
		WithNewFile("/etc/nginx/conf.d/default.conf", nginxConf).
		WithExposedPort(80).
		WithExposedPort(443).
		AsService().
		WithHostname(hostname)

	return serviceBinding{alias: hostname, service: svc}
}

// targetServiceOnPort creates an nginx service container that serves static
// content on a single custom port with a TLS cert signed by the shared test
// CA. Used for tests that need services on non-standard ports.
func targetServiceOnPort(hostname string, port int) serviceBinding {
	nginxConf := fmt.Sprintf(`server {
    listen %d ssl;
    ssl_certificate /etc/nginx/cert.pem;
    ssl_certificate_key /etc/nginx/key.pem;
    location / {
        return 200 "OK\n";
        add_header Content-Type text/plain;
    }
}`, port)

	svc := dag.Container().
		From(nginxImage).
		WithNewFile("/ca/ca.pem", testCACert).
		WithNewFile("/ca/ca-key.pem", testCAKey).
		WithNewFile("/docker-entrypoint.d/99-ca-signed-cert.sh",
			"#!/bin/sh\n"+
				"apk add --no-cache openssl >/dev/null 2>&1\n"+
				"openssl req -newkey rsa:2048 -keyout /etc/nginx/key.pem "+
				"-out /tmp/csr.pem -nodes -subj \"/CN="+hostname+"\" 2>/dev/null\n"+
				"echo \"subjectAltName=DNS:"+hostname+"\" > /tmp/ext.cnf\n"+
				"openssl x509 -req -in /tmp/csr.pem -CA /ca/ca.pem -CAkey /ca/ca-key.pem "+
				"-CAcreateserial -out /etc/nginx/cert.pem -days 1 "+
				"-extfile /tmp/ext.cnf 2>/dev/null\n",
			dagger.ContainerWithNewFileOpts{Permissions: 0o755},
		).
		WithNewFile("/etc/nginx/conf.d/default.conf", nginxConf).
		WithExposedPort(port).
		AsService().
		WithHostname(hostname)

	return serviceBinding{alias: hostname, service: svc}
}

// udpEchoService creates a socat-based UDP echo service that responds with
// "UDP_ECHO_OK" on the specified port. Used for testing UDP TPROXY forwarding
// through Envoy.
func udpEchoService(hostname string, port int) serviceBinding {
	svc := dag.Container().
		From("debian:13-slim").
		WithExec([]string{"sh", "-c", "apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*"}).
		WithExposedPort(port, dagger.ContainerWithExposedPortOpts{
			Protocol: dagger.NetworkProtocolUdp,
		}).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{
				"socat",
				fmt.Sprintf("UDP-RECVFROM:%d,fork,reuseaddr", port),
				"EXEC:echo UDP_ECHO_OK",
			},
		}).
		WithHostname(hostname)

	return serviceBinding{alias: hostname, service: svc}
}

// tcpEchoService creates a socat-based TCP echo service that responds with
// "TCP_FORWARD_OK" on the specified port. Used for testing tcpForwards
// without HTTP/TLS.
func tcpEchoService(hostname string, port int) serviceBinding {
	svc := dag.Container().
		From("debian:13-slim").
		WithExec([]string{"sh", "-c", "apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*"}).
		WithExposedPort(port).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{
				"socat",
				fmt.Sprintf("TCP-LISTEN:%d,fork,reuseaddr", port),
				`SYSTEM:echo TCP_FORWARD_OK; sleep 1`,
			},
		}).
		WithHostname(hostname)

	return serviceBinding{alias: hostname, service: svc}
}

// testOption configures a [testCase] during construction via [newTestCase].
// Both [serviceBinding] and [funcOption] implement this interface.
type testOption interface {
	apply(*testCase)
}

// funcOption adapts a plain function to the [testOption] interface.
// Used by the with* option functions ([withAssertions], [withoutEnvoy],
// [withPackages], [withRootAssertions], [withInitCommand],
// [withLoopbackPort], [withConfigReplacements], [withPostExec]).
type funcOption func(*testCase)

// apply calls f to configure tc.
func (f funcOption) apply(tc *testCase) { f(tc) }

// apply appends b to the test case's service bindings list.
func (b serviceBinding) apply(tc *testCase) {
	tc.bindings = append(tc.bindings, b)
}

// assertion represents a single test assertion. Create instances with
// the assertion builder functions ([httpAllowed], [networkDenied], etc.).
// Serialized to JSON for the testrunner binary.
type assertion struct {
	Type     string `json:"type"`
	URL      string `json:"url,omitempty"`
	Method   string `json:"method,omitempty"`
	Header   string `json:"header,omitempty"`
	Body     string `json:"body,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Addr     string `json:"addr,omitempty"`
	Expected string `json:"expected,omitempty"`
	File     string `json:"file,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
	Domain   string `json:"domain,omitempty"`
	UID      string `json:"uid,omitempty"`
	Desc     string `json:"desc"`
}

func httpAllowed(url, desc string) assertion {
	return assertion{Type: "http_allowed", URL: url, Desc: desc}
}

func httpDenied(url, desc string) assertion {
	return assertion{Type: "http_denied", URL: url, Desc: desc}
}

func networkDenied(url, desc string) assertion {
	return assertion{Type: "network_denied", URL: url, Desc: desc}
}

func l7Allowed(url, method, body, desc string) assertion {
	return assertion{Type: "l7_allowed", URL: url, Method: method, Body: body, Desc: desc}
}

func l7Denied(url, method, desc string) assertion {
	return assertion{Type: "l7_denied", URL: url, Method: method, Desc: desc}
}

func l7BodyWithHeader(url, method, header, body, desc string) assertion {
	return assertion{Type: "l7_body_with_header", URL: url, Method: method, Header: header, Body: body, Desc: desc}
}

func l7DeniedWithHeader(url, method, header, desc string) assertion {
	return assertion{Type: "l7_denied_with_header", URL: url, Method: method, Header: header, Desc: desc}
}

func httpsPassthrough(url, body, desc string) assertion {
	return assertion{Type: "https_passthrough", URL: url, Body: body, Desc: desc}
}

func udpAllowed(host string, port int, expected, desc string) assertion {
	return assertion{Type: "udp_allowed", Host: host, Port: port, Expected: expected, Desc: desc}
}

func udpDenied(host string, port int, desc string) assertion {
	return assertion{Type: "udp_denied", Host: host, Port: port, Desc: desc}
}

func udpSend(host string, port int, desc string) assertion {
	return assertion{Type: "udp_send", Host: host, Port: port, Desc: desc}
}

func tcpForward(addr, expected, desc string) assertion {
	return assertion{Type: "tcp_forward", Addr: addr, Expected: expected, Desc: desc}
}

func dnsNoError(domain, desc string) assertion {
	return assertion{Type: "dns_noerror", Domain: domain, Desc: desc}
}

func dnsForwarded(domain, desc string) assertion {
	return assertion{Type: "dns_forwarded", Domain: domain, Desc: desc}
}

func dnsBlocked(domain, desc string) assertion {
	return assertion{Type: "dns_blocked", Domain: domain, Desc: desc}
}

func fileGrep(file, pattern, desc string) assertion {
	return assertion{Type: "file_grep", File: file, Pattern: pattern, Desc: desc}
}

func envoyUID(uid, desc string) assertion {
	return assertion{Type: "envoy_uid", UID: uid, Desc: desc}
}

func pingAllowed(host, desc string) assertion {
	return assertion{Type: "ping_allowed", Host: host, Desc: desc}
}

func pingDenied(host, desc string) assertion {
	return assertion{Type: "ping_denied", Host: host, Desc: desc}
}

// testSpec mirrors the testrunner's spec type for JSON serialization.
type testSpec struct {
	ConfigPath      string      `json:"configPath"`
	ValidateEnvoy   bool        `json:"validateEnvoy"`
	InitCommand     string      `json:"initCommand"`
	ExtraCACertPath string      `json:"extraCACertPath,omitempty"`
	LoopbackPort    int         `json:"loopbackPort,omitempty"`
	Assertions      []assertion `json:"assertions"`
	RootAssertions  []assertion `json:"rootAssertions"`
}

// testCase encapsulates the e2e test lifecycle: config validation,
// terrarium init, readiness wait, and assertion execution.
// Create instances with [newTestCase].
type testCase struct {
	name               string
	config             string
	bindings           []serviceBinding
	assertions         []assertion
	envoy              bool
	packages           []string
	rootAssertions     []assertion
	initCommand        string
	loopbackPort       int
	configReplacements map[string]string
	postExec           func(ctx context.Context, variant string, ctr *dagger.Container) error
}

// newTestCase creates a new [testCase] with Envoy validation enabled by
// default. Options are applied in order, so later values override earlier
// ones for single-value fields.
func newTestCase(name, config string, opts ...testOption) *testCase {
	tc := &testCase{
		name:   name,
		config: config,
		envoy:  true,
	}
	for _, opt := range opts {
		opt.apply(tc)
	}
	return tc
}

// withAssertions returns a [testOption] that sets assertions run as the
// unprivileged dev user (UID 1000).
func withAssertions(assertions ...assertion) testOption {
	return funcOption(func(tc *testCase) {
		tc.assertions = assertions
	})
}

// withoutEnvoy returns a [testOption] that disables the Envoy config
// validation step. Use for tests where no Envoy listeners are created
// (deny-all, CIDR-only, unrestricted).
func withoutEnvoy() testOption {
	return funcOption(func(tc *testCase) {
		tc.envoy = false
	})
}

// withPackages returns a [testOption] that installs the given apt packages
// in the test container before running assertions.
func withPackages(packages ...string) testOption {
	return funcOption(func(tc *testCase) {
		tc.packages = packages
	})
}

// withRootAssertions returns a [testOption] that sets assertions run as
// root. Used for checks that require elevated privileges such as process
// inspection, ping via terrarium exec, and dig queries.
func withRootAssertions(assertions ...assertion) testOption {
	return funcOption(func(tc *testCase) {
		tc.rootAssertions = assertions
	})
}

// withInitCommand returns a [testOption] that overrides the default
// "sleep infinity" child command passed to terrarium init.
func withInitCommand(initCommand string) testOption {
	return funcOption(func(tc *testCase) {
		tc.initCommand = initCommand
	})
}

// withLoopbackPort returns a [testOption] that configures the testrunner
// to start an HTTP listener on the given localhost port before starting
// terrarium. Used to verify that loopback traffic remains reachable under
// deny-all policies.
func withLoopbackPort(port int) testOption {
	return funcOption(func(tc *testCase) {
		tc.loopbackPort = port
	})
}

// withConfigReplacements returns a [testOption] that maps placeholder strings
// in the config to hostnames. During [testCase.run], each placeholder is
// replaced with the IP address resolved via getent hosts inside the terrarium
// container, where the service bindings are active. This avoids resolving IPs
// in a separate container that may see different addresses.
func withConfigReplacements(replacements map[string]string) testOption {
	return funcOption(func(tc *testCase) {
		tc.configReplacements = replacements
	})
}

// withPostExec returns a [testOption] that registers a callback invoked
// after the testrunner completes successfully. The callback receives the
// executed container for file and output inspection.
func withPostExec(fn func(ctx context.Context, variant string, ctr *dagger.Container) error) testOption {
	return funcOption(func(tc *testCase) {
		tc.postExec = fn
	})
}

// combinePostExec runs the supplied callbacks sequentially against
// the same container. The first error short-circuits the chain;
// the chain wraps the error with a dump of the full stats DB so
// dagger surfaces the whole state, not just the first failed
// assertion. (dagger captures the returned error; arbitrary stderr
// writes from this Go process are not surfaced in the call output.)
func combinePostExec(
	fns ...func(ctx context.Context, variant string, ctr *dagger.Container) error,
) func(ctx context.Context, variant string, ctr *dagger.Container) error {
	return func(ctx context.Context, variant string, ctr *dagger.Container) error {
		for _, fn := range fns {
			err := fn(ctx, variant, ctr)
			if err != nil {
				return fmt.Errorf("%w\n--- diagnostic stats dump ---\n%s",
					err, statsDebugDump(ctx, ctr))
			}
		}

		return nil
	}
}

// statsDebugDump returns a single multi-line string with the
// summary and full event list from the container's stats DB.
// Used by [combinePostExec] to attach DB state to assertion
// failure messages.
func statsDebugDump(ctx context.Context, ctr *dagger.Container) string {
	var b strings.Builder

	if out, err := runTerrarium(ctx, ctr,
		"stats", "--db", statsDBPath, "--format", "json",
	); err == nil {
		fmt.Fprintf(&b, "summary:\n%s\n", out)
	} else {
		fmt.Fprintf(&b, "summary: <error: %v>\n", err)
	}

	if out, err := runTerrarium(ctx, ctr,
		"stats", "list", "--db", statsDBPath, "--format", "json", "--limit", "200",
	); err == nil {
		fmt.Fprintf(&b, "list (all sources):\n%s\n", out)
	} else {
		fmt.Fprintf(&b, "list: <error: %v>\n", err)
	}

	return b.String()
}

// statsListContains runs `terrarium stats list --format json` against
// the SQLite event store inside the container and checks the output
// for the given substring. Replaces the file-tail-based access log
// assertions used before the gRPC ALS event store landed.
func statsListContains(substr, msg string) func(ctx context.Context, variant string, ctr *dagger.Container) error {
	return func(ctx context.Context, _ string, ctr *dagger.Container) error {
		out, err := runTerrarium(ctx, ctr,
			"stats", "list",
			"--db", statsDBPath,
			"--format", "json",
			"--limit", "200",
		)
		if err != nil {
			return err
		}

		if !strings.Contains(out, substr) {
			return fmt.Errorf("%s\nstats list output:\n%s", msg, out)
		}

		return nil
	}
}

// runTerrarium executes a terrarium subcommand inside the test
// container and returns the captured stdout. The error already
// carries the invoked command for context, so callers should not
// re-wrap it with the same information.
func runTerrarium(ctx context.Context, ctr *dagger.Container, args ...string) (string, error) {
	cmd := append([]string{"/usr/local/bin/terrarium"}, args...)

	out, err := ctr.WithExec(cmd).Stdout(ctx)
	if err != nil {
		return out, fmt.Errorf("running terrarium %s: %w", strings.Join(args, " "), err)
	}

	return out, nil
}

// statsListMatchesField parses the JSON output of `terrarium stats
// list` and asserts that at least one row has every key=value pair
// in want. Pass source="" to skip the --source filter; otherwise it
// becomes `--source <source>`. Keys must use the snake_case JSON
// tags from listRow in cmd/terrarium/stats.go (e.g. "http_status",
// "http_path", "domain"). The strictness statsListContains lacks
// today.
func statsListMatchesField(source string, want map[string]any, msg string) func(ctx context.Context, variant string, ctr *dagger.Container) error {
	return func(ctx context.Context, _ string, ctr *dagger.Container) error {
		args := []string{"stats", "list", "--db", statsDBPath, "--format", "json", "--limit", "200"}
		if source != "" {
			args = append(args, "--source", source)
		}

		out, err := runTerrarium(ctx, ctr, args...)
		if err != nil {
			return err
		}

		var rows []map[string]any

		err = json.Unmarshal([]byte(out), &rows)
		if err != nil {
			return fmt.Errorf("decoding stats list: %w\noutput:\n%s", err, out)
		}

		for _, row := range rows {
			if rowMatches(row, want) {
				return nil
			}
		}

		return fmt.Errorf("%s\nwant fields: %s\nstats list output:\n%s",
			msg, formatWantFields(want), out)
	}
}

// formatWantFields renders a map[string]any with sorted keys so
// failure messages diff cleanly across runs (Go map iteration order
// is intentionally randomized).
func formatWantFields(want map[string]any) string {
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, want[k]))
	}

	return "{" + strings.Join(parts, ", ") + "}"
}

// rowMatches reports whether row contains every key=value pair in
// want. Numeric comparisons coerce JSON numbers (always float64) and
// expected ints to float64 so callers can pass int literals.
func rowMatches(row, want map[string]any) bool {
	for k, w := range want {
		got, ok := row[k]
		if !ok {
			return false
		}

		if !valueEquals(got, w) {
			return false
		}
	}

	return true
}

// valueEquals compares JSON-decoded values for the types
// statsListMatchesField actually accepts: bool, string, int,
// int64, float64. JSON numbers always decode as float64, so int
// and int64 literals from callers are coerced via float64
// comparison. Unknown want types fall back to reflect.DeepEqual,
// which keeps the helper safe against future map/slice values
// (rather than panicking on `got == want` for non-comparable types).
func valueEquals(got, want any) bool {
	switch w := want.(type) {
	case int:
		if g, ok := got.(float64); ok {
			return g == float64(w)
		}
	case int64:
		if g, ok := got.(float64); ok {
			return g == float64(w)
		}
	case float64:
		if g, ok := got.(float64); ok {
			return g == w
		}
	case string:
		if g, ok := got.(string); ok {
			return g == w
		}
	case bool:
		if g, ok := got.(bool); ok {
			return g == w
		}
	}

	return reflect.DeepEqual(got, want)
}

// statsListNonEmptyDomain asserts that at least one row from
// `terrarium stats list --source firewall --format json` has a
// non-empty `domain` field. Used to verify dnscache reverse
// attribution populated the firewall row.
func statsListNonEmptyDomain(source, msg string) func(ctx context.Context, variant string, ctr *dagger.Container) error {
	return func(ctx context.Context, _ string, ctr *dagger.Container) error {
		args := []string{"stats", "list", "--db", statsDBPath, "--format", "json", "--limit", "200"}
		if source != "" {
			args = append(args, "--source", source)
		}

		out, err := runTerrarium(ctx, ctr, args...)
		if err != nil {
			return err
		}

		var rows []map[string]any

		err = json.Unmarshal([]byte(out), &rows)
		if err != nil {
			return fmt.Errorf("decoding stats list: %w\noutput:\n%s", err, out)
		}

		for _, row := range rows {
			if d, _ := row["domain"].(string); d != "" {
				return nil
			}
		}

		return fmt.Errorf("%s\nstats list output:\n%s", msg, out)
	}
}

// statsTopReturns runs `terrarium stats top` with the given extra
// args (the helper supplies --db and --format=json) and asserts the
// JSON output is a non-empty array. When bucket is non-empty, also
// asserts at least one row's "bucket" field equals it exactly. Pass
// bucket="" to assert only that the result set is non-empty.
func statsTopReturns(args []string, bucket, msg string) func(ctx context.Context, variant string, ctr *dagger.Container) error {
	return func(ctx context.Context, _ string, ctr *dagger.Container) error {
		full := append([]string{"stats", "top", "--db", statsDBPath, "--format", "json"}, args...)

		out, err := runTerrarium(ctx, ctr, full...)
		if err != nil {
			return err
		}

		var rows []topJSONRow

		err = json.Unmarshal([]byte(out), &rows)
		if err != nil {
			return fmt.Errorf("decoding stats top: %w\noutput:\n%s", err, out)
		}

		if len(rows) == 0 {
			return fmt.Errorf("%s\nempty stats top output for args %v\noutput:\n%s",
				msg, args, out)
		}

		if bucket == "" {
			return nil
		}

		for _, r := range rows {
			if r.Bucket == bucket {
				return nil
			}
		}

		return fmt.Errorf("%s\nno bucket %q in stats top output for args %v\noutput:\n%s",
			msg, bucket, args, out)
	}
}

// topJSONRow mirrors the JSON shape of `terrarium stats top` output.
// Defined here rather than imported from the terrarium binary to
// keep the e2e module's import surface narrow.
type topJSONRow struct {
	Bucket string `json:"bucket"`
	Count  int    `json:"count"`
}

// statsSummaryNonZero asserts that the no-subcommand `terrarium
// stats --format json` summary returns at least one row with a
// non-zero count. Exercises [runStatsSummary].
func statsSummaryNonZero(msg string) func(ctx context.Context, variant string, ctr *dagger.Container) error {
	return func(ctx context.Context, _ string, ctr *dagger.Container) error {
		out, err := runTerrarium(ctx, ctr,
			"stats", "--db", statsDBPath, "--format", "json",
		)
		if err != nil {
			return err
		}

		var rows []struct {
			Source   string `json:"source"`
			Decision string `json:"decision"`
			Count    int    `json:"count"`
		}

		err = json.Unmarshal([]byte(out), &rows)
		if err != nil {
			return fmt.Errorf("decoding stats summary: %w\noutput:\n%s", err, out)
		}

		for _, r := range rows {
			if r.Count > 0 {
				return nil
			}
		}

		return fmt.Errorf("%s\nstats summary output:\n%s", msg, out)
	}
}

// statsListCSVHeader asserts that `terrarium stats list --format csv`
// emits the canonical header row before any data rows. The header
// must be the lowercase column names from [runStatsList].
func statsListCSVHeader(msg string) func(ctx context.Context, variant string, ctr *dagger.Container) error {
	want := "time,source,decision,domain,port,protocol,method,path,status,flags,reason"

	return func(ctx context.Context, _ string, ctr *dagger.Container) error {
		out, err := runTerrarium(ctx, ctr,
			"stats", "list", "--db", statsDBPath, "--format", "csv", "--limit", "5",
		)
		if err != nil {
			return err
		}

		first, _, _ := strings.Cut(out, "\n")
		if strings.TrimSpace(first) != want {
			return fmt.Errorf("%s\nwant first line: %s\ngot:\n%s", msg, want, out)
		}

		return nil
	}
}

// statsTopCSVHeader asserts that `terrarium stats top --format csv`
// emits the `<groupBy>,count` header. The CSV path is separate from
// the JSON path in [runStatsTop]; this exercises it.
func statsTopCSVHeader(msg string) func(ctx context.Context, variant string, ctr *dagger.Container) error {
	want := "domain,count"

	return func(ctx context.Context, _ string, ctr *dagger.Container) error {
		out, err := runTerrarium(ctx, ctr,
			"stats", "top", "--db", statsDBPath, "--format", "csv", "--by", "domain",
		)
		if err != nil {
			return err
		}

		first, _, _ := strings.Cut(out, "\n")
		if strings.TrimSpace(first) != want {
			return fmt.Errorf("%s\nwant first line: %s\ngot:\n%s", msg, want, out)
		}

		return nil
	}
}

// statsListCursor exercises pagination: list with --limit 1, capture
// next_cursor from the last row, then re-query with --cursor and
// confirm the second page returns a different first row id.
func statsListCursor(msg string) func(ctx context.Context, variant string, ctr *dagger.Container) error {
	return func(ctx context.Context, _ string, ctr *dagger.Container) error {
		out, err := runTerrarium(ctx, ctr,
			"stats", "list", "--db", statsDBPath, "--format", "json", "--limit", "1",
		)
		if err != nil {
			return err
		}

		var page1 []map[string]any

		err = json.Unmarshal([]byte(out), &page1)
		if err != nil {
			return fmt.Errorf("decoding page 1: %w\noutput:\n%s", err, out)
		}

		if len(page1) != 1 {
			return fmt.Errorf("%s: page 1 returned %d rows, want 1\noutput:\n%s",
				msg, len(page1), out)
		}

		cursor, _ := page1[0]["next_cursor"].(string)
		if cursor == "" {
			return fmt.Errorf("%s: page 1 missing next_cursor\noutput:\n%s", msg, out)
		}

		out2, err := runTerrarium(ctx, ctr,
			"stats", "list", "--db", statsDBPath, "--format", "json",
			"--limit", "1", "--cursor", cursor,
		)
		if err != nil {
			return err
		}

		var page2 []map[string]any

		err = json.Unmarshal([]byte(out2), &page2)
		if err != nil {
			return fmt.Errorf("decoding page 2: %w\noutput:\n%s", err, out2)
		}

		// The cursor is `WHERE id < cursor` server-side. With many
		// events generated by this test, page 2 is expected to
		// have at least one row, and that row cannot equal page
		// 1's row (different SQL id). Compare on the full row to
		// avoid false-failing when two events share the same
		// RFC3339 second.
		if len(page2) == 0 {
			return fmt.Errorf("%s: page 2 returned no rows; pagination didn't advance\noutput:\n%s",
				msg, out2)
		}

		// Strip next_cursor before comparison: page 1 always
		// carries it, page 2 only if a third page exists.
		p1 := withoutKey(page1[0], "next_cursor")
		p2 := withoutKey(page2[0], "next_cursor")

		if reflect.DeepEqual(p1, p2) {
			return fmt.Errorf("%s: page 2 row matches page 1 row; cursor did not advance\npage1:\n%s\npage2:\n%s",
				msg, out, out2)
		}

		return nil
	}
}

// withoutKey returns a shallow copy of m with key removed.
func withoutKey(m map[string]any, key string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		if k == key {
			continue
		}

		out[k] = v
	}

	return out
}

// envoyLogContains returns a [withPostExec] callback that reads the
// Envoy process log file from the container and checks that it
// contains the given substring.
func envoyLogContains(substr, msg string) func(ctx context.Context, variant string, ctr *dagger.Container) error {
	return fileContains(envoyLogPath, substr, msg)
}

// fileContains returns a [withPostExec] callback that reads a file from
// the container and checks that it contains the given substring.
func fileContains(path, substr, msg string) func(ctx context.Context, variant string, ctr *dagger.Container) error {
	return func(ctx context.Context, _ string, ctr *dagger.Container) error {
		contents, err := ctr.File(path).Contents(ctx)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		if !strings.Contains(contents, substr) {
			return fmt.Errorf("%s\n%s:\n%s", msg, path, contents)
		}

		return nil
	}
}

// run executes the test across all [e2eVariants] in parallel. For each
// variant it builds a terrarium container, mounts the testrunner binary
// and spec, and runs the test. On failure it distinguishes between
// assertion failures and infrastructure crashes via exit codes.
func (tc *testCase) run(ctx context.Context) error {
	s := testSpec{
		ConfigPath:      "/etc/terrarium/config.yaml",
		ValidateEnvoy:   tc.envoy,
		InitCommand:     tc.initCommand,
		ExtraCACertPath: testCAPath,
		LoopbackPort:    tc.loopbackPort,
		Assertions:      tc.assertions,
		RootAssertions:  tc.rootAssertions,
	}
	if s.InitCommand == "" {
		s.InitCommand = "sleep infinity"
	}

	specJSON, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("%s: marshaling spec: %w", tc.name, err)
	}

	g, ctx := errgroup.WithContext(ctx)

	for _, variant := range e2eVariants {
		g.Go(func() error {
			ctr, err := terrariumContainer(ctx, variant, tc.config, tc.bindings)
			if err != nil {
				return fmt.Errorf("%s/%s: %w", tc.name, variant, err)
			}

			// Resolve hostnames and substitute placeholders in the config.
			for placeholder, hostname := range tc.configReplacements {
				ctr = ctr.WithExec([]string{
					"sh", "-c",
					fmt.Sprintf(`ip=$(getent hosts %s | awk '{print $1}') && sed -i "s/%s/$ip/g" %s`,
						hostname, placeholder, s.ConfigPath),
				})
			}

			// Install packages if needed.
			if len(tc.packages) > 0 {
				ctr = ctr.WithExec([]string{"apt-get", "update", "-qq"})
				for _, pkg := range tc.packages {
					ctr = ctr.WithExec([]string{"apt-get", "install", "-y", "-qq", pkg})
				}
			}

			// Mount testrunner binary and spec.
			testrunnerBin := dag.Ci().TestRunner()
			ctr = ctr.
				WithFile("/usr/local/bin/testrunner", testrunnerBin).
				WithNewFile("/tmp/spec.json", string(specJSON))

			// Run testrunner.
			ctr = ctr.WithExec(
				[]string{"testrunner", "--spec", "/tmp/spec.json"},
				dagger.ContainerWithExecOpts{InsecureRootCapabilities: true},
			)

			_, err = ctr.Stdout(ctx)
			if err != nil {
				var execErr *dagger.ExecError
				if errors.As(err, &execErr) {
					if execErr.ExitCode == 2 {
						return fmt.Errorf("%s/%s: infrastructure error\nstdout:\n%s\nstderr:\n%s",
							tc.name, variant, execErr.Stdout, execErr.Stderr)
					}
					return fmt.Errorf("%s/%s: %w\nstdout:\n%s\nstderr:\n%s",
						tc.name, variant, err, execErr.Stdout, execErr.Stderr)
				}
				return fmt.Errorf("%s/%s: %w", tc.name, variant, err)
			}

			if tc.postExec != nil {
				if err := tc.postExec(ctx, variant, ctr); err != nil {
					return fmt.Errorf("%s/%s: %w", tc.name, variant, err)
				}
			}

			return nil
		})
	}

	return g.Wait()
}

// terrariumContainer builds a terrarium container for the given variant,
// mounts the test config at the expected path, and applies service bindings.
// The returned container is configured but not yet executed.
func terrariumContainer(
	ctx context.Context,
	variant string,
	configContent string,
	bindings []serviceBinding,
) (*dagger.Container, error) {
	dist := dag.Ci().Build()

	containers, err := dag.Ci().BuildImages(ctx, dagger.CiBuildImagesOpts{
		Version: "v0.0.0-e2e",
		Dist:    dist,
		Variant: variant,
	})
	if err != nil {
		return nil, fmt.Errorf("building %s images: %w", variant, err)
	}

	if len(containers) == 0 {
		return nil, fmt.Errorf("no containers built for variant %s", variant)
	}

	// Select the container matching the engine's native platform.
	nativePlatform, err := dag.DefaultPlatform(ctx)
	if err != nil {
		return nil, fmt.Errorf("querying default platform: %w", err)
	}

	var ctr *dagger.Container
	for i := range containers {
		p, err := containers[i].Platform(ctx)
		if err != nil {
			return nil, fmt.Errorf("querying container platform: %w", err)
		}
		if p == nativePlatform {
			ctr = &containers[i]
			break
		}
	}
	if ctr == nil {
		return nil, fmt.Errorf("no container for platform %s in variant %s", nativePlatform, variant)
	}

	// Mount the config at an explicit path decoupled from XDG resolution.
	ctr = ctr.WithNewFile("/etc/terrarium/config.yaml", configContent)

	// Mount the test CA cert for the testrunner to install at runtime
	// (before terrarium init reads the CA bundle for Envoy config).
	ctr = ctr.WithNewFile(testCAPath, testCACert)

	// Apply service bindings.
	for _, b := range bindings {
		ctr = ctr.WithServiceBinding(b.alias, b.service)
	}

	return ctr, nil
}
