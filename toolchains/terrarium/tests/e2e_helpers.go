package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"dagger/tests/internal/dagger"

	"golang.org/x/sync/errgroup"
)

const (
	nginxImage = "nginx:1-alpine"

	// testCAPath is where the test CA cert is mounted in the terrarium
	// container. The testrunner appends it to the system CA bundle at
	// runtime before terrarium init reads it.
	testCAPath = "/tmp/test-ca.pem"
)

// testCACert and testCAKey are a static CA used to sign upstream
// nginx certs in e2e tests. The testrunner installs the cert into
// the system CA bundle so Envoy's MITM DFP cluster validates
// upstream connections. Using static keys avoids Dagger cache
// identity issues with non-deterministic openssl output.
const testCACert = `-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUJNDHZkM4uC2Q8Op6qlLgogqpeSgwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjAzMjEwMDEzNTNaFw0yNjAzMjIw
MDEzNTNaMBIxEDAOBgNVBAMMB1Rlc3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCvvctvv5858asbRxaeeqF4I3HK0VS18PrJH4gAQVAOhXoLAWjl
I9gwwcwheTR4zV0ORj7yB7880foNg55D+hn5koCRaynfX85zo9LW3tOXQc8NCARZ
rk3GNNXv3dEKpMMBMZlQiScClynwaAZuM0sS+/h/WrvVndzjpvk+FFFYIOlpuX2Z
7BKk9KsRwNEAK3vUM7yrOk75KdYy7lBQUKlHlS2zMluc5ShULUdO4jYE7V1WaxXs
MmjhuuHBJZwog8+cNjhp4AKIZscOt4fTBN5bo+gbW0bE5BucBZ7ZI3ZeHtjNSLdO
Wq1Yh9duLtQvfbBYI1+f8zVCWKuyvTAfpDehAgMBAAGjUzBRMB0GA1UdDgQWBBS0
5y4jAwQuryg+qdzYE7OvdWimdDAfBgNVHSMEGDAWgBS05y4jAwQuryg+qdzYE7Ov
dWimdDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBjfyL0UFNk
niQbRPuVbnzVcudewezdcPTnrG8mrFmZyvqiEFuZjD6+jsl1HO2QFktgPxzUvPpQ
SvIJZudGoGU6JKVocJmRh3J4FV2g7Oy9G+quluWkLBzt3p833dJJOjQIhA37hgSX
SolqZc2a/KRK+0IMMDbfEegYdBJjeAJ+9NrpbFsbCY1PJcOv5Da1rHTSH0F6MKnr
p3n77uVAIgvuVpEn8eH5HvH9TvyDmnM+NqWgf1It1gnKYCBbCgp7TGkoVpgBLCl/
bp4A6fJpgfb2qwMy+Qr8tYcIuZxg4EbpPncV40RkTQiSE7tOs0drM7+MOc9Ar5FX
xQi9GLP+9OwE
-----END CERTIFICATE-----`

const testCAKey = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCvvctvv5858asb
RxaeeqF4I3HK0VS18PrJH4gAQVAOhXoLAWjlI9gwwcwheTR4zV0ORj7yB7880foN
g55D+hn5koCRaynfX85zo9LW3tOXQc8NCARZrk3GNNXv3dEKpMMBMZlQiScClynw
aAZuM0sS+/h/WrvVndzjpvk+FFFYIOlpuX2Z7BKk9KsRwNEAK3vUM7yrOk75KdYy
7lBQUKlHlS2zMluc5ShULUdO4jYE7V1WaxXsMmjhuuHBJZwog8+cNjhp4AKIZscO
t4fTBN5bo+gbW0bE5BucBZ7ZI3ZeHtjNSLdOWq1Yh9duLtQvfbBYI1+f8zVCWKuy
vTAfpDehAgMBAAECggEACp/6ZzCsZ87GO7l0UvypclHpsoJ29bVN9VkMURuhw13Y
70Zm5r5yiR5hyhpK6AzMKD/YQoeYqOgt2DO/Z9zX/Hc+XV6fdT25F/hIhZqvUFWJ
twAMJ0i6/ExgdfRDQszU2sMfHSWVnYxDpXyTaKpZXRqI4+rL562KIOUM7CWMLSnw
Ao2wBawZEN7I/urIB+UldmnVpHUTVpurXyVKtCA0WyxlZTmzvzPy0S/kmNQOWGEU
56BPeDjmfkRbwyb20oHhqb1442YSqJYiCbsOVEdqx40uDyLO1Z8NmyOKhVOVac9b
RoME7MfdywUZhh//iub7bWCELnOMeVXiiLokBHW2uwKBgQD19FtwdbuAAWhsKVyA
1c5kWIhHc6DVdqXYRnWeVpIykXDdSiwiyTA9EqAtgVJZNAHIVhnUiVLXSDjDwCoi
pqsIvtgwcqdgtDNiSebREuKN5A0pBqonhvfTNq2oE2TGdckpDBeKz4wyhIq98MlB
StZu8xRCs9V8zJ3ki+Dz+MZXEwKBgQC2604vQpOXWlS0DmuSQnrC/fJQN9gH2S9s
QgAYje3bR99kvHeEm3EKNs/x5XshQHmGxNfxfSL3a1liEyMVGZgU5Zw4MRr46KK9
0xMCak+ck1ZFoUFx6labhL1FmdqWgjuiQnVVI5EyXZ7HjKXjHjJMdiI3JHIwhckA
KcZhgQLI+wKBgQDECXxIas6D/JtKer0sQz46ZQZaTSNIgUU22RIunjnw7FPVTaVY
JJu6Ufoxyv3j87vn/higesP4q6vy+lubOtTgJ50RIJGgVoEOOnEq+65wAfErXhCJ
aN5nDxHjAXI1bPRlLyokjcDlExeyxRTkYc4AqObhM41Z542B+KvYSdVs2QKBgQCs
5MKUxw/r+lSfkBW7PBz+27tCeVY3LOC3Kbcffl95aXjMpZsueyIgbmikkqyMZH25
lasqtYXsaMomekIpunRWJCVBs6Bz7qeMVsrb+JJhQ55C2EWcn8vW2WNxOxgyNMya
9MgkfibKfVUL9nQBtVQDk5GJn2hTVtEC13mMRb3VKwKBgQDUYODufA++KllEVab5
QMsYNUhplMhBOWa24vCeXAv0S6i68c3FnRe8MHcIcOi6MB12eyczf6D1jLfhB4Nq
hUCPXYjkLczq5yMBkHP9TcVRJdTW/MN0qf0D4FeES6V6sYecs2ChoPm1M0lcmT3B
cNKi3ae9Ls32whS4EwZdMgWeNA==
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
				"EXEC:echo TCP_FORWARD_OK",
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

func dnsRefused(domain, desc string) assertion {
	return assertion{Type: "dns_refused", Domain: domain, Desc: desc}
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
	name           string
	config         string
	bindings       []serviceBinding
	assertions     []assertion
	envoy          bool
	packages       []string
	rootAssertions []assertion
	initCommand    string
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
// executed container for stdout/stderr inspection.
func withPostExec(fn func(ctx context.Context, variant string, ctr *dagger.Container) error) testOption {
	return funcOption(func(tc *testCase) {
		tc.postExec = fn
	})
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
			testrunnerBin := dag.Terrarium().TestRunner()
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
	dist := dag.Terrarium().Build()

	containers, err := dag.Terrarium().BuildImages(ctx, dagger.TerrariumBuildImagesOpts{
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
