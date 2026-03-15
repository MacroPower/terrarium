package main

import (
	"context"
	"fmt"

	"dagger/tests/internal/dagger"
)

const (
	nginxImage = "nginx:1-alpine"
)

// serviceBinding pairs a hostname alias with a Dagger service for
// container service binding.
type serviceBinding struct {
	alias   string
	service *dagger.Service
}

// targetService creates an nginx service container that serves static content
// on ports 80 and 443 with a self-signed TLS cert. The hostname parameter
// sets the service's discoverable hostname for DNS resolution within the
// Dagger network. The nginxConf parameter is the raw nginx configuration
// content.
func targetService(hostname, nginxConf string) serviceBinding {
	svc := dag.Container().
		From(nginxImage).
		WithNewFile("/docker-entrypoint.d/99-self-signed-cert.sh",
			"#!/bin/sh\n"+
				"apk add --no-cache openssl >/dev/null 2>&1\n"+
				"openssl req -x509 -newkey rsa:2048 -keyout /etc/nginx/key.pem "+
				"-out /etc/nginx/cert.pem -days 1 -nodes "+
				"-subj \"/CN="+hostname+"\" 2>/dev/null\n",
			dagger.ContainerWithNewFileOpts{Permissions: 0o755},
		).
		WithNewFile("/etc/nginx/conf.d/default.conf", nginxConf).
		WithExposedPort(80).
		WithExposedPort(443).
		AsService().
		WithHostname(hostname)

	return serviceBinding{alias: hostname, service: svc}
}

// tcpEchoService creates a socat-based TCP echo service that responds with
// "TCP_FORWARD_OK" on the specified port. Used for testing tcpForwards
// without HTTP/TLS.
func tcpEchoService(hostname string, port int) serviceBinding {
	svc := dag.Container().
		From("alpine:3.22").
		WithExec([]string{"apk", "add", "--no-cache", "socat"}).
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

	// Use the first platform container (linux/amd64).
	ctr := &containers[0]

	// Mount the config at the default XDG path.
	ctr = ctr.WithNewFile("/root/.config/terrarium/config.yaml", configContent)

	// Apply service bindings.
	for _, b := range bindings {
		ctr = ctr.WithServiceBinding(b.alias, b.service)
	}

	return ctr, nil
}

// assertionScript builds the full assertion script by prepending the shared
// framework and appending the test-specific assertions. The script starts
// terrarium init in the background and waits for Envoy readiness before
// running assertions.
func assertionScript(assertions string) string {
	return `#!/bin/sh
set -e

PASS=0
FAIL=0

assert_allowed() {
    url="$1"
    desc="${2:-$url reachable}"
    if curl -sf -k --max-time 10 "$url" >/dev/null 2>&1; then
        echo "PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc (expected ALLOWED, got DENIED)"
        FAIL=$((FAIL + 1))
    fi
}

assert_denied() {
    url="$1"
    desc="${2:-$url denied}"
    if curl -sf -k --max-time 10 "$url" >/dev/null 2>&1; then
        echo "FAIL: $desc (expected DENIED, got ALLOWED -- SECURITY VIOLATION)"
        FAIL=$((FAIL + 1))
    else
        echo "PASS: $desc"
        PASS=$((PASS + 1))
    fi
}

assert_l7_allowed() {
    url="$1"
    method="${2:-GET}"
    expected_body="$3"
    desc="${4:-$method $url allowed}"
    body=$(curl -sf -k --max-time 10 -X "$method" "$url" 2>/dev/null) || {
        echo "FAIL: $desc (expected L7 ALLOWED, connection failed)"
        FAIL=$((FAIL + 1))
        return
    }
    if [ -n "$expected_body" ]; then
        if echo "$body" | grep -q "$expected_body"; then
            echo "PASS: $desc"
            PASS=$((PASS + 1))
        else
            echo "FAIL: $desc (expected body containing '$expected_body', got '$body')"
            FAIL=$((FAIL + 1))
        fi
    else
        echo "PASS: $desc"
        PASS=$((PASS + 1))
    fi
}

assert_l7_denied() {
    url="$1"
    method="${2:-GET}"
    desc="${3:-$method $url denied}"
    status=$(curl -s -k --max-time 10 -o /dev/null -w "%{http_code}" -X "$method" "$url" 2>/dev/null) || true
    if [ "$status" = "403" ]; then
        echo "PASS: $desc (HTTP 403)"
        PASS=$((PASS + 1))
    elif [ "$status" = "000" ]; then
        echo "PASS: $desc (connection refused)"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc (expected HTTP 403, got HTTP $status -- SECURITY VIOLATION)"
        FAIL=$((FAIL + 1))
    fi
}

# Start terrarium init in background
terrarium init -- sleep infinity &
TERRARIUM_PID=$!

# Wait for Envoy readiness by polling listener ports with curl.
# Envoy proxy listens on 15443 (HTTPS) and/or 15080 (HTTP).
# We use --connect-timeout to test TCP connectivity; any response
# (including errors) means Envoy is listening.
ready=0
for i in $(seq 1 60); do
    if curl -sko /dev/null --connect-timeout 1 https://127.0.0.1:15443/ 2>/dev/null || \
       curl -so /dev/null --connect-timeout 1 http://127.0.0.1:15080/ 2>/dev/null; then
        ready=1
        break
    fi
    sleep 1
done

if [ "$ready" -ne 1 ]; then
    echo "FAIL: terrarium did not become ready within 60 seconds"
    kill $TERRARIUM_PID 2>/dev/null || true
    exit 1
fi

# Give Envoy a moment to finish initialization
sleep 2

` + assertions + `

echo ""
echo "Results: $PASS passed, $FAIL failed"

# Clean up
kill $TERRARIUM_PID 2>/dev/null || true
wait $TERRARIUM_PID 2>/dev/null || true

[ "$FAIL" -eq 0 ]
`
}

// assertionScriptNoEnvoy builds an assertion script for scenarios where
// Envoy is not started (unrestricted, deny-all, CIDR-only rules). These
// configs have no FQDN ports, so no Envoy listeners are created.
func assertionScriptNoEnvoy(assertions string) string {
	return `#!/bin/sh
set -e

PASS=0
FAIL=0

assert_allowed() {
    url="$1"
    desc="${2:-$url reachable}"
    if curl -sf -k --max-time 10 "$url" >/dev/null 2>&1; then
        echo "PASS: $desc"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc (expected ALLOWED, got DENIED)"
        FAIL=$((FAIL + 1))
    fi
}

assert_denied() {
    url="$1"
    desc="${2:-$url denied}"
    if curl -sf -k --max-time 10 "$url" >/dev/null 2>&1; then
        echo "FAIL: $desc (expected DENIED, got ALLOWED -- SECURITY VIOLATION)"
        FAIL=$((FAIL + 1))
    else
        echo "PASS: $desc"
        PASS=$((PASS + 1))
    fi
}

# Start terrarium init in background.
# No FQDN ports = no Envoy, so init finishes quickly.
terrarium init -- sleep infinity &
TERRARIUM_PID=$!

# Wait for init to apply nftables rules (no Envoy to wait for).
sleep 3

` + assertions + `

echo ""
echo "Results: $PASS passed, $FAIL failed"

kill $TERRARIUM_PID 2>/dev/null || true
wait $TERRARIUM_PID 2>/dev/null || true

[ "$FAIL" -eq 0 ]
`
}

// runE2ETest executes an assertion script inside a terrarium container with
// InsecureRootCapabilities. Returns the container after execution for
// stdout/stderr inspection.
func runE2ETest(
	ctx context.Context,
	variant string,
	configContent string,
	script string,
	bindings []serviceBinding,
) (*dagger.Container, error) {
	ctr, err := terrariumContainer(ctx, variant, configContent, bindings)
	if err != nil {
		return nil, err
	}

	// Write the assertion script.
	ctr = ctr.WithNewFile("/tmp/test.sh", script,
		dagger.ContainerWithNewFileOpts{Permissions: 0o755},
	)

	// Run the assertion script with root capabilities (needed for nftables,
	// mount manipulation, and setpriv).
	return ctr.WithExec(
		[]string{"/bin/sh", "/tmp/test.sh"},
		dagger.ContainerWithExecOpts{
			InsecureRootCapabilities: true,
		},
	), nil
}
