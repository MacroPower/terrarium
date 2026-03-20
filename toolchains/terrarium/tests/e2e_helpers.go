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

// targetServiceOnPort creates an nginx service container that serves static
// content on a single custom port with a self-signed TLS cert. Used for
// tests that need services on non-standard ports (e.g., port range tests).
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
		WithNewFile("/docker-entrypoint.d/99-self-signed-cert.sh",
			"#!/bin/sh\n"+
				"apk add --no-cache openssl >/dev/null 2>&1\n"+
				"openssl req -x509 -newkey rsa:2048 -keyout /etc/nginx/key.pem "+
				"-out /etc/nginx/cert.pem -days 1 -nodes "+
				"-subj \"/CN="+hostname+"\" 2>/dev/null\n",
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

	// Apply service bindings.
	for _, b := range bindings {
		ctr = ctr.WithServiceBinding(b.alias, b.service)
	}

	return ctr, nil
}

// assertionPreamble contains all shared shell assertion functions used by
// both Envoy and non-Envoy test scripts. Defining them once avoids
// duplication and ensures consistent behavior across test variants.
const assertionPreamble = `
assert_allowed() {
    url="$1"
    desc="${2:-$url reachable}"
    attempt=1
    while [ "$attempt" -le 3 ]; do
        if curl -sf -k --max-time 10 "$url" >/dev/null 2>&1; then
            echo "PASS: $desc"
            PASS=$((PASS + 1))
            return
        fi
        if [ "$attempt" -lt 3 ]; then
            echo "RETRY: $desc (attempt $attempt/3 failed, retrying in 2s)"
            sleep 2
        fi
        attempt=$((attempt + 1))
    done
    echo "FAIL: $desc (expected ALLOWED, got DENIED after 3 attempts)"
    FAIL=$((FAIL + 1))
}

assert_denied() {
    url="$1"
    desc="${2:-$url denied}"
    status=$(curl -s -k --max-time 10 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    exit_code=$?
    if [ "$exit_code" -eq 0 ] && [ "$status" != "000" ] && [ "$status" != "403" ] && [ "$status" != "404" ]; then
        echo "FAIL: $desc (expected DENIED, got HTTP $status -- SECURITY VIOLATION)"
        FAIL=$((FAIL + 1))
    elif [ "$exit_code" -eq 0 ] && { [ "$status" = "403" ] || [ "$status" = "404" ]; }; then
        echo "PASS: $desc (HTTP $status)"
        PASS=$((PASS + 1))
    elif [ "$exit_code" -eq 6 ]; then
        echo "FAIL: $desc (DNS resolution failed -- expected network-level denial, not DNS error)"
        FAIL=$((FAIL + 1))
    elif [ "$exit_code" -eq 35 ] || [ "$exit_code" -eq 60 ]; then
        echo "FAIL: $desc (TLS error exit $exit_code -- expected network-level denial, not TLS error)"
        FAIL=$((FAIL + 1))
    elif [ "$exit_code" -eq 7 ] || [ "$exit_code" -eq 28 ] || [ "$status" = "000" ]; then
        echo "PASS: $desc (curl exit $exit_code)"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc (unexpected curl exit $exit_code, HTTP $status)"
        FAIL=$((FAIL + 1))
    fi
}

assert_network_denied() {
    url="$1"
    desc="${2:-$url network denied}"
    status=$(curl -s -k --max-time 10 -o /dev/null -w "%{http_code}" "$url" 2>/dev/null) || true
    if [ "$status" = "000" ]; then
        echo "PASS: $desc (HTTP 000)"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc (expected HTTP 000, got HTTP $status)"
        FAIL=$((FAIL + 1))
    fi
}

assert_l7_allowed() {
    url="$1"
    method="${2:-GET}"
    expected_body="$3"
    desc="${4:-$method $url allowed}"
    attempt=1
    while [ "$attempt" -le 3 ]; do
        status=$(curl -s -k --max-time 10 -o /tmp/l7_body -w "%{http_code}" -X "$method" "$url" 2>/dev/null) || {
            if [ "$attempt" -lt 3 ]; then
                echo "RETRY: $desc (attempt $attempt/3 connection failed, retrying in 2s)"
                sleep 2
                attempt=$((attempt + 1))
                continue
            fi
            echo "FAIL: $desc (expected L7 ALLOWED, connection failed after 3 attempts)"
            FAIL=$((FAIL + 1))
            return
        }
        # Verify HTTP status is 2xx.
        case "$status" in
            2[0-9][0-9]) ;;
            *)
                if [ "$attempt" -lt 3 ]; then
                    echo "RETRY: $desc (attempt $attempt/3 got HTTP $status, retrying in 2s)"
                    sleep 2
                    attempt=$((attempt + 1))
                    continue
                fi
                echo "FAIL: $desc (expected HTTP 2xx, got HTTP $status after 3 attempts)"
                FAIL=$((FAIL + 1))
                return
                ;;
        esac
        if [ -n "$expected_body" ]; then
            body=$(cat /tmp/l7_body)
            if echo "$body" | grep -q "$expected_body"; then
                echo "PASS: $desc (HTTP $status)"
                PASS=$((PASS + 1))
                return
            else
                if [ "$attempt" -lt 3 ]; then
                    echo "RETRY: $desc (attempt $attempt/3 body mismatch, retrying in 2s)"
                    sleep 2
                    attempt=$((attempt + 1))
                    continue
                fi
                echo "FAIL: $desc (expected body containing '$expected_body', got '$body' after 3 attempts)"
                FAIL=$((FAIL + 1))
                return
            fi
        else
            echo "PASS: $desc (HTTP $status)"
            PASS=$((PASS + 1))
            return
        fi
    done
}

assert_l7_denied() {
    url="$1"
    method="${2:-GET}"
    desc="${3:-$method $url denied}"
    status=$(curl -s -k --max-time 10 -o /dev/null -w "%{http_code}" -X "$method" "$url" 2>/dev/null) || true
    if [ "$status" = "403" ]; then
        echo "PASS: $desc (HTTP 403)"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $desc (expected HTTP 403, got HTTP $status)"
        FAIL=$((FAIL + 1))
    fi
}

assert_passthrough() {
    url="$1"
    expected_body="$2"
    desc="${3:-$url passthrough}"
    attempt=1
    while [ "$attempt" -le 3 ]; do
        body=$(curl -sf -k --max-time 10 "$url" 2>/dev/null) || {
            if [ "$attempt" -lt 3 ]; then
                echo "RETRY: $desc (attempt $attempt/3 connection failed, retrying in 2s)"
                sleep 2
                attempt=$((attempt + 1))
                continue
            fi
            echo "FAIL: $desc (expected passthrough response, connection failed after 3 attempts)"
            FAIL=$((FAIL + 1))
            return
        }
        if echo "$body" | grep -q "$expected_body"; then
            echo "PASS: $desc"
            PASS=$((PASS + 1))
            return
        else
            if [ "$attempt" -lt 3 ]; then
                echo "RETRY: $desc (attempt $attempt/3 body mismatch, retrying in 2s)"
                sleep 2
                attempt=$((attempt + 1))
                continue
            fi
            echo "FAIL: $desc (expected body containing '$expected_body', got '$body')"
            FAIL=$((FAIL + 1))
            return
        fi
    done
}

assert_udp_allowed() {
    host="$1"; port="$2"; expected="$3"
    desc="${4:-UDP to $host:$port allowed}"
    attempt=1
    while [ "$attempt" -le 3 ]; do
        response=$(echo "hello" | socat -t2 - UDP:"$host":"$port" 2>/dev/null) || true
        if echo "$response" | grep -q "$expected"; then
            echo "PASS: $desc"; PASS=$((PASS + 1)); return
        fi
        if [ "$attempt" -lt 3 ]; then
            echo "RETRY: $desc (attempt $attempt/3, retrying in 2s)"; sleep 2
        fi
        attempt=$((attempt + 1))
    done
    echo "FAIL: $desc (expected '$expected', got: $response)"; FAIL=$((FAIL + 1))
}

assert_udp_denied() {
    host="$1"; port="$2"
    desc="${3:-UDP to $host:$port denied}"
    response=$(echo "hello" | socat -t3 - UDP:"$host":"$port" 2>/dev/null) || true
    if [ -z "$response" ]; then
        echo "PASS: $desc (no response)"; PASS=$((PASS + 1))
    else
        echo "FAIL: $desc (expected no response, got: $response)"; FAIL=$((FAIL + 1))
    fi
}

assert_tcp_forward() {
    addr="$1"
    expected="$2"
    desc="${3:-TCP forward to $addr}"
    attempt=1
    while [ "$attempt" -le 3 ]; do
        response=$(echo "" | curl -s "telnet://$addr" --max-time 5 2>/dev/null) || true
        if echo "$response" | grep -q "$expected"; then
            echo "PASS: $desc"
            PASS=$((PASS + 1))
            return
        fi
        if [ "$attempt" -lt 3 ]; then
            echo "RETRY: $desc (attempt $attempt/3 failed, retrying in 2s)"
            sleep 2
        fi
        attempt=$((attempt + 1))
    done
    echo "FAIL: $desc (expected '$expected' in response, got: $response)"
    FAIL=$((FAIL + 1))
}
`

// scriptSuffix is the shared report and cleanup logic appended to custom
// assertion scripts that run as root (DNS proxy, privilege isolation, etc.).
const scriptSuffix = `
echo ""
echo "Results: $PASS passed, $FAIL failed"

# Clean up
kill $TERRARIUM_PID 2>/dev/null || true
wait $TERRARIUM_PID 2>/dev/null || true

[ "$FAIL" -eq 0 ]
`

// assertionScript builds the full assertion script by composing the shared
// preamble, Envoy startup logic, test-specific assertions, and
// report/cleanup. The script starts terrarium init in the background and
// waits for Envoy readiness before running assertions.
//
// Assertions run as the dev user (UID 1000) because nftables rules only
// redirect terrarium-user traffic to Envoy. Root traffic to external IPs
// is dropped by the filter chain's default DROP policy.
func assertionScript(assertions string) string {
	return `#!/bin/sh
set -e

# Validate the generated Envoy config against the proto schema before
# starting the full init sequence. This catches missing required fields
# and type errors that Envoy's serve mode silently accepts.
terrarium generate --config /etc/terrarium/config.yaml --envoy-config /tmp/envoy-validate.yaml
/usr/local/bin/envoy --mode validate -c /tmp/envoy-validate.yaml
rm /tmp/envoy-validate.yaml

# Start terrarium init in background with a ready-file signal.
terrarium init --config /etc/terrarium/config.yaml --ready-file /tmp/.terrarium-ready -- sleep infinity &
TERRARIUM_PID=$!

# Wait for the ready file to appear, indicating all infrastructure
# (nftables, DNS proxy, Envoy) is fully operational.
ready=0
for i in $(seq 1 60); do
    if [ -f /tmp/.terrarium-ready ]; then
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

` + buildAssertionBlock(assertions) + `
ASSERT_RC=$?

# Clean up
kill $TERRARIUM_PID 2>/dev/null || true
wait $TERRARIUM_PID 2>/dev/null || true

exit $ASSERT_RC
`
}

// assertionScriptNoEnvoy builds an assertion script for scenarios where
// Envoy is not started (unrestricted, deny-all, CIDR-only rules). These
// configs have no FQDN ports, so no Envoy listeners are created. The script
// composes the shared preamble with a simpler startup that only waits for
// nftables rules.
func assertionScriptNoEnvoy(assertions string) string {
	return `#!/bin/sh
set -e

# Start terrarium init in background with a ready-file signal.
# No FQDN ports = no Envoy, so init finishes quickly.
terrarium init --config /etc/terrarium/config.yaml --ready-file /tmp/.terrarium-ready -- sleep infinity &
TERRARIUM_PID=$!

# Wait for the ready file to appear, indicating all infrastructure
# (nftables, DNS proxy) is fully operational.
ready=0
for i in $(seq 1 60); do
    if [ -f /tmp/.terrarium-ready ]; then
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

` + buildAssertionBlock(assertions) + `
ASSERT_RC=$?

# Clean up
kill $TERRARIUM_PID 2>/dev/null || true
wait $TERRARIUM_PID 2>/dev/null || true

exit $ASSERT_RC
`
}

// buildAssertionBlock writes the assertion preamble and test-specific
// assertions to a temp script and runs it as the dev user (UID 1000).
// This is necessary because nftables rules only allow terrarium-user
// traffic; root traffic to external IPs is dropped.
func buildAssertionBlock(assertions string) string {
	return `
# Write assertion script to run as the terrarium user (UID 1000).
# nftables only redirects UID 1000 traffic to Envoy; root traffic
# to external IPs is dropped by the default DROP policy.
cat > /tmp/assertions.sh << 'ASSERTIONS_EOF'
#!/bin/sh
PASS=0
FAIL=0
` + assertionPreamble + assertions + `
echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
ASSERTIONS_EOF
chmod 755 /tmp/assertions.sh
su -s /bin/sh dev -c /tmp/assertions.sh`
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
	// mount manipulation, and privilege dropping).
	return ctr.WithExec(
		[]string{"/bin/sh", "/tmp/test.sh"},
		dagger.ContainerWithExecOpts{
			InsecureRootCapabilities: true,
		},
	), nil
}
