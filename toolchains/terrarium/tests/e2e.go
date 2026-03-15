package main

import (
	"context"
	"fmt"
	"strings"

	"golang.org/x/sync/errgroup"
)

// e2eVariants lists the image variants to test.
var e2eVariants = []string{"debian", "alpine"}

const (
	defaultNginxConf = `server {
    listen 80;
    listen 443 ssl;
    ssl_certificate /etc/nginx/cert.pem;
    ssl_certificate_key /etc/nginx/key.pem;
    location / {
        return 200 "OK\n";
        add_header Content-Type text/plain;
    }
}`
	l7NginxConf = `server {
    listen 80;
    listen 443 ssl;
    ssl_certificate /etc/nginx/cert.pem;
    ssl_certificate_key /etc/nginx/key.pem;

    location /allowed/ {
        return 200 "ALLOWED_PATH\n";
        add_header Content-Type text/plain;
    }
    location /denied/ {
        return 200 "DENIED_PATH\n";
        add_header Content-Type text/plain;
    }
    location / {
        return 200 "ROOT_PATH\n";
        add_header Content-Type text/plain;
    }
}`
)

// TestEgressAll runs all egress E2E tests across debian and alpine variants.
//
// Not annotated with +check because E2E tests require InsecureRootCapabilities,
// take significant time, and depend on external network conditions within the
// Dagger engine. Run manually:
//
//	dagger call -m toolchains/terrarium/tests test-egress-all
func (m *Tests) TestEgressAll(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return m.TestEgressDenyAll(ctx) })
	g.Go(func() error { return m.TestEgressFqdnExact(ctx) })
	g.Go(func() error { return m.TestEgressFqdnWildcard(ctx) })
	g.Go(func() error { return m.TestEgressFqdnPortRestrict(ctx) })
	g.Go(func() error { return m.TestEgressCidrAllow(ctx) })
	g.Go(func() error { return m.TestEgressL7HttpPath(ctx) })
	g.Go(func() error { return m.TestEgressL7HttpMethod(ctx) })
	g.Go(func() error { return m.TestEgressMultipleRules(ctx) })
	g.Go(func() error { return m.TestEgressUnrestricted(ctx) })
	g.Go(func() error { return m.TestEgressCidrExcept(ctx) })
	g.Go(func() error { return m.TestEgressTcpForward(ctx) })

	return g.Wait()
}

// TestEgressDenyAll verifies that the deny-all config (egress: [{}]) blocks
// all outbound traffic from the sandbox user. The deny-all pattern has no
// ports, so Envoy is not started; nftables rules alone enforce the lockdown.
//
//	dagger call -m toolchains/terrarium/tests test-egress-deny-all
func (m *Tests) TestEgressDenyAll(ctx context.Context) error {
	config := `egress:
  - {}
`
	bindings := []serviceBinding{
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
	}

	// deny-all has no ports, so no Envoy is started. Use the no-envoy
	// assertion script variant with denial checks.
	script := assertionScriptNoEnvoy(`
assert_denied "http://target-allow:80/" "deny-all: HTTP to target-allow"
assert_denied "https://target-allow:443/" "deny-all: HTTPS to target-allow"
assert_denied "http://target-deny:80/" "deny-all: HTTP to target-deny"
assert_denied "https://target-deny:443/" "deny-all: HTTPS to target-deny"
`)

	return runVariants(ctx, "deny-all", config, script, bindings)
}

// TestEgressFqdnExact verifies exact FQDN matching. Only the explicitly named
// host on the specified ports should be reachable.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-exact
func (m *Tests) TestEgressFqdnExact(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
          - port: "443"
            protocol: TCP
`
	bindings := []serviceBinding{
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
	}

	script := assertionScript(`
assert_allowed "http://target-allow:80/" "fqdn-exact: HTTP to target-allow"
assert_allowed "https://target-allow:443/" "fqdn-exact: HTTPS to target-allow"
assert_denied "http://target-deny:80/" "fqdn-exact: HTTP to target-deny"
assert_denied "https://target-deny:443/" "fqdn-exact: HTTPS to target-deny"
`)

	return runVariants(ctx, "fqdn-exact", config, script, bindings)
}

// TestEgressFqdnWildcard verifies wildcard FQDN matching. Single * matches
// exactly one DNS label.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-wildcard
func (m *Tests) TestEgressFqdnWildcard(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchPattern: "*.target-zone"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`
	bindings := []serviceBinding{
		targetService("allowed.target-zone", defaultNginxConf),
		targetService("denied.other-zone", defaultNginxConf),
	}

	script := assertionScript(`
assert_allowed "https://allowed.target-zone:443/" "fqdn-wildcard: HTTPS to allowed.target-zone"
assert_denied "https://denied.other-zone:443/" "fqdn-wildcard: HTTPS to denied.other-zone"
assert_denied "http://allowed.target-zone:80/" "fqdn-wildcard: HTTP port 80 not allowed"
`)

	return runVariants(ctx, "fqdn-wildcard", config, script, bindings)
}

// TestEgressFqdnPortRestrict verifies port-level restriction on an allowed
// FQDN. The target is reachable on port 443 but not on port 80.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-port-restrict
func (m *Tests) TestEgressFqdnPortRestrict(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`
	bindings := []serviceBinding{
		targetService("target-allow", defaultNginxConf),
	}

	script := assertionScript(`
assert_allowed "https://target-allow:443/" "fqdn-port-restrict: HTTPS port 443 allowed"
assert_denied "http://target-allow:80/" "fqdn-port-restrict: HTTP port 80 denied"
`)

	return runVariants(ctx, "fqdn-port-restrict", config, script, bindings)
}

// TestEgressCidrAllow verifies CIDR-based allowlisting. Any IP is reachable
// on port 80 (broad CIDR), but other ports should be blocked. CIDR rules
// bypass Envoy and are enforced directly by nftables.
//
//	dagger call -m toolchains/terrarium/tests test-egress-cidr-allow
func (m *Tests) TestEgressCidrAllow(ctx context.Context) error {
	config := `egress:
  - toCIDR:
      - "0.0.0.0/0"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`
	bindings := []serviceBinding{
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
	}

	// CIDR rules bypass Envoy; nftables rules enforce port restrictions.
	script := assertionScriptNoEnvoy(`
assert_allowed "http://target-allow:80/" "cidr-allow: HTTP to target-allow"
assert_allowed "http://target-deny:80/" "cidr-allow: HTTP to target-deny"
assert_denied "https://target-allow:443/" "cidr-allow: HTTPS port 443 denied"
`)

	return runVariants(ctx, "cidr-allow", config, script, bindings)
}

// TestEgressL7HttpPath verifies L7 HTTP path filtering via MITM. Terrarium
// terminates TLS, inspects the HTTP request, and only allows GET requests
// to paths matching /allowed/.*.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-path
func (m *Tests) TestEgressL7HttpPath(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchName: "target-l7"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
        rules:
          http:
            - method: "GET"
              path: "/allowed/.*"
`
	bindings := []serviceBinding{
		targetService("target-l7", l7NginxConf),
	}

	script := assertionScript(`
assert_l7_allowed "https://target-l7:443/allowed/resource" "GET" "ALLOWED_PATH" "l7-path: GET /allowed/resource"
assert_l7_allowed "https://target-l7:443/allowed/nested/deep" "GET" "ALLOWED_PATH" "l7-path: GET /allowed/nested/deep"
assert_l7_denied "https://target-l7:443/denied/resource" "GET" "l7-path: GET /denied/resource denied"
assert_l7_denied "https://target-l7:443/allowed/resource" "POST" "l7-path: POST /allowed/resource denied"
`)

	return runVariants(ctx, "l7-http-path", config, script, bindings)
}

// TestEgressL7HttpMethod verifies method-only L7 restriction. GET and HEAD
// are allowed; POST, PUT, DELETE are denied.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-method
func (m *Tests) TestEgressL7HttpMethod(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchName: "target-l7"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
        rules:
          http:
            - method: "GET|HEAD"
`
	bindings := []serviceBinding{
		targetService("target-l7", l7NginxConf),
	}

	script := assertionScript(`
assert_l7_allowed "https://target-l7:443/" "GET" "ROOT_PATH" "l7-method: GET allowed"
assert_l7_allowed "https://target-l7:443/" "HEAD" "" "l7-method: HEAD allowed"
assert_l7_denied "https://target-l7:443/" "POST" "l7-method: POST denied"
assert_l7_denied "https://target-l7:443/" "PUT" "l7-method: PUT denied"
assert_l7_denied "https://target-l7:443/" "DELETE" "l7-method: DELETE denied"
`)

	return runVariants(ctx, "l7-http-method", config, script, bindings)
}

// TestEgressMultipleRules verifies that multiple egress rules are OR'd.
// Traffic matching any rule is allowed; traffic matching none is denied.
//
//	dagger call -m toolchains/terrarium/tests test-egress-multiple-rules
func (m *Tests) TestEgressMultipleRules(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
  - toFQDNs:
      - matchName: "target-l7"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`
	bindings := []serviceBinding{
		targetService("target-allow", defaultNginxConf),
		targetService("target-l7", l7NginxConf),
		targetService("target-deny", defaultNginxConf),
	}

	script := assertionScript(`
assert_allowed "http://target-allow:80/" "multiple-rules: HTTP to target-allow (rule 1)"
assert_denied "https://target-allow:443/" "multiple-rules: HTTPS to target-allow (rule 1 port 80 only)"
assert_allowed "https://target-l7:443/" "multiple-rules: HTTPS to target-l7 (rule 2)"
assert_denied "http://target-l7:80/" "multiple-rules: HTTP to target-l7 (rule 2 port 443 only)"
assert_denied "http://target-deny:80/" "multiple-rules: HTTP to target-deny (no rule)"
`)

	return runVariants(ctx, "multiple-rules", config, script, bindings)
}

// TestEgressUnrestricted verifies that when no egress rules are present, all
// traffic is unrestricted.
//
//	dagger call -m toolchains/terrarium/tests test-egress-unrestricted
func (m *Tests) TestEgressUnrestricted(ctx context.Context) error {
	config := `logging: false
`
	bindings := []serviceBinding{
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
	}

	script := assertionScriptNoEnvoy(`
assert_allowed "http://target-allow:80/" "unrestricted: HTTP to target-allow"
assert_allowed "https://target-allow:443/" "unrestricted: HTTPS to target-allow"
assert_allowed "http://target-deny:80/" "unrestricted: HTTP to target-deny"
assert_allowed "https://target-deny:443/" "unrestricted: HTTPS to target-deny"
`)

	return runVariants(ctx, "unrestricted", config, script, bindings)
}

// TestEgressCidrExcept verifies toCIDRSet with an except clause. A broad
// 0.0.0.0/0 CIDR allows all IPs on port 80, but the except list carves out
// target-deny's IP. Because Dagger service IPs are dynamic, the config is
// generated at runtime after resolving target-deny's address.
//
//	dagger call -m toolchains/terrarium/tests test-egress-cidr-except
func (m *Tests) TestEgressCidrExcept(ctx context.Context) error {
	svcAllow := targetService("target-allow", defaultNginxConf)
	svcDeny := targetService("target-deny", defaultNginxConf)

	// Resolve target-deny's IP from a helper container so we can
	// template it into the except list.
	ip, err := dag.Container().
		From("alpine:3.22").
		WithServiceBinding("target-deny", svcDeny.service).
		WithExec([]string{"sh", "-c", "getent hosts target-deny | awk '{print $1}'"}).
		Stdout(ctx)
	if err != nil {
		return fmt.Errorf("resolving target-deny IP: %w", err)
	}
	ip = strings.TrimSpace(ip)

	config := fmt.Sprintf(`egress:
  - toCIDRSet:
      - cidr: "0.0.0.0/0"
        except:
          - "%s/32"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`, ip)

	bindings := []serviceBinding{svcAllow, svcDeny}

	// CIDR rules bypass Envoy; nftables rules enforce port + except.
	script := assertionScriptNoEnvoy(`
assert_allowed "http://target-allow:80/" "cidr-except: HTTP to target-allow (not in except)"
assert_denied "http://target-deny:80/" "cidr-except: HTTP to target-deny (carved out by except)"
assert_denied "https://target-allow:443/" "cidr-except: HTTPS port 443 not in toPorts"
`)

	return runVariants(ctx, "cidr-except", config, script, bindings)
}

// TestEgressTcpForward verifies that tcpForwards creates a plain TCP proxy
// on localhost that reaches the upstream service. A socat echo server
// listens on port 22, and terrarium proxies localhost:15022 to it.
//
//	dagger call -m toolchains/terrarium/tests test-egress-tcp-forward
func (m *Tests) TestEgressTcpForward(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
tcpForwards:
  - host: "target-tcp"
    port: 22
`
	bindings := []serviceBinding{
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
		tcpEchoService("target-tcp", 22),
	}

	script := assertionScript(`
assert_allowed "https://target-allow:443/" "tcp-forward: HTTPS to target-allow via FQDN rule"
assert_denied "https://target-deny:443/" "tcp-forward: HTTPS to target-deny denied"

# Verify TCP forward reaches upstream via localhost proxy port.
response=$(echo "" | curl -s telnet://127.0.0.1:15022 --max-time 5 2>/dev/null) || true
if echo "$response" | grep -q "TCP_FORWARD_OK"; then
    echo "PASS: tcp-forward: TCP forward to target-tcp:22 via localhost:15022"
    PASS=$((PASS + 1))
else
    echo "FAIL: tcp-forward: TCP forward to target-tcp:22 via localhost:15022 (got: $response)"
    FAIL=$((FAIL + 1))
fi
`)

	return runVariants(ctx, "tcp-forward", config, script, bindings)
}

// runVariants runs the same test across all e2eVariants in parallel.
func runVariants(
	ctx context.Context,
	testName string,
	configContent string,
	script string,
	bindings []serviceBinding,
) error {
	g, ctx := errgroup.WithContext(ctx)

	for _, variant := range e2eVariants {
		g.Go(func() error {
			ctr, err := runE2ETest(ctx, variant, configContent, script, bindings)
			if err != nil {
				return fmt.Errorf("%s/%s: %w", testName, variant, err)
			}

			_, err = ctr.Stdout(ctx)
			if err != nil {
				return fmt.Errorf("%s/%s: %w", testName, variant, err)
			}

			return nil
		})
	}

	return g.Wait()
}
