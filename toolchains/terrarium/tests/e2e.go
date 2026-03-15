package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"dagger/tests/internal/dagger"

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
	g.Go(func() error { return m.TestEgressFqdnWildcardDepth(ctx) })
	g.Go(func() error { return m.TestEgressFqdnWildcardMultiLabel(ctx) })
	g.Go(func() error { return m.TestEgressFqdnBareWildcard(ctx) })
	g.Go(func() error { return m.TestEgressL7HttpHost(ctx) })
	g.Go(func() error { return m.TestEgressL7HttpHeaderPresence(ctx) })
	g.Go(func() error { return m.TestEgressL7HttpHeaderValue(ctx) })
	g.Go(func() error { return m.TestEgressL7HttpCombined(ctx) })
	g.Go(func() error { return m.TestEgressL7HttpOrSemantics(ctx) })
	g.Go(func() error { return m.TestEgressL7HttpPlain(ctx) })
	g.Go(func() error { return m.TestEgressL7L4Nullification(ctx) })
	g.Go(func() error { return m.TestEgressCidrMultiExcept(ctx) })
	g.Go(func() error { return m.TestEgressFqdnMultiple(ctx) })
	g.Go(func() error { return m.TestEgressPortRange(ctx) })
	g.Go(func() error { return m.TestEgressDnsProxyFiltering(ctx) })
	g.Go(func() error { return m.TestEgressPrivilegeIsolation(ctx) })
	g.Go(func() error { return m.TestEgressEnvoyUID(ctx) })
	g.Go(func() error { return m.TestEgressLoopbackDenyAll(ctx) })
	g.Go(func() error { return m.TestEgressExitCodePropagation(ctx) })
	g.Go(func() error { return m.TestEgressLogging(ctx) })

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
assert_network_denied "http://target-allow:80/" "deny-all: HTTP to target-allow"
assert_network_denied "https://target-allow:443/" "deny-all: HTTPS to target-allow"
assert_network_denied "http://target-deny:80/" "deny-all: HTTP to target-deny"
assert_network_denied "https://target-deny:443/" "deny-all: HTTPS to target-deny"
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
assert_network_denied "http://target-deny:80/" "fqdn-exact: HTTP to target-deny"
assert_network_denied "https://target-deny:443/" "fqdn-exact: HTTPS to target-deny"
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
assert_network_denied "https://denied.other-zone:443/" "fqdn-wildcard: HTTPS to denied.other-zone"
assert_denied "http://allowed.target-zone:80/" "fqdn-wildcard: HTTP port 80 not allowed"
`)

	return runVariants(ctx, "fqdn-wildcard", config, script, bindings)
}

// TestEgressFqdnWildcardDepth verifies that *.target-zone matches exactly one
// DNS label. Multi-label subdomains (deep.sub.target-zone) must be rejected to
// prevent policy bypass.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-wildcard-depth
func (m *Tests) TestEgressFqdnWildcardDepth(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchPattern: "*.target-zone"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`
	bindings := []serviceBinding{
		targetService("one.target-zone", defaultNginxConf),
		targetService("deep.sub.target-zone", defaultNginxConf),
		targetService("denied.other-zone", defaultNginxConf),
	}

	script := assertionScript(`
assert_allowed "https://one.target-zone:443/" "wildcard-depth: single-label match allowed"
assert_network_denied "https://deep.sub.target-zone:443/" "wildcard-depth: multi-label rejected"
assert_network_denied "https://denied.other-zone:443/" "wildcard-depth: wrong zone denied"
`)

	return runVariants(ctx, "fqdn-wildcard-depth", config, script, bindings)
}

// TestEgressFqdnWildcardMultiLabel verifies that **.target-zone matches
// subdomains at arbitrary depth. Both single-label (one.target-zone) and
// multi-label (two.one.target-zone) subdomains are allowed, exercising the
// distinct RBAC regex path in Envoy.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-wildcard-multi-label
func (m *Tests) TestEgressFqdnWildcardMultiLabel(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchPattern: "**.target-zone"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`
	bindings := []serviceBinding{
		targetService("one.target-zone", defaultNginxConf),
		targetService("two.one.target-zone", defaultNginxConf),
		targetService("denied.other-zone", defaultNginxConf),
	}

	script := assertionScript(`
assert_allowed "https://one.target-zone:443/" "multi-label-wildcard: single-label match allowed"
assert_allowed "https://two.one.target-zone:443/" "multi-label-wildcard: multi-label match allowed"
assert_network_denied "https://denied.other-zone:443/" "multi-label-wildcard: wrong zone denied"
`)

	return runVariants(ctx, "fqdn-wildcard-multi-label", config, script, bindings)
}

// TestEgressFqdnBareWildcard verifies that matchPattern: "*" allows all FQDNs
// while still enforcing port restrictions. HTTPS (port 443) to any service is
// allowed, but HTTP (port 80) is denied because it is not in toPorts.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-bare-wildcard
func (m *Tests) TestEgressFqdnBareWildcard(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchPattern: "*"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`
	bindings := []serviceBinding{
		targetService("target-a", defaultNginxConf),
		targetService("target-b", defaultNginxConf),
	}

	script := assertionScript(`
assert_allowed "https://target-a:443/" "bare-wildcard: HTTPS to target-a allowed"
assert_allowed "https://target-b:443/" "bare-wildcard: HTTPS to target-b allowed"
assert_denied "http://target-a:80/" "bare-wildcard: HTTP port 80 to target-a denied"
assert_denied "http://target-b:80/" "bare-wildcard: HTTP port 80 to target-b denied"
`)

	return runVariants(ctx, "fqdn-bare-wildcard", config, script, bindings)
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
assert_network_denied "https://target-allow:443/" "cidr-allow: HTTPS port 443 denied"
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

// TestEgressL7HttpHost verifies L7 host header matching. Envoy's RBAC checks
// the HTTP Host/:authority header against the configured host field. Requests
// with the correct host are allowed; requests smuggled with a different Host
// header value are denied with HTTP 403.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-host
func (m *Tests) TestEgressL7HttpHost(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchName: "target-l7"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
        rules:
          http:
            - host: "target-l7"
`
	bindings := []serviceBinding{
		targetService("target-l7", defaultNginxConf),
	}

	script := assertionScript(`
assert_l7_allowed "https://target-l7:443/" "GET" "OK" "l7-host: matching Host header allowed"

# Smuggle a wrong Host header -- Envoy should deny with 403.
status=$(curl -s -k --max-time 10 -o /dev/null -w "%{http_code}" -H "Host: evil-host" "https://target-l7:443/" 2>/dev/null) || true
if [ "$status" = "403" ]; then
    echo "PASS: l7-host: smuggled Host header denied (HTTP 403)"
    PASS=$((PASS + 1))
else
    echo "FAIL: l7-host: smuggled Host header (expected HTTP 403, got HTTP $status)"
    FAIL=$((FAIL + 1))
fi
`)

	return runVariants(ctx, "l7-http-host", config, script, bindings)
}

// TestEgressL7HttpHeaderPresence verifies that L7 rules with a headers field
// check for the presence of specific request headers. Requests that include the
// required header are allowed; requests without it are denied with HTTP 403.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-header-presence
func (m *Tests) TestEgressL7HttpHeaderPresence(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchName: "target-l7"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
        rules:
          http:
            - headers:
                - "X-Allowed"
`
	bindings := []serviceBinding{
		targetService("target-l7", defaultNginxConf),
	}

	script := assertionScript(`
# Request with X-Allowed header present -- should be allowed.
attempt=1
while [ "$attempt" -le 3 ]; do
    body=$(curl -sf -k --max-time 10 -H "X-Allowed: yes" "https://target-l7:443/" 2>/dev/null) && {
        echo "PASS: l7-header-presence: request with X-Allowed header allowed"
        PASS=$((PASS + 1))
        break
    }
    if [ "$attempt" -lt 3 ]; then
        echo "RETRY: l7-header-presence: request with X-Allowed header (attempt $attempt/3 failed, retrying in 2s)"
        sleep 2
    else
        echo "FAIL: l7-header-presence: request with X-Allowed header (expected ALLOWED, failed after 3 attempts)"
        FAIL=$((FAIL + 1))
    fi
    attempt=$((attempt + 1))
done

# Request without X-Allowed header -- Envoy should deny with 403.
status=$(curl -s -k --max-time 10 -o /dev/null -w "%{http_code}" "https://target-l7:443/" 2>/dev/null) || true
if [ "$status" = "403" ]; then
    echo "PASS: l7-header-presence: request without X-Allowed header denied (HTTP 403)"
    PASS=$((PASS + 1))
else
    echo "FAIL: l7-header-presence: request without X-Allowed header (expected HTTP 403, got HTTP $status)"
    FAIL=$((FAIL + 1))
fi
`)

	return runVariants(ctx, "l7-http-header-presence", config, script, bindings)
}

// TestEgressL7HttpHeaderValue verifies that L7 rules with headerMatches check
// exact header name/value pairs. Requests with the correct header value are
// allowed; requests with a wrong value or missing the header entirely are
// denied with HTTP 403.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-header-value
func (m *Tests) TestEgressL7HttpHeaderValue(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchName: "target-l7"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
        rules:
          http:
            - headerMatches:
                - name: "X-Token"
                  value: "secret"
`
	bindings := []serviceBinding{
		targetService("target-l7", defaultNginxConf),
	}

	script := assertionScript(`
# Request with correct X-Token value -- should be allowed.
attempt=1
while [ "$attempt" -le 3 ]; do
    body=$(curl -sf -k --max-time 10 -H "X-Token: secret" "https://target-l7:443/" 2>/dev/null) && {
        echo "PASS: l7-header-value: request with X-Token: secret allowed"
        PASS=$((PASS + 1))
        break
    }
    if [ "$attempt" -lt 3 ]; then
        echo "RETRY: l7-header-value: request with X-Token: secret (attempt $attempt/3 failed, retrying in 2s)"
        sleep 2
    else
        echo "FAIL: l7-header-value: request with X-Token: secret (expected ALLOWED, failed after 3 attempts)"
        FAIL=$((FAIL + 1))
    fi
    attempt=$((attempt + 1))
done

# Request with wrong X-Token value -- Envoy should deny with 403.
status=$(curl -s -k --max-time 10 -o /dev/null -w "%{http_code}" -H "X-Token: wrong" "https://target-l7:443/" 2>/dev/null) || true
if [ "$status" = "403" ]; then
    echo "PASS: l7-header-value: request with X-Token: wrong denied (HTTP 403)"
    PASS=$((PASS + 1))
else
    echo "FAIL: l7-header-value: request with X-Token: wrong (expected HTTP 403, got HTTP $status)"
    FAIL=$((FAIL + 1))
fi

# Request without X-Token header -- Envoy should deny with 403.
status=$(curl -s -k --max-time 10 -o /dev/null -w "%{http_code}" "https://target-l7:443/" 2>/dev/null) || true
if [ "$status" = "403" ]; then
    echo "PASS: l7-header-value: request without X-Token denied (HTTP 403)"
    PASS=$((PASS + 1))
else
    echo "FAIL: l7-header-value: request without X-Token (expected HTTP 403, got HTTP $status)"
    FAIL=$((FAIL + 1))
fi
`)

	return runVariants(ctx, "l7-http-header-value", config, script, bindings)
}

// TestEgressL7HttpCombined verifies AND semantics for multiple L7 constraints
// within a single HTTP rule. A rule with method, path, and host fields requires
// all three to match; violating any single constraint results in HTTP 403.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-combined
func (m *Tests) TestEgressL7HttpCombined(ctx context.Context) error {
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
              path: "/api/.*"
              host: "target-l7"
`
	bindings := []serviceBinding{
		targetService("target-l7", l7NginxConf),
	}

	script := assertionScript(`
# All three constraints satisfied: GET + /api/foo + correct host.
assert_l7_allowed "https://target-l7:443/api/foo" "GET" "ROOT_PATH" "l7-combined: GET /api/foo correct host allowed"

# Wrong method: POST instead of GET.
assert_l7_denied "https://target-l7:443/api/foo" "POST" "l7-combined: POST /api/foo denied (wrong method)"

# Wrong path: /other instead of /api/*.
assert_l7_denied "https://target-l7:443/other" "GET" "l7-combined: GET /other denied (wrong path)"

# Wrong host: smuggle a different Host header.
status=$(curl -s -k --max-time 10 -o /dev/null -w "%{http_code}" -H "Host: evil-host" "https://target-l7:443/api/foo" 2>/dev/null) || true
if [ "$status" = "403" ]; then
    echo "PASS: l7-combined: GET /api/foo wrong host denied (HTTP 403)"
    PASS=$((PASS + 1))
else
    echo "FAIL: l7-combined: GET /api/foo wrong host (expected HTTP 403, got HTTP $status)"
    FAIL=$((FAIL + 1))
fi
`)

	return runVariants(ctx, "l7-http-combined", config, script, bindings)
}

// TestEgressL7HttpOrSemantics verifies OR semantics for multiple HTTP rule
// entries within a single rules block. Two rules -- {GET, /read/.*} and
// {POST, /write/.*} -- mean a request matching either rule is allowed.
// Cross-combinations (GET /write, POST /read) must be denied with HTTP 403.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-or-semantics
func (m *Tests) TestEgressL7HttpOrSemantics(ctx context.Context) error {
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
              path: "/read/.*"
            - method: "POST"
              path: "/write/.*"
`
	bindings := []serviceBinding{
		targetService("target-l7", l7NginxConf),
	}

	script := assertionScript(`
# Rule 1 match: GET /read/x should be allowed.
assert_l7_allowed "https://target-l7:443/read/x" "GET" "ROOT_PATH" "l7-or: GET /read/x allowed (rule 1)"

# Rule 2 match: POST /write/x should be allowed.
assert_l7_allowed "https://target-l7:443/write/x" "POST" "ROOT_PATH" "l7-or: POST /write/x allowed (rule 2)"

# Cross: GET /write/x matches neither rule (GET matches rule 1 method but not path, rule 2 path but not method).
assert_l7_denied "https://target-l7:443/write/x" "GET" "l7-or: GET /write/x denied (no rule match)"

# Cross: POST /read/x matches neither rule (POST matches rule 2 method but not path, rule 1 path but not method).
assert_l7_denied "https://target-l7:443/read/x" "POST" "l7-or: POST /read/x denied (no rule match)"
`)

	return runVariants(ctx, "l7-http-or-semantics", config, script, bindings)
}

// TestEgressL7HttpPlain verifies that L7 rules work on plain HTTP (port 80)
// where Envoy inspects traffic via http_connection_manager without TLS
// termination. This exercises the virtual host path without MITM.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-plain
func (m *Tests) TestEgressL7HttpPlain(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchName: "target-l7"
    toPorts:
      - ports:
          - port: "80"
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
assert_l7_allowed "http://target-l7:80/allowed/resource" "GET" "ALLOWED_PATH" "l7-http-plain: GET /allowed/resource on port 80"
assert_l7_denied "http://target-l7:80/denied/resource" "GET" "l7-http-plain: GET /denied/resource on port 80 denied"
assert_l7_denied "http://target-l7:80/allowed/resource" "POST" "l7-http-plain: POST /allowed/resource on port 80 denied"
`)

	return runVariants(ctx, "l7-http-plain", config, script, bindings)
}

// TestEgressL7L4Nullification verifies that when a rule has both an
// L7-restricted and an L4-only (no rules) toPorts entry for the same port,
// the L4-only entry nullifies the L7 restriction. Under Cilium semantics,
// unrestricted wins: the merged result is plain L4 forwarding with no HTTP
// inspection. This exercises the nullification logic in config/resolve.go
// (matchRuleForPort).
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-l4-nullification
func (m *Tests) TestEgressL7L4Nullification(ctx context.Context) error {
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
      - ports:
          - port: "443"
            protocol: TCP
`
	bindings := []serviceBinding{
		targetService("target-l7", l7NginxConf),
	}

	// The L4-only entry on port 443 nullifies the L7 path restriction.
	// Both /allowed/ and /denied/ paths should be reachable because
	// Envoy treats the domain as unrestricted (no MITM, SNI passthrough).
	script := assertionScript(`
assert_allowed "https://target-l7:443/allowed/resource" "l7-l4-nullification: /allowed/ path reachable"
assert_allowed "https://target-l7:443/denied/resource" "l7-l4-nullification: /denied/ path reachable (L4 nullifies L7)"
assert_allowed "https://target-l7:443/" "l7-l4-nullification: root path reachable (L4 nullifies L7)"
`)

	return runVariants(ctx, "l7-l4-nullification", config, script, bindings)
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
assert_network_denied "http://target-deny:80/" "multiple-rules: HTTP to target-deny (no rule)"
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
assert_network_denied "http://target-deny:80/" "cidr-except: HTTP to target-deny (carved out by except)"
assert_network_denied "https://target-allow:443/" "cidr-except: HTTPS port 443 not in toPorts"
`)

	return runVariants(ctx, "cidr-except", config, script, bindings)
}

// TestEgressCidrMultiExcept verifies that toCIDRSet with multiple entries in
// the except list carves out each excepted IP from the allowed CIDR range.
// A broad 0.0.0.0/0 CIDR allows all IPs on port 80, but two IPs in the except
// list are blocked. Because Dagger service IPs are dynamic, the config is
// generated at runtime after resolving the excepted services' addresses.
//
//	dagger call -m toolchains/terrarium/tests test-egress-cidr-multi-except
func (m *Tests) TestEgressCidrMultiExcept(ctx context.Context) error {
	svcAllow := targetService("target-allow", defaultNginxConf)
	svcDeny1 := targetService("target-deny-1", defaultNginxConf)
	svcDeny2 := targetService("target-deny-2", defaultNginxConf)

	// Resolve both denied services' IPs so we can template them into the
	// except list.
	ip1, err := dag.Container().
		From("alpine:3.22").
		WithServiceBinding("target-deny-1", svcDeny1.service).
		WithExec([]string{"sh", "-c", "getent hosts target-deny-1 | awk '{print $1}'"}).
		Stdout(ctx)
	if err != nil {
		return fmt.Errorf("resolving target-deny-1 IP: %w", err)
	}
	ip1 = strings.TrimSpace(ip1)

	ip2, err := dag.Container().
		From("alpine:3.22").
		WithServiceBinding("target-deny-2", svcDeny2.service).
		WithExec([]string{"sh", "-c", "getent hosts target-deny-2 | awk '{print $1}'"}).
		Stdout(ctx)
	if err != nil {
		return fmt.Errorf("resolving target-deny-2 IP: %w", err)
	}
	ip2 = strings.TrimSpace(ip2)

	config := fmt.Sprintf(`egress:
  - toCIDRSet:
      - cidr: "0.0.0.0/0"
        except:
          - "%s/32"
          - "%s/32"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`, ip1, ip2)

	bindings := []serviceBinding{svcAllow, svcDeny1, svcDeny2}

	// CIDR rules bypass Envoy; nftables rules enforce port + except.
	script := assertionScriptNoEnvoy(`
assert_allowed "http://target-allow:80/" "cidr-multi-except: HTTP to target-allow (not in except)"
assert_network_denied "http://target-deny-1:80/" "cidr-multi-except: HTTP to target-deny-1 (excepted)"
assert_network_denied "http://target-deny-2:80/" "cidr-multi-except: HTTP to target-deny-2 (excepted)"
`)

	return runVariants(ctx, "cidr-multi-except", config, script, bindings)
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
assert_network_denied "https://target-deny:443/" "tcp-forward: HTTPS to target-deny denied"

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

// TestEgressFqdnMultiple verifies that multiple matchName entries in toFQDNs
// are OR'd correctly. Both named FQDNs are allowed on port 443; an unlisted
// FQDN is denied.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-multiple
func (m *Tests) TestEgressFqdnMultiple(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchName: "target-a"
      - matchName: "target-b"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`
	bindings := []serviceBinding{
		targetService("target-a", defaultNginxConf),
		targetService("target-b", defaultNginxConf),
		targetService("target-c", defaultNginxConf),
	}

	script := assertionScript(`
assert_allowed "https://target-a:443/" "fqdn-multiple: HTTPS to target-a allowed"
assert_allowed "https://target-b:443/" "fqdn-multiple: HTTPS to target-b allowed"
assert_network_denied "https://target-c:443/" "fqdn-multiple: HTTPS to target-c denied"
`)

	return runVariants(ctx, "fqdn-multiple", config, script, bindings)
}

// TestEgressPortRange verifies that endPort correctly allows a range of ports.
// An FQDN rule with port 8000 and endPort 8100 should allow services running
// on ports within the range (e.g., 8080) while blocking ports outside the
// range (e.g., 9000). Uses custom nginx services on non-standard ports.
//
//	dagger call -m toolchains/terrarium/tests test-egress-port-range
func (m *Tests) TestEgressPortRange(ctx context.Context) error {
	config := `egress:
  - toFQDNs:
      - matchName: "target-range"
    toPorts:
      - ports:
          - port: "8000"
            endPort: 8100
            protocol: TCP
`
	bindings := []serviceBinding{
		targetServiceOnPort("target-range", 8080),
		targetServiceOnPort("target-outside", 9000),
	}

	script := assertionScript(`
assert_allowed "https://target-range:8080/" "port-range: port 8080 within range 8000-8100"
assert_denied "https://target-range:9000/" "port-range: port 9000 outside range 8000-8100"
assert_network_denied "https://target-outside:9000/" "port-range: different FQDN outside rule denied"
`)

	return runVariants(ctx, "port-range", config, script, bindings)
}

// TestEgressDnsProxyFiltering verifies that the DNS proxy returns REFUSED for
// domains not in the allowlist. An FQDN rule allows "target-allow" on port 443;
// dig queries against "target-deny" must receive status REFUSED (not NXDOMAIN
// or a valid answer), while queries for "target-allow" must return NOERROR with
// a resolved address.
//
//	dagger call -m toolchains/terrarium/tests test-egress-dns-proxy-filtering
func (m *Tests) TestEgressDnsProxyFiltering(ctx context.Context) error {
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
		targetService("target-deny", defaultNginxConf),
	}

	// dig must be installed before terrarium init starts, because the
	// firewall would block access to package repos. This requires a custom
	// script rather than assertionScript().
	script := `#!/bin/sh
set -e

PASS=0
FAIL=0
` + assertionPreamble + `
# Install dig before starting terrarium (firewall would block package repos).
if command -v apk >/dev/null 2>&1; then
    apk add --no-cache bind-tools >/dev/null 2>&1
else
    apt-get update >/dev/null 2>&1 && apt-get install -y dnsutils >/dev/null 2>&1
fi

# Start terrarium init in background.
terrarium init --config /etc/terrarium/config.yaml -- sleep infinity &
TERRARIUM_PID=$!

# Wait for Envoy readiness by polling listener ports with curl.
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

sleep 2

# Query an allowed domain -- dig should return status NOERROR with an answer.
dig_output=$(dig target-allow 2>/dev/null)
dig_status=$(echo "$dig_output" | grep -o "status: [A-Z]*" | head -1 | awk '{print $2}')
dig_answer=$(dig +short target-allow 2>/dev/null)
if [ "$dig_status" = "NOERROR" ] && [ -n "$dig_answer" ]; then
    echo "PASS: dns-proxy: allowed domain returns NOERROR with answer ($dig_answer)"
    PASS=$((PASS + 1))
else
    echo "FAIL: dns-proxy: allowed domain (expected NOERROR with answer, got status=$dig_status answer=$dig_answer)"
    FAIL=$((FAIL + 1))
fi

# Query a denied domain -- dig should return status REFUSED.
dig_output=$(dig target-deny 2>/dev/null)
dig_status=$(echo "$dig_output" | grep -o "status: [A-Z]*" | head -1 | awk '{print $2}')
if [ "$dig_status" = "REFUSED" ]; then
    echo "PASS: dns-proxy: denied domain returns REFUSED"
    PASS=$((PASS + 1))
else
    echo "FAIL: dns-proxy: denied domain (expected REFUSED, got status=$dig_status)"
    FAIL=$((FAIL + 1))
fi
` + scriptSuffix

	return runVariants(ctx, "dns-proxy-filtering", config, script, bindings)
}

// TestEgressPrivilegeIsolation verifies that the sandboxed process runs as
// UID 1000 / GID 1000 with all Linux capabilities dropped. The sandbox
// command writes identity and capability info to files, which the assertion
// script then validates. A filtered policy (FQDN rule) is used to ensure
// privilege drop happens in the filtered code path.
//
//	dagger call -m toolchains/terrarium/tests test-egress-privilege-isolation
func (m *Tests) TestEgressPrivilegeIsolation(ctx context.Context) error {
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

	// The sandbox command (after privilege drop) writes id output and
	// capability status to files, then sleeps so the container stays alive
	// for the assertion script to read them.
	script := `#!/bin/sh
set -e

PASS=0
FAIL=0
` + assertionPreamble + `
# Start terrarium init with a sandbox command that captures identity
# and capability info to files, then sleeps to keep the container alive.
terrarium init --config /etc/terrarium/config.yaml -- sh -c '
    id > /tmp/sandbox_id.txt
    grep "^Cap" /proc/self/status > /tmp/sandbox_caps.txt
    sleep infinity
' &
TERRARIUM_PID=$!

# Wait for Envoy readiness (filtered policy starts Envoy).
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

sleep 2

# Wait for sandbox output files to appear (should be near-instant).
file_ready=0
for i in $(seq 1 10); do
    if [ -f /tmp/sandbox_id.txt ] && [ -f /tmp/sandbox_caps.txt ]; then
        file_ready=1
        break
    fi
    sleep 1
done

if [ "$file_ready" -ne 1 ]; then
    echo "FAIL: sandbox output files did not appear within 10 seconds"
    kill $TERRARIUM_PID 2>/dev/null || true
    exit 1
fi

# Verify UID is 1000.
id_output=$(cat /tmp/sandbox_id.txt)
if echo "$id_output" | grep -q "uid=1000"; then
    echo "PASS: privilege-isolation: UID is 1000"
    PASS=$((PASS + 1))
else
    echo "FAIL: privilege-isolation: expected uid=1000, got: $id_output"
    FAIL=$((FAIL + 1))
fi

# Verify GID is 1000.
if echo "$id_output" | grep -q "gid=1000"; then
    echo "PASS: privilege-isolation: GID is 1000"
    PASS=$((PASS + 1))
else
    echo "FAIL: privilege-isolation: expected gid=1000, got: $id_output"
    FAIL=$((FAIL + 1))
fi

# Verify all capability sets are zeroed out.
caps_output=$(cat /tmp/sandbox_caps.txt)
all_caps_zero=1
for cap_name in CapInh CapPrm CapEff CapBnd CapAmb; do
    cap_val=$(echo "$caps_output" | grep "^${cap_name}:" | awk '{print $2}')
    if [ "$cap_val" = "0000000000000000" ]; then
        echo "PASS: privilege-isolation: ${cap_name} is 0000000000000000"
        PASS=$((PASS + 1))
    else
        echo "FAIL: privilege-isolation: expected ${cap_name}=0000000000000000, got ${cap_val}"
        FAIL=$((FAIL + 1))
        all_caps_zero=0
    fi
done
` + scriptSuffix

	return runVariants(ctx, "privilege-isolation", config, script, bindings)
}

// TestEgressEnvoyUID verifies that the Envoy process runs as UID 999. A
// filtered policy (FQDN rule) is used to ensure Envoy is started. After
// Envoy readiness, the test checks ps output to confirm the envoy process
// owner.
//
//	dagger call -m toolchains/terrarium/tests test-egress-envoy-uid
func (m *Tests) TestEgressEnvoyUID(ctx context.Context) error {
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

	script := `#!/bin/sh
set -e

PASS=0
FAIL=0
` + assertionPreamble + `
# Start terrarium init in background.
terrarium init --config /etc/terrarium/config.yaml -- sleep infinity &
TERRARIUM_PID=$!

# Wait for Envoy readiness (filtered policy starts Envoy).
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

sleep 2

# Find the Envoy process and check its UID.
# ps -e -o uid,comm lists all processes with their UID and command name.
envoy_uid=$(ps -e -o uid,comm | grep envoy | awk '{print $1}' | head -1)

if [ -z "$envoy_uid" ]; then
    echo "FAIL: envoy-uid: no envoy process found in ps output"
    FAIL=$((FAIL + 1))
elif [ "$envoy_uid" = "999" ]; then
    echo "PASS: envoy-uid: Envoy process running as UID 999"
    PASS=$((PASS + 1))
else
    echo "FAIL: envoy-uid: expected UID 999, got UID $envoy_uid"
    FAIL=$((FAIL + 1))
fi
` + scriptSuffix

	return runVariants(ctx, "envoy-uid", config, script, bindings)
}

// TestEgressLoopbackDenyAll verifies that localhost communication works even
// under a deny-all policy. A simple HTTP listener is started on localhost
// inside the container before terrarium init. The sandbox command (UID 1000)
// verifies it can reach the localhost service while external traffic is denied.
//
//	dagger call -m toolchains/terrarium/tests test-egress-loopback-deny-all
func (m *Tests) TestEgressLoopbackDenyAll(ctx context.Context) error {
	config := `egress:
  - {}
`
	bindings := []serviceBinding{
		targetService("target-external", defaultNginxConf),
	}

	// Custom script: start a localhost HTTP listener, then run terrarium init
	// with a sandbox command that tests localhost reachability and external
	// denial. Results are written to files and validated by the assertion script.
	script := `#!/bin/sh
set -e

PASS=0
FAIL=0
` + assertionPreamble + `
# Start a simple HTTP listener on localhost:8080 before terrarium init.
# This runs as root and stays alive for the duration of the test.
while true; do
    echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nLOOPBACK_OK" | nc -l -p 8080 -w 1 2>/dev/null || true
done &
LISTENER_PID=$!

# Verify the listener is up before proceeding.
listener_ready=0
for i in $(seq 1 10); do
    if curl -sf --max-time 2 http://127.0.0.1:8080/ >/dev/null 2>&1; then
        listener_ready=1
        break
    fi
    sleep 1
done

if [ "$listener_ready" -ne 1 ]; then
    echo "FAIL: localhost listener did not start within 10 seconds"
    kill $LISTENER_PID 2>/dev/null || true
    exit 1
fi

# Start terrarium init with a sandbox command that tests connectivity
# and writes results to files.
terrarium init --config /etc/terrarium/config.yaml -- sh -c '
    # Test localhost reachability (should work under deny-all).
    attempt=1
    lo_ok=0
    while [ "$attempt" -le 5 ]; do
        if curl -sf --max-time 5 http://127.0.0.1:8080/ > /tmp/lo_result.txt 2>&1; then
            lo_ok=1
            break
        fi
        sleep 1
        attempt=$((attempt + 1))
    done
    if [ "$lo_ok" -eq 0 ]; then
        echo "CURL_FAILED" > /tmp/lo_result.txt
    fi

    # Test external reachability (should be denied under deny-all).
    ext_status=$(curl -s -k --max-time 10 -o /dev/null -w "%{http_code}" http://target-external:80/ 2>/dev/null) || true
    echo "$ext_status" > /tmp/ext_result.txt

    sleep infinity
' &
TERRARIUM_PID=$!

# Wait for nftables rules to appear (deny-all, no Envoy).
ready=0
for i in $(seq 1 30); do
    if nft list table inet terrarium >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 1
done

if [ "$ready" -ne 1 ]; then
    echo "FAIL: terrarium nftables rules did not appear within 30 seconds"
    kill $TERRARIUM_PID 2>/dev/null || true
    kill $LISTENER_PID 2>/dev/null || true
    exit 1
fi

# Wait for sandbox output files to appear.
file_ready=0
for i in $(seq 1 30); do
    if [ -f /tmp/lo_result.txt ] && [ -f /tmp/ext_result.txt ]; then
        file_ready=1
        break
    fi
    sleep 1
done

if [ "$file_ready" -ne 1 ]; then
    echo "FAIL: sandbox output files did not appear within 30 seconds"
    kill $TERRARIUM_PID 2>/dev/null || true
    kill $LISTENER_PID 2>/dev/null || true
    exit 1
fi

# Verify localhost was reachable from sandbox.
lo_result=$(cat /tmp/lo_result.txt)
if echo "$lo_result" | grep -q "LOOPBACK_OK"; then
    echo "PASS: loopback-deny-all: sandbox can reach localhost:8080"
    PASS=$((PASS + 1))
else
    echo "FAIL: loopback-deny-all: expected LOOPBACK_OK, got: $lo_result"
    FAIL=$((FAIL + 1))
fi

# Verify external traffic is denied from sandbox.
ext_result=$(cat /tmp/ext_result.txt)
if [ "$ext_result" = "000" ]; then
    echo "PASS: loopback-deny-all: external traffic denied (HTTP 000)"
    PASS=$((PASS + 1))
else
    echo "FAIL: loopback-deny-all: expected HTTP 000 for external, got: $ext_result"
    FAIL=$((FAIL + 1))
fi

# Clean up listener.
kill $LISTENER_PID 2>/dev/null || true
` + scriptSuffix

	return runVariants(ctx, "loopback-deny-all", config, script, bindings)
}

// TestEgressExitCodePropagation verifies that terrarium propagates the child
// process exit code. When the sandbox command exits with a non-zero code,
// terrarium should exit with the same code. When it exits with 0, terrarium
// should exit with 0.
//
//	dagger call -m toolchains/terrarium/tests test-egress-exit-code-propagation
func (m *Tests) TestEgressExitCodePropagation(ctx context.Context) error {
	config := `egress:
  - {}
`

	g, ctx := errgroup.WithContext(ctx)

	for _, variant := range e2eVariants {
		g.Go(func() error {
			// Test 1: exit 42 should propagate as exit code 42.
			ctr, err := terrariumContainer(ctx, variant, config, nil)
			if err != nil {
				return fmt.Errorf("exit-code/%s: building container: %w", variant, err)
			}

			ctr = ctr.WithExec(
				[]string{"sh", "-c", "terrarium init --config /etc/terrarium/config.yaml -- sh -c 'exit 42'"},
				dagger.ContainerWithExecOpts{InsecureRootCapabilities: true},
			)

			_, err = ctr.Stdout(ctx)
			if err == nil {
				return fmt.Errorf("exit-code/%s: expected exit code 42 but command succeeded", variant)
			}

			var execErr *dagger.ExecError
			if !errors.As(err, &execErr) {
				return fmt.Errorf("exit-code/%s: expected ExecError, got: %w", variant, err)
			}

			if execErr.ExitCode != 42 {
				return fmt.Errorf("exit-code/%s: expected exit code 42, got %d\nstdout:\n%s\nstderr:\n%s",
					variant, execErr.ExitCode, execErr.Stdout, execErr.Stderr)
			}

			// Test 2: exit 0 should succeed.
			ctr2, err := terrariumContainer(ctx, variant, config, nil)
			if err != nil {
				return fmt.Errorf("exit-code/%s: building container for exit 0: %w", variant, err)
			}

			ctr2 = ctr2.WithExec(
				[]string{"sh", "-c", "terrarium init --config /etc/terrarium/config.yaml -- sh -c 'exit 0'"},
				dagger.ContainerWithExecOpts{InsecureRootCapabilities: true},
			)

			_, err = ctr2.Stdout(ctx)
			if err != nil {
				var execErr2 *dagger.ExecError
				if errors.As(err, &execErr2) {
					return fmt.Errorf("exit-code/%s: expected exit code 0, got %d\nstdout:\n%s\nstderr:\n%s",
						variant, execErr2.ExitCode, execErr2.Stdout, execErr2.Stderr)
				}
				return fmt.Errorf("exit-code/%s: expected exit code 0, got error: %w", variant, err)
			}

			return nil
		})
	}

	return g.Wait()
}

// TestEgressLogging verifies that logging: true produces Envoy access log
// entries on stderr for proxied traffic.
//
//	dagger call -m toolchains/terrarium/tests test-egress-logging
func (m *Tests) TestEgressLogging(ctx context.Context) error {
	config := `logging: true
egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`
	bindings := []serviceBinding{
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
	}

	// Generate both allowed and denied traffic, then verify the assertion
	// script passes before checking stderr for access log entries.
	script := assertionScript(`
assert_allowed "https://target-allow:443/" "logging: HTTPS to target-allow"
assert_network_denied "https://target-deny:443/" "logging: HTTPS to target-deny"
`)

	g, ctx := errgroup.WithContext(ctx)

	for _, variant := range e2eVariants {
		g.Go(func() error {
			ctr, err := runE2ETest(ctx, variant, config, script, bindings)
			if err != nil {
				return fmt.Errorf("logging/%s: %w", variant, err)
			}

			// Force execution and capture stdout (assertions).
			_, err = ctr.Stdout(ctx)
			if err != nil {
				var execErr *dagger.ExecError
				if errors.As(err, &execErr) {
					return fmt.Errorf("logging/%s: %w\nstdout:\n%s\nstderr:\n%s",
						variant, err, execErr.Stdout, execErr.Stderr)
				}
				return fmt.Errorf("logging/%s: %w", variant, err)
			}

			// Capture stderr and verify Envoy access log entries are present.
			stderr, err := ctr.Stderr(ctx)
			if err != nil {
				return fmt.Errorf("logging/%s: capturing stderr: %w", variant, err)
			}

			// Envoy access logs are written to stderr when logging is enabled.
			// Look for access log entries that indicate proxied traffic was logged.
			if !strings.Contains(stderr, "target-allow") {
				return fmt.Errorf("logging/%s: stderr does not contain Envoy access log entries for target-allow\nstderr:\n%s",
					variant, stderr)
			}

			return nil
		})
	}

	return g.Wait()
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
				var execErr *dagger.ExecError
				if errors.As(err, &execErr) {
					return fmt.Errorf("%s/%s: %w\nstdout:\n%s\nstderr:\n%s",
						testName, variant, err, execErr.Stdout, execErr.Stderr)
				}
				return fmt.Errorf("%s/%s: %w", testName, variant, err)
			}

			return nil
		})
	}

	return g.Wait()
}
