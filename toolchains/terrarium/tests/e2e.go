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
var e2eVariants = []string{"debian"}

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
	headerEchoNginxConf = `server {
    listen 80;
    listen 443 ssl;
    ssl_certificate /etc/nginx/cert.pem;
    ssl_certificate_key /etc/nginx/key.pem;
    location / {
        return 200 "TOKEN=$http_x_token\n";
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

// e2eTestFuncs registers all e2e test functions for dispatch by
// [Tests.TestEgressAll].
var e2eTestFuncs = []struct {
	name string
	fn   func(*Tests, context.Context) error
}{
	{"deny-all", (*Tests).TestEgressDenyAll},
	{"fqdn-exact", (*Tests).TestEgressFqdnExact},
	{"fqdn-wildcard", (*Tests).TestEgressFqdnWildcard},
	{"fqdn-port-restrict", (*Tests).TestEgressFqdnPortRestrict},
	{"cidr-allow", (*Tests).TestEgressCidrAllow},
	{"cidr-logging", (*Tests).TestEgressCidrLogging},
	{"l7-http-path", (*Tests).TestEgressL7HttpPath},
	{"l7-http-method", (*Tests).TestEgressL7HttpMethod},
	{"multiple-rules", (*Tests).TestEgressMultipleRules},
	{"unrestricted", (*Tests).TestEgressUnrestricted},
	{"cidr-except", (*Tests).TestEgressCidrExcept},
	{"tcp-forward", (*Tests).TestEgressTcpForward},
	{"fqdn-wildcard-depth", (*Tests).TestEgressFqdnWildcardDepth},
	{"fqdn-wildcard-multi-label", (*Tests).TestEgressFqdnWildcardMultiLabel},
	{"fqdn-bare-wildcard", (*Tests).TestEgressFqdnBareWildcard},
	{"l7-http-host", (*Tests).TestEgressL7HttpHost},
	{"l7-http-header-presence", (*Tests).TestEgressL7HttpHeaderPresence},
	{"l7-http-header-value", (*Tests).TestEgressL7HttpHeaderValue},
	{"l7-http-combined", (*Tests).TestEgressL7HttpCombined},
	{"l7-http-or-semantics", (*Tests).TestEgressL7HttpOrSemantics},
	{"l7-http-plain", (*Tests).TestEgressL7HttpPlain},
	{"l7-l4-nullification", (*Tests).TestEgressL7L4Nullification},
	{"cidr-multi-except", (*Tests).TestEgressCidrMultiExcept},
	{"fqdn-multiple", (*Tests).TestEgressFqdnMultiple},
	{"port-range", (*Tests).TestEgressPortRange},
	{"dns-proxy-filtering", (*Tests).TestEgressDnsProxyFiltering},
	{"privilege-isolation", (*Tests).TestEgressPrivilegeIsolation},
	{"envoy-uid", (*Tests).TestEgressEnvoyUID},
	{"loopback-deny-all", (*Tests).TestEgressLoopbackDenyAll},
	{"exit-code-propagation", (*Tests).TestEgressExitCodePropagation},
	{"logging", (*Tests).TestEgressLogging},
	{"udp-forward", (*Tests).TestEgressUdpForward},
	{"udp-deny-all", (*Tests).TestEgressUdpDenyAll},
	{"udp-filtered", (*Tests).TestEgressUdpFiltered},
	{"udp-logging", (*Tests).TestEgressUdpLogging},
	{"egress-deny", (*Tests).TestEgressDenyAllViaEgressDeny},
	{"entity-world-ipv4", (*Tests).TestEgressEntityWorldIpv4},
	{"icmp-fqdn", (*Tests).TestEgressIcmpFqdn},
	{"header-match-mismatch", (*Tests).TestEgressHeaderMatchMismatch},
	{"server-name-bare-wildcard", (*Tests).TestEgressServerNameBareWildcard},
	{"fqdn-wildcard-http-rbac", (*Tests).TestEgressFqdnWildcardHttpRbac},
}

// TestEgressAll runs all egress E2E tests across all e2e variants.
//
// Not annotated with +check because E2E tests require InsecureRootCapabilities,
// take significant time, and depend on external network conditions within the
// Dagger engine. Run manually:
//
//	dagger call -m toolchains/terrarium/tests test-egress-all
func (m *Tests) TestEgressAll(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)
	for _, t := range e2eTestFuncs {
		g.Go(func() error { return t.fn(m, ctx) })
	}
	return g.Wait()
}

// TestEgressDenyAll verifies that the deny-all config (egress: [{}]) blocks
// all outbound traffic from the terrarium user. The deny-all pattern has no
// ports, so Envoy is not started; nftables rules alone enforce the lockdown.
//
//	dagger call -m toolchains/terrarium/tests test-egress-deny-all
func (m *Tests) TestEgressDenyAll(ctx context.Context) error {
	return newTestCase("deny-all", `egress:
  - {}
`,
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
		withoutEnvoy(),
		withAssertions(
			networkDenied("http://target-allow:80/", "deny-all: HTTP to target-allow"),
			networkDenied("https://target-allow:443/", "deny-all: HTTPS to target-allow"),
			networkDenied("http://target-deny:80/", "deny-all: HTTP to target-deny"),
			networkDenied("https://target-deny:443/", "deny-all: HTTPS to target-deny"),
		),
	).run(ctx)
}

// TestEgressFqdnExact verifies exact FQDN matching. Only the explicitly named
// host on the specified ports should be reachable.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-exact
func (m *Tests) TestEgressFqdnExact(ctx context.Context) error {
	return newTestCase("fqdn-exact", `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
          - port: "443"
            protocol: TCP
`,
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
		withAssertions(
			httpAllowed("http://target-allow:80/", "fqdn-exact: HTTP to target-allow"),
			httpsPassthrough("https://target-allow:443/", "OK", "fqdn-exact: HTTPS passthrough to target-allow"),
			httpDenied("http://target-deny:80/", "fqdn-exact: HTTP to target-deny"),
			networkDenied("https://target-deny:443/", "fqdn-exact: HTTPS to target-deny"),
		),
	).run(ctx)
}

// TestEgressFqdnWildcard verifies wildcard FQDN matching. Single * matches
// exactly one DNS label.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-wildcard
func (m *Tests) TestEgressFqdnWildcard(ctx context.Context) error {
	return newTestCase("fqdn-wildcard", `egress:
  - toFQDNs:
      - matchPattern: "*.target-zone"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		targetService("allowed.target-zone", defaultNginxConf),
		targetService("denied.other-zone", defaultNginxConf),
		withAssertions(
			httpAllowed("https://allowed.target-zone:443/", "fqdn-wildcard: HTTPS to allowed.target-zone"),
			networkDenied("https://denied.other-zone:443/", "fqdn-wildcard: HTTPS to denied.other-zone"),
			httpDenied("http://allowed.target-zone:80/", "fqdn-wildcard: HTTP port 80 not allowed"),
		),
	).run(ctx)
}

// TestEgressFqdnWildcardDepth verifies that *.target-zone matches exactly one
// DNS label. Multi-label subdomains (deep.sub.target-zone) must be rejected to
// prevent policy bypass.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-wildcard-depth
func (m *Tests) TestEgressFqdnWildcardDepth(ctx context.Context) error {
	return newTestCase("fqdn-wildcard-depth", `egress:
  - toFQDNs:
      - matchPattern: "*.target-zone"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		targetService("one.target-zone", defaultNginxConf),
		targetService("deep.sub.target-zone", defaultNginxConf),
		targetService("denied.other-zone", defaultNginxConf),
		withAssertions(
			httpAllowed("https://one.target-zone:443/", "wildcard-depth: single-label match allowed"),
			networkDenied("https://deep.sub.target-zone:443/", "wildcard-depth: multi-label rejected"),
			networkDenied("https://denied.other-zone:443/", "wildcard-depth: wrong zone denied"),
		),
	).run(ctx)
}

// TestEgressFqdnWildcardMultiLabel verifies that **.target-zone matches
// subdomains at arbitrary depth. Both single-label (one.target-zone) and
// multi-label (two.one.target-zone) subdomains are allowed, exercising the
// distinct RBAC regex path in Envoy.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-wildcard-multi-label
func (m *Tests) TestEgressFqdnWildcardMultiLabel(ctx context.Context) error {
	return newTestCase("fqdn-wildcard-multi-label", `egress:
  - toFQDNs:
      - matchPattern: "**.target-zone"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		targetService("one.target-zone", defaultNginxConf),
		targetService("two.one.target-zone", defaultNginxConf),
		targetService("denied.other-zone", defaultNginxConf),
		withAssertions(
			httpAllowed("https://one.target-zone:443/", "multi-label-wildcard: single-label match allowed"),
			httpAllowed("https://two.one.target-zone:443/", "multi-label-wildcard: multi-label match allowed"),
			networkDenied("https://denied.other-zone:443/", "multi-label-wildcard: wrong zone denied"),
		),
	).run(ctx)
}

// TestEgressFqdnWildcardHttpRbac verifies that the HTTP RBAC filter enforces
// single-label wildcard depth on plain HTTP (port 80). This exercises
// [envoy.buildWildcardHTTPRBACFilter] on the http_forward listener, which
// validates the :authority header against the wildcard pattern. Without this
// filter, multi-label subdomains could bypass the wildcard restriction over
// plain HTTP.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-wildcard-http-rbac
func (m *Tests) TestEgressFqdnWildcardHttpRbac(ctx context.Context) error {
	return newTestCase("fqdn-wildcard-http-rbac", `egress:
  - toFQDNs:
      - matchPattern: "*.target-zone"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`,
		targetService("one.target-zone", defaultNginxConf),
		targetService("deep.sub.target-zone", defaultNginxConf),
		targetService("denied.other-zone", defaultNginxConf),
		withAssertions(
			httpAllowed("http://one.target-zone:80/", "wildcard-http-rbac: single-label match allowed"),
			l7Denied("http://deep.sub.target-zone:80/", "GET", "wildcard-http-rbac: multi-label rejected by HTTP RBAC"),
			httpDenied("http://denied.other-zone:80/", "wildcard-http-rbac: wrong zone denied"),
		),
	).run(ctx)
}

// TestEgressFqdnBareWildcard verifies that matchPattern: "*" allows all FQDNs
// while still enforcing port restrictions. HTTPS (port 443) to any service is
// allowed, but HTTP (port 80) is denied because it is not in toPorts.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-bare-wildcard
func (m *Tests) TestEgressFqdnBareWildcard(ctx context.Context) error {
	return newTestCase("fqdn-bare-wildcard", `egress:
  - toFQDNs:
      - matchPattern: "*"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		targetService("target-a", defaultNginxConf),
		targetService("target-b", defaultNginxConf),
		withAssertions(
			httpAllowed("https://target-a:443/", "bare-wildcard: HTTPS to target-a allowed"),
			httpAllowed("https://target-b:443/", "bare-wildcard: HTTPS to target-b allowed"),
			httpDenied("http://target-a:80/", "bare-wildcard: HTTP port 80 to target-a denied"),
			httpDenied("http://target-b:80/", "bare-wildcard: HTTP port 80 to target-b denied"),
		),
	).run(ctx)
}

// TestEgressFqdnPortRestrict verifies port-level restriction on an allowed
// FQDN. The target is reachable on port 443 but not on port 80.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-port-restrict
func (m *Tests) TestEgressFqdnPortRestrict(ctx context.Context) error {
	return newTestCase("fqdn-port-restrict", `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		targetService("target-allow", defaultNginxConf),
		withAssertions(
			httpAllowed("https://target-allow:443/", "fqdn-port-restrict: HTTPS port 443 allowed"),
			httpDenied("http://target-allow:80/", "fqdn-port-restrict: HTTP port 80 denied"),
		),
	).run(ctx)
}

// TestEgressCidrAllow verifies CIDR-based allowlisting. Any IP is reachable
// on port 80 (broad CIDR), but other ports should be blocked. CIDR TCP
// traffic is routed through Envoy's CIDR catch-all listener (original_dst).
//
//	dagger call -m toolchains/terrarium/tests test-egress-cidr-allow
func (m *Tests) TestEgressCidrAllow(ctx context.Context) error {
	return newTestCase("cidr-allow", `egress:
  - toCIDR:
      - "0.0.0.0/0"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`,
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
		withAssertions(
			httpAllowed("http://target-allow:80/", "cidr-allow: HTTP to target-allow"),
			httpAllowed("http://target-deny:80/", "cidr-allow: HTTP to target-deny"),
			networkDenied("https://target-allow:443/", "cidr-allow: HTTPS port 443 denied"),
		),
	).run(ctx)
}

// TestEgressCidrLogging verifies that CIDR TCP traffic routed through
// Envoy's CIDR catch-all listener produces access log entries on stderr.
// The test enables logging and makes an HTTP request to a CIDR-allowed
// target, then checks stderr for the target hostname in the access log.
//
//	dagger call -m toolchains/terrarium/tests test-egress-cidr-logging
func (m *Tests) TestEgressCidrLogging(ctx context.Context) error {
	return newTestCase("cidr-logging", `logging: true
egress:
  - toCIDR:
      - "0.0.0.0/0"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`,
		targetService("target-cidr", defaultNginxConf),
		withAssertions(
			httpAllowed("http://target-cidr:80/", "cidr-logging: HTTP to target-cidr"),
		),
		withPostExec(func(ctx context.Context, variant string, ctr *dagger.Container) error {
			stderr, err := ctr.Stderr(ctx)
			if err != nil {
				return fmt.Errorf("capturing stderr: %w", err)
			}
			// CIDR TCP goes through the CIDR catch-all listener
			// (TCP proxy with original_dst). The access log line
			// contains the upstream host IP:port in
			// %UPSTREAM_HOST%. Since the request goes to port 80,
			// the log entry will contain ":80" in the upstream.
			if !strings.Contains(stderr, ":80") {
				return fmt.Errorf("stderr does not contain access log entries for CIDR TCP traffic\nstderr:\n%s", stderr)
			}
			return nil
		}),
	).run(ctx)
}

// TestEgressL7HttpPath verifies L7 HTTP path filtering via MITM. Terrarium
// terminates TLS, inspects the HTTP request, and only allows GET requests
// to paths matching /allowed/.*.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-path
func (m *Tests) TestEgressL7HttpPath(ctx context.Context) error {
	return newTestCase("l7-http-path", `egress:
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
`,
		targetService("target-l7", l7NginxConf),
		withAssertions(
			l7Allowed("https://target-l7:443/allowed/resource", "GET", "ALLOWED_PATH", "l7-path: GET /allowed/resource"),
			l7Allowed("https://target-l7:443/allowed/nested/deep", "GET", "ALLOWED_PATH", "l7-path: GET /allowed/nested/deep"),
			l7Denied("https://target-l7:443/denied/resource", "GET", "l7-path: GET /denied/resource denied"),
			l7Denied("https://target-l7:443/allowed/resource", "POST", "l7-path: POST /allowed/resource denied"),
		),
	).run(ctx)
}

// TestEgressL7HttpMethod verifies method-only L7 restriction. GET and HEAD
// are allowed; POST, PUT, DELETE are denied.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-method
func (m *Tests) TestEgressL7HttpMethod(ctx context.Context) error {
	return newTestCase("l7-http-method", `egress:
  - toFQDNs:
      - matchName: "target-l7"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
        rules:
          http:
            - method: "GET|HEAD"
`,
		targetService("target-l7", l7NginxConf),
		withAssertions(
			l7Allowed("https://target-l7:443/", "GET", "ROOT_PATH", "l7-method: GET allowed"),
			l7Allowed("https://target-l7:443/", "HEAD", "", "l7-method: HEAD allowed"),
			l7Denied("https://target-l7:443/", "POST", "l7-method: POST denied"),
			l7Denied("https://target-l7:443/", "PUT", "l7-method: PUT denied"),
			l7Denied("https://target-l7:443/", "DELETE", "l7-method: DELETE denied"),
		),
	).run(ctx)
}

// TestEgressL7HttpHost verifies L7 host header matching. Envoy's RBAC checks
// the HTTP Host/:authority header against the configured host field. Requests
// with the correct host are allowed; requests smuggled with a different Host
// header value are denied with HTTP 403.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-host
func (m *Tests) TestEgressL7HttpHost(ctx context.Context) error {
	return newTestCase("l7-http-host", `egress:
  - toFQDNs:
      - matchName: "target-l7"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
        rules:
          http:
            - host: "target-l7"
`,
		targetService("target-l7", defaultNginxConf),
		withAssertions(
			l7Allowed("https://target-l7:443/", "GET", "OK", "l7-host: matching Host header allowed"),
			l7DeniedWithHeader("https://target-l7:443/", "GET", "Host: evil-host", "l7-host: smuggled Host header denied"),
		),
	).run(ctx)
}

// TestEgressL7HttpHeaderPresence verifies that L7 rules with a headers field
// check for the presence of specific request headers. Requests that include the
// required header are allowed; requests without it are denied with HTTP 403.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-header-presence
func (m *Tests) TestEgressL7HttpHeaderPresence(ctx context.Context) error {
	return newTestCase("l7-http-header-presence", `egress:
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
`,
		targetService("target-l7", defaultNginxConf),
		withAssertions(
			l7BodyWithHeader("https://target-l7:443/", "GET", "X-Allowed: yes", "", "l7-header-presence: request with X-Allowed header allowed"),
			l7Denied("https://target-l7:443/", "GET", "l7-header-presence: request without X-Allowed header denied"),
		),
	).run(ctx)
}

// TestEgressL7HttpHeaderValue verifies that L7 rules with headerMatches check
// exact header name/value pairs. Requests with the correct header value are
// allowed; requests with a wrong value or missing the header entirely are
// denied with HTTP 403.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-header-value
func (m *Tests) TestEgressL7HttpHeaderValue(ctx context.Context) error {
	return newTestCase("l7-http-header-value", `egress:
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
`,
		targetService("target-l7", defaultNginxConf),
		withAssertions(
			l7BodyWithHeader("https://target-l7:443/", "GET", "X-Token: secret", "", "l7-header-value: request with X-Token: secret allowed"),
			l7DeniedWithHeader("https://target-l7:443/", "GET", "X-Token: wrong", "l7-header-value: request with X-Token: wrong denied"),
			l7Denied("https://target-l7:443/", "GET", "l7-header-value: request without X-Token denied"),
		),
	).run(ctx)
}

// TestEgressL7HttpCombined verifies AND semantics for multiple L7 constraints
// within a single HTTP rule. A rule with method, path, and host fields requires
// all three to match; violating any single constraint results in HTTP 403.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-combined
func (m *Tests) TestEgressL7HttpCombined(ctx context.Context) error {
	return newTestCase("l7-http-combined", `egress:
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
`,
		targetService("target-l7", l7NginxConf),
		withAssertions(
			l7Allowed("https://target-l7:443/api/foo", "GET", "ROOT_PATH", "l7-combined: GET /api/foo correct host allowed"),
			l7Denied("https://target-l7:443/api/foo", "POST", "l7-combined: POST /api/foo denied (wrong method)"),
			l7Denied("https://target-l7:443/other", "GET", "l7-combined: GET /other denied (wrong path)"),
			l7DeniedWithHeader("https://target-l7:443/api/foo", "GET", "Host: evil-host", "l7-combined: GET /api/foo wrong host denied"),
		),
	).run(ctx)
}

// TestEgressL7HttpOrSemantics verifies OR semantics for multiple HTTP rule
// entries within a single rules block. Two rules -- {GET, /read/.*} and
// {POST, /write/.*} -- mean a request matching either rule is allowed.
// Cross-combinations (GET /write, POST /read) must be denied with HTTP 403.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-or-semantics
func (m *Tests) TestEgressL7HttpOrSemantics(ctx context.Context) error {
	return newTestCase("l7-http-or-semantics", `egress:
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
`,
		targetService("target-l7", l7NginxConf),
		withAssertions(
			l7Allowed("https://target-l7:443/read/x", "GET", "ROOT_PATH", "l7-or: GET /read/x allowed (rule 1)"),
			l7Allowed("https://target-l7:443/write/x", "POST", "ROOT_PATH", "l7-or: POST /write/x allowed (rule 2)"),
			l7Denied("https://target-l7:443/write/x", "GET", "l7-or: GET /write/x denied (no rule match)"),
			l7Denied("https://target-l7:443/read/x", "POST", "l7-or: POST /read/x denied (no rule match)"),
		),
	).run(ctx)
}

// TestEgressL7HttpPlain verifies that L7 rules work on plain HTTP (port 80)
// where Envoy inspects traffic via http_connection_manager without TLS
// termination. This exercises the virtual host path without MITM.
//
//	dagger call -m toolchains/terrarium/tests test-egress-l7-http-plain
func (m *Tests) TestEgressL7HttpPlain(ctx context.Context) error {
	return newTestCase("l7-http-plain", `egress:
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
`,
		targetService("target-l7", l7NginxConf),
		withAssertions(
			l7Allowed("http://target-l7:80/allowed/resource", "GET", "ALLOWED_PATH", "l7-http-plain: GET /allowed/resource on port 80"),
			l7Denied("http://target-l7:80/denied/resource", "GET", "l7-http-plain: GET /denied/resource on port 80 denied"),
			l7Denied("http://target-l7:80/allowed/resource", "POST", "l7-http-plain: POST /allowed/resource on port 80 denied"),
		),
	).run(ctx)
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
	return newTestCase("l7-l4-nullification", `egress:
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
`,
		targetService("target-l7", l7NginxConf),
		withAssertions(
			httpAllowed("https://target-l7:443/allowed/resource", "l7-l4-nullification: /allowed/ path reachable"),
			httpAllowed("https://target-l7:443/denied/resource", "l7-l4-nullification: /denied/ path reachable (L4 nullifies L7)"),
			httpAllowed("https://target-l7:443/", "l7-l4-nullification: root path reachable (L4 nullifies L7)"),
		),
	).run(ctx)
}

// TestEgressMultipleRules verifies that multiple egress rules are OR'd.
// Traffic matching any rule is allowed; traffic matching none is denied.
//
//	dagger call -m toolchains/terrarium/tests test-egress-multiple-rules
func (m *Tests) TestEgressMultipleRules(ctx context.Context) error {
	return newTestCase("multiple-rules", `egress:
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
`,
		targetService("target-allow", defaultNginxConf),
		targetService("target-l7", l7NginxConf),
		targetService("target-deny", defaultNginxConf),
		withAssertions(
			httpAllowed("http://target-allow:80/", "multiple-rules: HTTP to target-allow (rule 1)"),
			httpDenied("https://target-allow:443/", "multiple-rules: HTTPS to target-allow (rule 1 port 80 only)"),
			httpAllowed("https://target-l7:443/", "multiple-rules: HTTPS to target-l7 (rule 2)"),
			httpDenied("http://target-l7:80/", "multiple-rules: HTTP to target-l7 (rule 2 port 443 only)"),
			networkDenied("http://target-deny:80/", "multiple-rules: HTTP to target-deny (no rule)"),
		),
	).run(ctx)
}

// TestEgressUnrestricted verifies that when no egress rules are present, all
// traffic is unrestricted.
//
//	dagger call -m toolchains/terrarium/tests test-egress-unrestricted
func (m *Tests) TestEgressUnrestricted(ctx context.Context) error {
	return newTestCase("unrestricted", `logging: false
`,
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
		withoutEnvoy(),
		withAssertions(
			httpAllowed("http://target-allow:80/", "unrestricted: HTTP to target-allow"),
			httpAllowed("https://target-allow:443/", "unrestricted: HTTPS to target-allow"),
			httpAllowed("http://target-deny:80/", "unrestricted: HTTP to target-deny"),
			httpAllowed("https://target-deny:443/", "unrestricted: HTTPS to target-deny"),
		),
	).run(ctx)
}

// TestEgressCidrExcept verifies toCIDRSet with an except clause. A broad
// 0.0.0.0/0 CIDR allows all IPs on port 80, but the except list carves out
// target-deny's IP. The placeholder is resolved inside the terrarium container
// where the service binding is active, so the IP always matches.
//
//	dagger call -m toolchains/terrarium/tests test-egress-cidr-except
func (m *Tests) TestEgressCidrExcept(ctx context.Context) error {
	return newTestCase("cidr-except", `egress:
  - toCIDRSet:
      - cidr: "0.0.0.0/0"
        except:
          - "__TARGET_DENY_IP__/32"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`,
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
		withConfigReplacements(map[string]string{
			"__TARGET_DENY_IP__": "target-deny",
		}),
		withAssertions(
			httpAllowed("http://target-allow:80/", "cidr-except: HTTP to target-allow (not in except)"),
			networkDenied("http://target-deny:80/", "cidr-except: HTTP to target-deny (carved out by except)"),
			networkDenied("https://target-allow:443/", "cidr-except: HTTPS port 443 not in toPorts"),
		),
	).run(ctx)
}

// TestEgressCidrMultiExcept verifies that toCIDRSet with multiple entries in
// the except list carves out each excepted IP from the allowed CIDR range.
// A broad 0.0.0.0/0 CIDR allows all IPs on port 80, but two IPs in the except
// list are blocked. Placeholders are resolved inside the terrarium container
// where the service bindings are active, so the IPs always match.
//
//	dagger call -m toolchains/terrarium/tests test-egress-cidr-multi-except
func (m *Tests) TestEgressCidrMultiExcept(ctx context.Context) error {
	return newTestCase("cidr-multi-except", `egress:
  - toCIDRSet:
      - cidr: "0.0.0.0/0"
        except:
          - "__TARGET_DENY_1_IP__/32"
          - "__TARGET_DENY_2_IP__/32"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`,
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny-1", defaultNginxConf),
		targetService("target-deny-2", defaultNginxConf),
		withConfigReplacements(map[string]string{
			"__TARGET_DENY_1_IP__": "target-deny-1",
			"__TARGET_DENY_2_IP__": "target-deny-2",
		}),
		withAssertions(
			httpAllowed("http://target-allow:80/", "cidr-multi-except: HTTP to target-allow (not in except)"),
			networkDenied("http://target-deny-1:80/", "cidr-multi-except: HTTP to target-deny-1 (excepted)"),
			networkDenied("http://target-deny-2:80/", "cidr-multi-except: HTTP to target-deny-2 (excepted)"),
		),
	).run(ctx)
}

// TestEgressTcpForward verifies that tcpForwards creates a plain TCP proxy
// on localhost that reaches the upstream service. A socat echo server
// listens on port 22, and terrarium proxies localhost:15022 to it.
//
//	dagger call -m toolchains/terrarium/tests test-egress-tcp-forward
func (m *Tests) TestEgressTcpForward(ctx context.Context) error {
	return newTestCase("tcp-forward", `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
tcpForwards:
  - host: "PLACEHOLDER_TARGET_TCP"
    port: 8080
`,
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
		targetServiceOnPort("target-tcp", 8080),
		withConfigReplacements(map[string]string{
			"PLACEHOLDER_TARGET_TCP": "target-tcp",
		}),
		withAssertions(
			httpAllowed("https://target-allow:443/", "tcp-forward: HTTPS to target-allow via FQDN rule"),
			networkDenied("https://target-deny:443/", "tcp-forward: HTTPS to target-deny denied"),
			httpAllowed("http://127.0.0.1:23080/", "tcp-forward: HTTP via TCP forward to target-tcp:8080"),
		),
	).run(ctx)
}

// TestEgressFqdnMultiple verifies that multiple matchName entries in toFQDNs
// are OR'd correctly. Both named FQDNs are allowed on port 443; an unlisted
// FQDN is denied.
//
//	dagger call -m toolchains/terrarium/tests test-egress-fqdn-multiple
func (m *Tests) TestEgressFqdnMultiple(ctx context.Context) error {
	return newTestCase("fqdn-multiple", `egress:
  - toFQDNs:
      - matchName: "target-a"
      - matchName: "target-b"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		targetService("target-a", defaultNginxConf),
		targetService("target-b", defaultNginxConf),
		targetService("target-c", defaultNginxConf),
		withAssertions(
			httpAllowed("https://target-a:443/", "fqdn-multiple: HTTPS to target-a allowed"),
			httpAllowed("https://target-b:443/", "fqdn-multiple: HTTPS to target-b allowed"),
			networkDenied("https://target-c:443/", "fqdn-multiple: HTTPS to target-c denied"),
		),
	).run(ctx)
}

// TestEgressPortRange verifies that endPort correctly allows a range of ports.
// An FQDN rule with port 8000 and endPort 8100 should allow services running
// on ports within the range (e.g., 8080) while blocking ports outside the
// range (e.g., 9000). Uses custom nginx services on non-standard ports.
//
//	dagger call -m toolchains/terrarium/tests test-egress-port-range
func (m *Tests) TestEgressPortRange(ctx context.Context) error {
	return newTestCase("port-range", `egress:
  - toFQDNs:
      - matchName: "target-range"
    toPorts:
      - ports:
          - port: "8000"
            endPort: 8100
            protocol: TCP
`,
		targetServiceOnPort("target-range", 8080),
		targetServiceOnPort("target-outside", 9000),
		withAssertions(
			httpAllowed("https://target-range:8080/", "port-range: port 8080 within range 8000-8100"),
			httpDenied("https://target-range:9000/", "port-range: port 9000 outside range 8000-8100"),
			networkDenied("https://target-outside:9000/", "port-range: different FQDN outside rule denied"),
		),
	).run(ctx)
}

// TestEgressDnsProxyFiltering verifies that the DNS proxy returns REFUSED for
// domains not in the allowlist. An FQDN rule allows "target-allow" on port 443;
// dig queries against "target-deny" must receive status REFUSED (not NXDOMAIN
// or a valid answer), while queries for "target-allow" must return NOERROR with
// a resolved address.
//
//	dagger call -m toolchains/terrarium/tests test-egress-dns-proxy-filtering
func (m *Tests) TestEgressDnsProxyFiltering(ctx context.Context) error {
	return newTestCase("dns-proxy-filtering", `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
		withRootAssertions(
			dnsForwarded("target-allow", "dns-proxy: allowed domain is forwarded"),
			dnsRefused("target-deny", "dns-proxy: denied domain returns REFUSED"),
		),
	).run(ctx)
}

// TestEgressPrivilegeIsolation verifies that the terrarium process runs as
// UID 1000 / GID 1000 with all Linux capabilities dropped. The terrarium
// command writes identity and capability info to files, which the assertion
// script then validates. A filtered policy (FQDN rule) is used to ensure
// privilege drop happens in the filtered code path.
//
//	dagger call -m toolchains/terrarium/tests test-egress-privilege-isolation
func (m *Tests) TestEgressPrivilegeIsolation(ctx context.Context) error {
	return newTestCase("privilege-isolation", `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		targetService("target-allow", defaultNginxConf),
		withInitCommand(`sh -c 'id > /tmp/terrarium_id.txt; grep "^Cap" /proc/self/status > /tmp/terrarium_caps.txt; sleep infinity'`),
		withRootAssertions(
			fileGrep("/tmp/terrarium_id.txt", "uid=1000", "privilege-isolation: UID is 1000"),
			fileGrep("/tmp/terrarium_id.txt", "gid=1000", "privilege-isolation: GID is 1000"),
			fileGrep("/tmp/terrarium_caps.txt", "CapInh:.*0000000000000000", "privilege-isolation: CapInh is zeroed"),
			fileGrep("/tmp/terrarium_caps.txt", "CapPrm:.*0000000000000000", "privilege-isolation: CapPrm is zeroed"),
			fileGrep("/tmp/terrarium_caps.txt", "CapEff:.*0000000000000000", "privilege-isolation: CapEff is zeroed"),
			fileGrep("/tmp/terrarium_caps.txt", "CapBnd:.*0000000000000000", "privilege-isolation: CapBnd is zeroed"),
			fileGrep("/tmp/terrarium_caps.txt", "CapAmb:.*0000000000000000", "privilege-isolation: CapAmb is zeroed"),
		),
	).run(ctx)
}

// TestEgressEnvoyUID verifies that the Envoy process runs as UID 1001. A
// filtered policy (FQDN rule) is used to ensure Envoy is started. After
// Envoy readiness, the test checks ps output to confirm the envoy process
// owner.
//
//	dagger call -m toolchains/terrarium/tests test-egress-envoy-uid
func (m *Tests) TestEgressEnvoyUID(ctx context.Context) error {
	return newTestCase("envoy-uid", `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		targetService("target-allow", defaultNginxConf),
		withRootAssertions(
			envoyUID("1001", "envoy-uid: Envoy process running as UID 1001"),
		),
	).run(ctx)
}

// TestEgressLoopbackDenyAll verifies that localhost communication works even
// under a deny-all policy. A simple HTTP listener is started on localhost
// inside the container before terrarium init. The terrarium command (UID 1000)
// verifies it can reach the localhost service while external traffic is denied.
//
//	dagger call -m toolchains/terrarium/tests test-egress-loopback-deny-all
func (m *Tests) TestEgressLoopbackDenyAll(ctx context.Context) error {
	return newTestCase("loopback-deny-all", `egress:
  - {}
`,
		targetService("target-external", defaultNginxConf),
		withoutEnvoy(),
		withLoopbackPort(8080),
		withAssertions(
			httpAllowed("http://127.0.0.1:8080/", "loopback-deny-all: terrarium can reach localhost:8080"),
			networkDenied("http://target-external:80/", "loopback-deny-all: external traffic denied"),
		),
	).run(ctx)
}

// TestEgressExitCodePropagation verifies that terrarium propagates the child
// process exit code. When the terrarium command exits with a non-zero code,
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
	return newTestCase("logging", `logging: true
egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
		withAssertions(
			httpAllowed("https://target-allow:443/", "logging: HTTPS to target-allow"),
			networkDenied("https://target-deny:443/", "logging: HTTPS to target-deny"),
		),
		withPostExec(func(ctx context.Context, variant string, ctr *dagger.Container) error {
			stderr, err := ctr.Stderr(ctx)
			if err != nil {
				return fmt.Errorf("capturing stderr: %w", err)
			}
			if !strings.Contains(stderr, "target-allow") {
				return fmt.Errorf("stderr does not contain Envoy access log entries for target-allow\nstderr:\n%s", stderr)
			}
			return nil
		}),
	).run(ctx)
}

// TestEgressUdpForward verifies that UDP datagrams reach an echo service
// in unrestricted mode (no egress rules). Root has a blanket ACCEPT in the
// output chain so traffic goes directly without TPROXY.
//
//	dagger call -m toolchains/terrarium/tests test-egress-udp-forward
func (m *Tests) TestEgressUdpForward(ctx context.Context) error {
	return newTestCase("udp-forward", `logging: false
`,
		udpEchoService("target-udp", 5000),
		withoutEnvoy(),
		withRootAssertions(
			udpAllowed("target-udp", 5000, "UDP_ECHO_OK", "udp-forward: UDP to target-udp:5000 allowed"),
		),
	).run(ctx)
}

// TestEgressUdpDenyAll verifies that UDP is blocked in deny-all mode.
// No mangle chains or Envoy TPROXY listener are created. Assertions run
// as UID 1000 so the denial is tested through the terrarium-UID path.
//
//	dagger call -m toolchains/terrarium/tests test-egress-udp-deny-all
func (m *Tests) TestEgressUdpDenyAll(ctx context.Context) error {
	return newTestCase("udp-deny-all", `egress:
  - {}
`,
		udpEchoService("target-udp", 5000),
		withoutEnvoy(),
		withAssertions(
			udpDenied("target-udp", 5000, "udp-deny-all: UDP to target-udp:5000 denied"),
		),
	).run(ctx)
}

// TestEgressUdpFiltered verifies that UDP traffic on a non-policy port is
// denied in filtered mode. A CIDR rule allows UDP port 5000, but port 6000
// has no policy and must be dropped by the nftables filter chain. The
// allowed-port assertion is omitted because Envoy's ORIGINAL_DST cluster
// cannot recover the destination from TPROXY'd UDP transparent sockets
// (upstream Envoy issue). Assertions run as UID 1000 because nftables
// policy only applies to that UID.
//
//	dagger call -m toolchains/terrarium/tests test-egress-udp-filtered
func (m *Tests) TestEgressUdpFiltered(ctx context.Context) error {
	return newTestCase("udp-filtered", `egress:
  - toCIDRSet:
      - cidr: "0.0.0.0/0"
    toPorts:
      - ports:
          - port: "5000"
            protocol: UDP
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		udpEchoService("target-udp-deny", 6000),
		targetService("target-allow", defaultNginxConf),
		withAssertions(
			udpDenied("target-udp-deny", 6000, "udp-filtered: UDP to target-udp-deny:6000 denied (wrong port)"),
		),
	).run(ctx)
}

// TestEgressUdpLogging verifies that Envoy access logs on stderr contain
// evidence of UDP traffic when logging is enabled. The UDP datagram is
// sent as UID 1000 so it goes through the mangle/TPROXY path and reaches
// Envoy. Envoy logs the connection attempt even though the ORIGINAL_DST
// cluster cannot recover the destination from the transparent socket
// (upstream Envoy issue with TPROXY'd UDP).
//
//	dagger call -m toolchains/terrarium/tests test-egress-udp-logging
func (m *Tests) TestEgressUdpLogging(ctx context.Context) error {
	return newTestCase("udp-logging", `logging: true
`,
		udpEchoService("target-udp", 5000),
		withoutEnvoy(),
		withAssertions(
			udpSend("target-udp", 5000, "udp-logging: send UDP datagram"),
		),
		withPostExec(func(ctx context.Context, variant string, ctr *dagger.Container) error {
			stderr, err := ctr.Stderr(ctx)
			if err != nil {
				return fmt.Errorf("capturing stderr: %w", err)
			}
			if !strings.Contains(stderr, "original_dst") {
				return fmt.Errorf("stderr does not contain Envoy log entries for UDP traffic\nstderr:\n%s", stderr)
			}
			return nil
		}),
	).run(ctx)
}

// TestEgressDenyAllViaEgressDeny verifies that egressDeny rules block a subset
// of otherwise allowed traffic. Deny CIDR NAT chains ACCEPT (skip redirect)
// before allow CIDR chains REDIRECT, so port 443 is denied even though a
// broad CIDR allow covers it. The filter chain's deny rules DROP the
// non-redirected traffic.
//
//	dagger call -m toolchains/terrarium/tests test-egress-deny-all-via-egress-deny
func (m *Tests) TestEgressDenyAllViaEgressDeny(ctx context.Context) error {
	return newTestCase("egress-deny", `egress:
  - toCIDR:
      - "0.0.0.0/0"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
          - port: "443"
            protocol: TCP
egressDeny:
  - toCIDR:
      - "0.0.0.0/0"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
		withAssertions(
			httpAllowed("http://target-allow:80/", "egress-deny: HTTP port 80 allowed"),
			networkDenied("https://target-deny:443/", "egress-deny: HTTPS port 443 denied by egressDeny"),
		),
	).run(ctx)
}

// TestEgressEntityWorldIpv4 verifies that toEntities with world-ipv4 expands
// to 0.0.0.0/0. Port 80 is allowed; port 443 is not in toPorts and is blocked.
//
//	dagger call -m toolchains/terrarium/tests test-egress-entity-world-ipv4
func (m *Tests) TestEgressEntityWorldIpv4(ctx context.Context) error {
	return newTestCase("entity-world-ipv4", `egress:
  - toEntities:
      - world-ipv4
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`,
		targetService("target-allow", defaultNginxConf),
		withoutEnvoy(),
		withAssertions(
			httpAllowed("http://target-allow:80/", "entity-world-ipv4: HTTP port 80 allowed"),
			networkDenied("https://target-allow:443/", "entity-world-ipv4: HTTPS port 443 denied"),
		),
	).run(ctx)
}

// TestEgressIcmpFqdn verifies that ICMP rules combined with toFQDNs create
// dedicated FQDN ipsets for ICMP traffic. DNS resolution through the proxy
// populates the ICMP ipset, enabling ping to allowed FQDNs while denying
// ping to unlisted FQDNs.
//
//	dagger call -m toolchains/terrarium/tests test-egress-icmp-fqdn
func (m *Tests) TestEgressIcmpFqdn(ctx context.Context) error {
	return newTestCase("icmp-fqdn", `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
  - toFQDNs:
      - matchName: "target-allow"
    icmps:
      - fields:
          - type: 8
            family: IPv4
`,
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
		withPackages("iputils-ping"),
		withRootAssertions(
			httpsPassthrough("https://target-allow:443/", "OK", "icmp-fqdn: HTTPS passthrough"),
			networkDenied("https://target-deny:443/", "icmp-fqdn: HTTPS to target-deny denied"),
			pingAllowed("target-allow", "icmp-fqdn: ping to target-allow"),
			pingDenied("target-deny", "icmp-fqdn: ping to target-deny denied"),
		),
	).run(ctx)
}

// TestEgressHeaderMatchMismatch verifies the headerMatch mismatch REPLACE
// action. When a request header does not match the expected value, Envoy
// overwrites it before forwarding. A custom nginx config echoes the X-Token
// header value in the response body, allowing verification that REPLACE
// normalizes all requests to carry the correct value.
//
//	dagger call -m toolchains/terrarium/tests test-egress-header-match-mismatch
func (m *Tests) TestEgressHeaderMatchMismatch(ctx context.Context) error {
	return newTestCase("header-match-mismatch", `egress:
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
                  mismatch: REPLACE
`,
		targetService("target-l7", headerEchoNginxConf),
		withAssertions(
			l7BodyWithHeader("https://target-l7:443/", "GET", "X-Token: secret", "TOKEN=secret", "header-mismatch: correct header passed through"),
			l7BodyWithHeader("https://target-l7:443/", "GET", "X-Token: wrong", "TOKEN=secret", "header-mismatch: wrong header replaced with correct value"),
			l7Allowed("https://target-l7:443/", "GET", "TOKEN=secret", "header-mismatch: missing header replaced with correct value"),
		),
	).run(ctx)
}

// TestEgressServerNameBareWildcard verifies that serverNames: ["*"] normalizes
// to nil, meaning no effective serverNames restriction. With no L7 rules and no
// effective serverNames, TLS passes through without MITM interception.
//
//	dagger call -m toolchains/terrarium/tests test-egress-server-name-bare-wildcard
func (m *Tests) TestEgressServerNameBareWildcard(ctx context.Context) error {
	return newTestCase("server-name-bare-wildcard", `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
        serverNames:
          - "*"
`,
		targetService("target-allow", defaultNginxConf),
		targetService("target-deny", defaultNginxConf),
		withAssertions(
			httpsPassthrough("https://target-allow:443/", "OK", "server-name-bare-wildcard: HTTPS passthrough (no MITM)"),
			networkDenied("https://target-deny:443/", "server-name-bare-wildcard: HTTPS to target-deny denied"),
		),
	).run(ctx)
}
