package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Assertion builder functions construct [assertion] values that match
// the testrunner's JSON schema. Each function maps to an assertion type
// (e.g., httpAllowed -> "http_allowed").

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

//nolint:unparam // parameterized for consistency with other assertion builders.
func l7BodyWithHeader(url, method, header, body, desc string) assertion {
	return assertion{Type: "l7_body_with_header", URL: url, Method: method, Header: header, Body: body, Desc: desc}
}

func l7DeniedWithHeader(url, method, header, desc string) assertion {
	return assertion{Type: "l7_denied_with_header", URL: url, Method: method, Header: header, Desc: desc}
}

//nolint:unparam // parameterized for consistency with other assertion builders.
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

func dnsForwarded(domain, desc string) assertion {
	return assertion{Type: "dns_forwarded", Domain: domain, Desc: desc}
}

func dnsBlocked(domain, desc string) assertion {
	return assertion{Type: "dns_blocked", Domain: domain, Desc: desc}
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

func nftTableExists(tableName, desc string) assertion {
	return assertion{Type: "nft_table_exists", Expected: tableName, Desc: desc}
}

func nftTableAbsent(tableName, desc string) assertion {
	return assertion{Type: "nft_table_absent", Expected: tableName, Desc: desc}
}

func systemctlActive(unit, desc string) assertion {
	return assertion{Type: "systemctl_active", Expected: unit, Desc: desc}
}

func multiUIDDenied(url, uid, desc string) assertion {
	return assertion{Type: "multi_uid_denied", URL: url, UID: uid, Desc: desc}
}

// vmTests defines all Lima VM e2e test cases run by the
// testrunner-lima command. Tests cover deny-all, FQDN exact/wildcard,
// CIDR, L7 HTTP filtering, port ranges, UDP, ICMP, egress deny rules,
// guard table behavior, config reload, and container-originated traffic.
var vmTests = []vmTest{
	{
		name: "vm-deny-all",
		config: `egress:
  - {}
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
			nginxService("target-deny", defaultNginxConf),
		},
		assertions: []assertion{
			networkDenied("http://target-allow:80/", "deny-all: HTTP to target-allow"),
			networkDenied("https://target-allow:443/", "deny-all: HTTPS to target-allow"),
			networkDenied("http://target-deny:80/", "deny-all: HTTP to target-deny"),
			networkDenied("https://target-deny:443/", "deny-all: HTTPS to target-deny"),
		},
	},
	{
		name: "vm-fqdn-exact",
		config: `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
          - port: "443"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
			nginxService("target-deny", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("http://target-allow:80/", "fqdn-exact: HTTP to target-allow"),
			httpsPassthrough("https://target-allow:443/", "OK", "fqdn-exact: HTTPS passthrough to target-allow"),
			networkDenied("http://target-deny:80/", "fqdn-exact: HTTP to target-deny"),
			networkDenied("https://target-deny:443/", "fqdn-exact: HTTPS to target-deny"),
		},
	},
	{
		name: "vm-fqdn-wildcard",
		config: `egress:
  - toFQDNs:
      - matchPattern: "*.target-zone"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("allowed.target-zone", defaultNginxConf),
			nginxService("denied.other-zone", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("https://allowed.target-zone:443/", "fqdn-wildcard: HTTPS to allowed.target-zone"),
			networkDenied("https://denied.other-zone:443/", "fqdn-wildcard: HTTPS to denied.other-zone"),
			httpDenied("http://allowed.target-zone:80/", "fqdn-wildcard: HTTP port 80 not allowed"),
		},
	},
	{
		name: "vm-fqdn-wildcard-depth",
		config: `egress:
  - toFQDNs:
      - matchPattern: "*.target-zone"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("one.target-zone", defaultNginxConf),
			nginxService("deep.sub.target-zone", defaultNginxConf),
			nginxService("denied.other-zone", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("https://one.target-zone:443/", "wildcard-depth: single-label match allowed"),
			networkDenied("https://deep.sub.target-zone:443/", "wildcard-depth: multi-label rejected"),
			networkDenied("https://denied.other-zone:443/", "wildcard-depth: wrong zone denied"),
		},
	},
	{
		name: "vm-fqdn-wildcard-multi-label",
		config: `egress:
  - toFQDNs:
      - matchPattern: "**.target-zone"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("one.target-zone", defaultNginxConf),
			nginxService("two.one.target-zone", defaultNginxConf),
			nginxService("denied.other-zone", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("https://one.target-zone:443/", "multi-label-wildcard: single-label match allowed"),
			httpAllowed("https://two.one.target-zone:443/", "multi-label-wildcard: multi-label match allowed"),
			networkDenied("https://denied.other-zone:443/", "multi-label-wildcard: wrong zone denied"),
		},
	},
	{
		name: "vm-fqdn-bare-wildcard",
		config: `egress:
  - toFQDNs:
      - matchPattern: "*"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-a", defaultNginxConf),
			nginxService("target-b", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("https://target-a:443/", "bare-wildcard: HTTPS to target-a allowed"),
			httpAllowed("https://target-b:443/", "bare-wildcard: HTTPS to target-b allowed"),
			httpDenied("http://target-a:80/", "bare-wildcard: HTTP port 80 to target-a denied"),
			httpDenied("http://target-b:80/", "bare-wildcard: HTTP port 80 to target-b denied"),
		},
	},
	{
		name: "vm-fqdn-port-restrict",
		config: `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("https://target-allow:443/", "fqdn-port-restrict: HTTPS port 443 allowed"),
			httpDenied("http://target-allow:80/", "fqdn-port-restrict: HTTP port 80 denied"),
		},
	},
	{
		name: "vm-fqdn-multiple",
		config: `egress:
  - toFQDNs:
      - matchName: "target-a"
      - matchName: "target-b"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-a", defaultNginxConf),
			nginxService("target-b", defaultNginxConf),
			nginxService("target-c", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("https://target-a:443/", "fqdn-multiple: HTTPS to target-a allowed"),
			httpAllowed("https://target-b:443/", "fqdn-multiple: HTTPS to target-b allowed"),
			networkDenied("https://target-c:443/", "fqdn-multiple: HTTPS to target-c denied"),
		},
	},
	{
		name: "vm-cidr-allow",
		config: `egress:
  - toCIDR:
      - "0.0.0.0/0"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
			nginxService("target-deny", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("http://target-allow:80/", "cidr-allow: HTTP to target-allow"),
			httpAllowed("http://target-deny:80/", "cidr-allow: HTTP to target-deny"),
			networkDenied("https://target-allow:443/", "cidr-allow: HTTPS port 443 denied"),
		},
	},
	{
		name: "vm-cidr-logging",
		config: `logging:
  envoy:
    accessLog:
      enabled: true
  firewall:
    enabled: true
egress:
  - toCIDR:
      - "0.0.0.0/0"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-cidr", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("http://target-cidr:80/", "cidr-logging: HTTP to target-cidr"),
		},
	},
	{
		name: "vm-l7-http-path",
		config: `egress:
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
		services: []serviceSpec{
			nginxService("target-l7", l7NginxConf),
		},
		assertions: []assertion{
			l7Allowed(
				"https://target-l7:443/allowed/resource",
				"GET",
				"ALLOWED_PATH",
				"l7-path: GET /allowed/resource",
			),
			l7Allowed(
				"https://target-l7:443/allowed/nested/deep",
				"GET",
				"ALLOWED_PATH",
				"l7-path: GET /allowed/nested/deep",
			),
			l7Denied("https://target-l7:443/denied/resource", "GET", "l7-path: GET /denied/resource denied"),
			l7Denied("https://target-l7:443/allowed/resource", "POST", "l7-path: POST /allowed/resource denied"),
		},
	},
	{
		name: "vm-l7-http-method",
		config: `egress:
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
		services: []serviceSpec{
			nginxService("target-l7", l7NginxConf),
		},
		assertions: []assertion{
			l7Allowed("https://target-l7:443/", "GET", "ROOT_PATH", "l7-method: GET allowed"),
			l7Allowed("https://target-l7:443/", "HEAD", "", "l7-method: HEAD allowed"),
			l7Denied("https://target-l7:443/", "POST", "l7-method: POST denied"),
			l7Denied("https://target-l7:443/", "PUT", "l7-method: PUT denied"),
			l7Denied("https://target-l7:443/", "DELETE", "l7-method: DELETE denied"),
		},
	},
	{
		name: "vm-l7-http-host",
		config: `egress:
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
		services: []serviceSpec{
			nginxService("target-l7", defaultNginxConf),
		},
		assertions: []assertion{
			l7Allowed("https://target-l7:443/", "GET", "OK", "l7-host: matching Host header allowed"),
			l7DeniedWithHeader(
				"https://target-l7:443/",
				"GET",
				"Host: evil-host",
				"l7-host: smuggled Host header denied",
			),
		},
	},
	{
		name: "vm-l7-http-header-presence",
		config: `egress:
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
		services: []serviceSpec{
			nginxService("target-l7", defaultNginxConf),
		},
		assertions: []assertion{
			l7BodyWithHeader(
				"https://target-l7:443/",
				"GET",
				"X-Allowed: yes",
				"",
				"l7-header-presence: request with X-Allowed header allowed",
			),
			l7Denied("https://target-l7:443/", "GET", "l7-header-presence: request without X-Allowed header denied"),
		},
	},
	{
		name: "vm-l7-http-header-value",
		config: `egress:
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
		services: []serviceSpec{
			nginxService("target-l7", defaultNginxConf),
		},
		assertions: []assertion{
			l7BodyWithHeader(
				"https://target-l7:443/",
				"GET",
				"X-Token: secret",
				"",
				"l7-header-value: request with X-Token: secret allowed",
			),
			l7DeniedWithHeader(
				"https://target-l7:443/",
				"GET",
				"X-Token: wrong",
				"l7-header-value: request with X-Token: wrong denied",
			),
			l7Denied("https://target-l7:443/", "GET", "l7-header-value: request without X-Token denied"),
		},
	},
	{
		name: "vm-l7-http-combined",
		config: `egress:
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
		services: []serviceSpec{
			nginxService("target-l7", l7NginxConf),
		},
		assertions: []assertion{
			l7Allowed(
				"https://target-l7:443/api/foo",
				"GET",
				"ROOT_PATH",
				"l7-combined: GET /api/foo correct host allowed",
			),
			l7Denied("https://target-l7:443/api/foo", "POST", "l7-combined: POST /api/foo denied (wrong method)"),
			l7Denied("https://target-l7:443/other", "GET", "l7-combined: GET /other denied (wrong path)"),
			l7DeniedWithHeader(
				"https://target-l7:443/api/foo",
				"GET",
				"Host: evil-host",
				"l7-combined: GET /api/foo wrong host denied",
			),
		},
	},
	{
		name: "vm-l7-http-or-semantics",
		config: `egress:
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
		services: []serviceSpec{
			nginxService("target-l7", l7NginxConf),
		},
		assertions: []assertion{
			l7Allowed("https://target-l7:443/read/x", "GET", "ROOT_PATH", "l7-or: GET /read/x allowed (rule 1)"),
			l7Allowed("https://target-l7:443/write/x", "POST", "ROOT_PATH", "l7-or: POST /write/x allowed (rule 2)"),
			l7Denied("https://target-l7:443/write/x", "GET", "l7-or: GET /write/x denied (no rule match)"),
			l7Denied("https://target-l7:443/read/x", "POST", "l7-or: POST /read/x denied (no rule match)"),
		},
	},
	{
		name: "vm-l7-http-plain",
		config: `egress:
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
		services: []serviceSpec{
			nginxService("target-l7", l7NginxConf),
		},
		assertions: []assertion{
			l7Allowed(
				"http://target-l7:80/allowed/resource",
				"GET",
				"ALLOWED_PATH",
				"l7-http-plain: GET /allowed/resource on port 80",
			),
			l7Denied(
				"http://target-l7:80/denied/resource",
				"GET",
				"l7-http-plain: GET /denied/resource on port 80 denied",
			),
			l7Denied(
				"http://target-l7:80/allowed/resource",
				"POST",
				"l7-http-plain: POST /allowed/resource on port 80 denied",
			),
		},
	},
	{
		name: "vm-l7-l4-nullification",
		config: `egress:
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
		services: []serviceSpec{
			nginxService("target-l7", l7NginxConf),
		},
		assertions: []assertion{
			httpAllowed("https://target-l7:443/allowed/resource", "l7-l4-nullification: /allowed/ path reachable"),
			httpAllowed(
				"https://target-l7:443/denied/resource",
				"l7-l4-nullification: /denied/ path reachable (L4 nullifies L7)",
			),
			httpAllowed("https://target-l7:443/", "l7-l4-nullification: root path reachable (L4 nullifies L7)"),
		},
	},
	{
		name: "vm-multiple-rules",
		config: `egress:
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
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
			nginxService("target-l7", l7NginxConf),
			nginxService("target-deny", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("http://target-allow:80/", "multiple-rules: HTTP to target-allow (rule 1)"),
			httpDenied("https://target-allow:443/", "multiple-rules: HTTPS to target-allow (rule 1 port 80 only)"),
			httpAllowed("https://target-l7:443/", "multiple-rules: HTTPS to target-l7 (rule 2)"),
			httpDenied("http://target-l7:80/", "multiple-rules: HTTP to target-l7 (rule 2 port 443 only)"),
			networkDenied("http://target-deny:80/", "multiple-rules: HTTP to target-deny (no rule)"),
		},
	},
	{
		name:   "vm-unrestricted",
		config: ``,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
			nginxService("target-deny", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("http://target-allow:80/", "unrestricted: HTTP to target-allow"),
			httpAllowed("https://target-allow:443/", "unrestricted: HTTPS to target-allow"),
			httpAllowed("http://target-deny:80/", "unrestricted: HTTP to target-deny"),
			httpAllowed("https://target-deny:443/", "unrestricted: HTTPS to target-deny"),
		},
	},
	{
		name: "vm-port-range",
		config: `egress:
  - toFQDNs:
      - matchName: "target-range"
    toPorts:
      - ports:
          - port: "8075"
            endPort: 8085
            protocol: TCP
`,
		services: []serviceSpec{
			nginxServiceOnPort("target-range", 8080),
			nginxServiceOnPort("target-outside", 9000),
		},
		assertions: []assertion{
			httpAllowed("https://target-range:8080/", "port-range: port 8080 within range 8075-8085"),
			networkDenied("https://target-range:9000/", "port-range: port 9000 outside range 8075-8085"),
			networkDenied("https://target-outside:9000/", "port-range: different FQDN outside rule denied"),
		},
	},
	{
		name: "vm-dns-proxy-filtering",
		config: `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
			nginxService("target-deny", defaultNginxConf),
		},
		rootAssertions: []assertion{
			dnsForwarded("target-allow", "dns-proxy: allowed domain is forwarded"),
			dnsBlocked("target-deny", "dns-proxy: denied domain returns NXDOMAIN"),
		},
	},
	{
		name: "vm-envoy-uid",
		config: `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
		},
		rootAssertions: []assertion{
			envoyUID("1001", "envoy-uid: Envoy process running as UID 1001"),
		},
	},
	{
		name: "vm-loopback-deny-all",
		config: `egress:
  - {}
`,
		services: []serviceSpec{
			nginxService("target-external", defaultNginxConf),
		},
		assertions: []assertion{
			networkDenied("http://target-external:80/", "loopback-deny-all: external traffic denied"),
		},
		rootAssertions: []assertion{
			// Loopback is always reachable in daemon mode -- the guard
			// table and daemon rules both allow loopback traffic.
			httpAllowed("http://127.0.0.1:80/", "loopback-deny-all: loopback reachable"),
		},
	},
	{
		name: "vm-logging",
		config: `logging:
  envoy:
    accessLog:
      enabled: true
egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
			nginxService("target-deny", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("https://target-allow:443/", "logging: HTTPS to target-allow"),
			networkDenied("https://target-deny:443/", "logging: HTTPS to target-deny"),
		},
	},
	{
		name: "vm-tcp-forward",
		config: `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
tcpForwards:
  - host: "target-tcp"
    port: 8080
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
			nginxService("target-deny", defaultNginxConf),
			tcpEchoService("target-tcp", 8080),
		},
		assertions: []assertion{
			httpAllowed("https://target-allow:443/", "tcp-forward: HTTPS to target-allow via FQDN rule"),
			networkDenied("https://target-deny:443/", "tcp-forward: HTTPS to target-deny denied"),
			tcpForward("target-tcp:8080", "TCP_FORWARD_OK", "tcp-forward: TCP forward to target-tcp:8080"),
		},
	},
	{
		name:   "vm-udp-forward",
		config: ``,
		services: []serviceSpec{
			udpEchoService("target-udp", 5000),
		},
		rootAssertions: []assertion{
			udpAllowed("target-udp", 5000, "UDP_ECHO_OK", "udp-forward: UDP to target-udp:5000 allowed"),
		},
	},
	{
		name: "vm-udp-deny-all",
		config: `egress:
  - {}
`,
		services: []serviceSpec{
			udpEchoService("target-udp", 5000),
		},
		assertions: []assertion{
			udpDenied("target-udp", 5000, "udp-deny-all: UDP to target-udp:5000 denied"),
		},
	},
	{
		name: "vm-udp-filtered",
		config: `egress:
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
		services: []serviceSpec{
			udpEchoService("target-udp-deny", 6000),
			nginxService("target-allow", defaultNginxConf),
		},
		assertions: []assertion{
			udpDenied("target-udp-deny", 6000, "udp-filtered: UDP to target-udp-deny:6000 denied (wrong port)"),
		},
	},
	{
		name: "vm-udp-logging",
		config: `logging:
  envoy:
    accessLog:
      enabled: true
`,
		services: []serviceSpec{
			udpEchoService("target-udp", 5000),
		},
		assertions: []assertion{
			udpSend("target-udp", 5000, "udp-logging: send UDP datagram"),
		},
	},
	{
		name: "vm-egress-deny",
		config: `egress:
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
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
			nginxService("target-deny", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("http://target-allow:80/", "egress-deny: HTTP port 80 allowed"),
			networkDenied("https://target-deny:443/", "egress-deny: HTTPS port 443 denied by egressDeny"),
		},
	},
	{
		name: "vm-entity-world-ipv4",
		config: `egress:
  - toEntities:
      - world-ipv4
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("http://target-allow:80/", "entity-world-ipv4: HTTP port 80 allowed"),
			networkDenied("https://target-allow:443/", "entity-world-ipv4: HTTPS port 443 denied"),
		},
	},
	{
		name: "vm-icmp-fqdn",
		config: `egress:
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
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
			nginxService("target-deny", defaultNginxConf),
		},
		assertions: []assertion{
			httpsPassthrough("https://target-allow:443/", "OK", "icmp-fqdn: HTTPS passthrough"),
			networkDenied("https://target-deny:443/", "icmp-fqdn: HTTPS to target-deny denied"),
		},
		rootAssertions: []assertion{
			pingAllowed("target-allow", "icmp-fqdn: ping to target-allow"),
			pingDenied("target-deny", "icmp-fqdn: ping to target-deny denied"),
		},
	},
	{
		name: "vm-header-match-mismatch",
		config: `egress:
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
		services: []serviceSpec{
			nginxService("target-l7", headerEchoNginxConf),
		},
		assertions: []assertion{
			l7BodyWithHeader(
				"https://target-l7:443/",
				"GET",
				"X-Token: secret",
				"TOKEN=secret",
				"header-mismatch: correct header passed through",
			),
			l7BodyWithHeader(
				"https://target-l7:443/",
				"GET",
				"X-Token: wrong",
				"TOKEN=secret",
				"header-mismatch: wrong header replaced with correct value",
			),
			l7Allowed(
				"https://target-l7:443/",
				"GET",
				"TOKEN=secret",
				"header-mismatch: missing header replaced with correct value",
			),
		},
	},
	{
		name: "vm-server-name-bare-wildcard",
		config: `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
        serverNames:
          - "*"
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
			nginxService("target-deny", defaultNginxConf),
		},
		assertions: []assertion{
			httpsPassthrough(
				"https://target-allow:443/",
				"OK",
				"server-name-bare-wildcard: HTTPS passthrough (no MITM)",
			),
			networkDenied("https://target-deny:443/", "server-name-bare-wildcard: HTTPS to target-deny denied"),
		},
	},
	{
		name: "vm-fqdn-wildcard-http-rbac",
		config: `egress:
  - toFQDNs:
      - matchPattern: "*.target-zone"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("one.target-zone", defaultNginxConf),
			nginxService("deep.sub.target-zone", defaultNginxConf),
			nginxService("denied.other-zone", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("http://one.target-zone:80/", "wildcard-http-rbac: single-label match allowed"),
			networkDenied("http://deep.sub.target-zone:80/", "wildcard-http-rbac: multi-label rejected by DNS"),
			networkDenied("http://denied.other-zone:80/", "wildcard-http-rbac: wrong zone denied"),
		},
	},

	// Container e2e tests: traffic originates from bridge-networked
	// containers and is intercepted via NAT PREROUTING DNAT (IPv4) or
	// TPROXY (IPv6). Target services run as containers with fixed IPs
	// on the 172.20.0.0/16 bridge subnet.
	{
		name:   "vm-container-infra-smoke",
		config: ``,
		containerServices: []serviceSpec{
			nginxService("ct-smoke", defaultNginxConf),
		},
		containerAssertions: []assertion{
			httpAllowed("http://ct-smoke:80/", "container-infra: HTTP reachable"),
			httpsPassthrough("https://ct-smoke:443/", "OK", "container-infra: HTTPS reachable"),
		},
		rootAssertions: []assertion{
			dnsForwarded("ct-smoke", "container-infra: DNS resolves"),
		},
	},
	{
		name: "vm-container-deny-all",
		config: `egress:
  - {}
`,
		containerServices: []serviceSpec{
			nginxService("ct-target", defaultNginxConf),
		},
		containerAssertions: []assertion{
			networkDenied("http://ct-target:80/", "container deny-all: HTTP denied"),
			networkDenied("https://ct-target:443/", "container deny-all: HTTPS denied"),
		},
	},
	{
		name: "vm-container-fqdn-allow",
		config: `egress:
  - toFQDNs:
      - matchName: "ct-allow"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
          - port: "443"
            protocol: TCP
`,
		containerServices: []serviceSpec{
			nginxService("ct-allow", defaultNginxConf),
			nginxService("ct-deny", defaultNginxConf),
		},
		containerAssertions: []assertion{
			httpAllowed("http://ct-allow:80/", "container fqdn-allow: HTTP to ct-allow"),
			httpAllowed("https://ct-allow:443/", "container fqdn-allow: HTTPS to ct-allow"),
			networkDenied("http://ct-deny:80/", "container fqdn-allow: HTTP to ct-deny denied"),
			networkDenied("https://ct-deny:443/", "container fqdn-allow: HTTPS to ct-deny denied"),
		},
	},
	{
		name: "vm-container-https-passthrough",
		config: `egress:
  - toFQDNs:
      - matchName: "ct-target"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		containerServices: []serviceSpec{
			nginxService("ct-target", defaultNginxConf),
		},
		containerAssertions: []assertion{
			httpsPassthrough("https://ct-target:443/", "OK", "container https-passthrough: HTTPS passthrough"),
		},
	},
	{
		name: "vm-container-l7-filtering",
		config: `egress:
  - toFQDNs:
      - matchName: "ct-l7"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
        rules:
          http:
            - method: "GET"
              path: "/allowed/.*"
`,
		containerServices: []serviceSpec{
			nginxService("ct-l7", l7NginxConf),
		},
		containerAssertions: []assertion{
			l7Allowed(
				"https://ct-l7:443/allowed/resource",
				"GET",
				"ALLOWED_PATH",
				"container l7: GET /allowed/resource",
			),
			l7Denied("https://ct-l7:443/denied/resource", "GET", "container l7: GET /denied/resource denied"),
		},
	},
	{
		name: "vm-container-mixed",
		config: `egress:
  - toFQDNs:
      - matchName: "target-allow"
      - matchName: "ct-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("https://target-allow:443/", "mixed: VM HTTPS to target-allow"),
		},
		containerServices: []serviceSpec{
			nginxService("ct-allow", defaultNginxConf),
		},
		containerAssertions: []assertion{
			httpAllowed("https://ct-allow:443/", "mixed: container HTTPS to ct-allow"),
		},
	},

	// Bridge-local DNS test: verifies that containers with DNS pointing
	// at a bridge-local address (like BuildKit/Dagger's embedded
	// resolver) still get DNS intercepted by terrarium.
	{
		name: "vm-container-bridge-local-dns",
		config: `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
		},
		verify: func(ctx context.Context, t *testing.T, d *driver) {
			t.Helper()

			// Run curl from a bridge-networked container with DNS
			// set to the CNI gateway (172.20.0.1). This is a local
			// address on the VM, simulating BuildKit's behavior.
			out, err := d.runInBridgeContainer(ctx,
				"172.20.0.1",
				"curl", "-sf", "--max-time", "10",
				"http://target-allow:80/")
			if err != nil {
				t.Errorf("bridge-local DNS: curl failed: %v\noutput: %s", err, out)
			}
		},
	},

	// Bridge-to-external test: verifies that bridge-networked container
	// traffic traversing the FORWARD chain and mangle PREROUTING TPROXY
	// path reaches the correct Envoy listener. The service runs on the
	// tproxy-test network (172.21.0.0/16, defined in configuration.nix)
	// so traffic from the default bridge (172.20.0.0/16) is L3-routed
	// through the VM kernel rather than L2 bridge-forwarded.
	{
		name: "vm-container-bridge-external",
		config: `egress:
  - toCIDR:
      - "172.21.0.0/16"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`,
		verify: func(ctx context.Context, t *testing.T, d *driver) {
			t.Helper()

			// Write a minimal nginx config for the service.
			confPath := "/tmp/bridge-svc-nginx.conf"
			conf := "error_log /dev/null;\nevents {}\nhttp {\naccess_log /dev/null;\nserver { listen 80; location / { return 200 'ok'; } }\n}\n"

			err := d.writeFile(ctx, confPath, conf)
			require.NoError(t, err)

			// Remove any stale container from a previous run.
			_, err = d.shell(ctx, "sudo", "nerdctl", "rm", "-f", "bridge-svc")
			if err != nil {
				t.Logf("removing stale bridge-svc container: %v", err)
			}

			t.Cleanup(func() {
				_, err := d.shell(ctx, "sudo", "nerdctl", "rm", "-f", "bridge-svc")
				if err != nil {
					t.Logf("cleanup: removing bridge-svc container: %v", err)
				}
			})

			// Remove stale 172.21.0.0/16 routes from interfaces
			// other than br-tproxy. Previous nerdctl network
			// operations can leave behind duplicate bridges
			// (br-<hash>, cni1, etc.) with the same subnet,
			// causing the kernel to route via a linkdown device.
			_, err = d.shell(ctx, "sudo", "ip", "route", "flush", "172.21.0.0/16", "dev", "cni1")
			if err != nil {
				t.Logf("flushing cni1 routes: %v", err)
			}

			routeOut, err := d.shell(ctx, "ip", "route", "show", "172.21.0.0/16")
			if err != nil {
				t.Logf("listing routes for 172.21.0.0/16: %v", err)
			}

			for line := range strings.SplitSeq(routeOut, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.Contains(line, "br-tproxy") {
					continue
				}

				// Extract "dev <name>" and flush that device's route.
				parts := strings.Fields(line)
				for i, p := range parts {
					if p == "dev" && i+1 < len(parts) {
						_, err = d.shell(
							ctx, "sudo", "ip", "route", "flush",
							"172.21.0.0/16", "dev", parts[i+1],
						)
						if err != nil {
							t.Logf("flushing route for dev %s: %v", parts[i+1], err)
						}
					}
				}
			}

			// Start nginx on the tproxy-test network (172.21.0.0/16,
			// defined in configuration.nix). Traffic from the default
			// bridge is L3-routed through the VM kernel and hits the
			// FORWARD chain + mangle PREROUTING TPROXY.
			_, err = d.shell(ctx, "sudo", "nerdctl", "run", "-d",
				"--name", "bridge-svc",
				"--network", "tproxy-test",
				"-v", confPath+":/etc/nginx/nginx.conf:ro",
				"terrarium-test:latest",
				"nginx", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;")
			require.NoError(t, err)

			// Get the service container's IP on the second network.
			ipOut, err := d.shell(ctx, "sudo", "nerdctl", "inspect",
				"-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "bridge-svc")
			require.NoError(t, err)

			ip := strings.TrimSpace(ipOut)
			require.NotEmpty(t, ip, "bridge-svc container has no IP")

			// Wait for nginx to be listening inside the
			// container. Using nerdctl exec bypasses all host
			// nftables chains, confirming the service is ready
			// before testing the TPROXY path.
			var readyErr error
			for range 10 {
				_, readyErr = d.shell(ctx, "sudo", "nerdctl", "exec",
					"bridge-svc", "curl", "-sf", "--max-time", "1",
					"http://127.0.0.1:80/")
				if readyErr == nil {
					break
				}

				time.Sleep(500 * time.Millisecond)
			}

			require.NoError(t, readyErr, "nginx not listening in bridge-svc")

			// Curl the service from a bridge container.
			out, err := d.runInBridgeContainer(ctx,
				"172.20.0.1",
				"curl", "-sf", "--max-time", "10",
				"http://"+net.JoinHostPort(ip, "80")+"/")
			if err != nil {
				// Collect diagnostics on failure.
				nft, nftErr := d.shell(ctx, "sudo", "nft",
					"list", "table", "inet", "terrarium")
				routes, routesErr := d.shell(ctx, "ip", "route", "show", "table", "all")
				ipRules, ipRulesErr := d.shell(ctx, "ip", "rule", "show")
				ss, ssErr := d.shell(ctx, "sudo", "ss", "-tlnp")
				ct, ctErr := d.shell(ctx, "sudo", "conntrack", "-L")
				arp, arpErr := d.shell(ctx, "ip", "neigh", "show")

				for name, derr := range map[string]error{
					"nft": nftErr, "routes": routesErr, "ip rule": ipRulesErr,
					"ss": ssErr, "conntrack": ctErr, "neigh": arpErr,
				} {
					if derr != nil {
						t.Logf("diagnostic %s: %v", name, derr)
					}
				}

				t.Errorf("bridge-external: curl failed: %v\noutput: %s"+
					"\n\nnft terrarium:\n%s"+
					"\nip route:\n%s\nip rule:\n%s\nss:\n%s"+
					"\nconntrack:\n%s\nneigh:\n%s",
					err, out, nft, routes, ipRules, ss, ct, arp)
			}
		},
	},

	// Bridge-to-external FQDN test: same cross-bridge TPROXY path as
	// vm-container-bridge-external, but with FQDN rules instead of CIDR.
	// This exercises the socket transparent re-marking path: established
	// TPROXY packets must carry tproxyMark for policy routing to deliver
	// them to Envoy. Without the socket transparent rule, established
	// packets route via the main table and are dropped in FORWARD.
	{
		name: "vm-container-bridge-external-fqdn",
		config: `egress:
  - toFQDNs:
      - matchName: "bridge-svc-fqdn"
    toPorts:
      - ports:
          - port: "80"
            protocol: TCP
`,
		verify: func(ctx context.Context, t *testing.T, d *driver) {
			t.Helper()

			confPath := "/tmp/bridge-svc-fqdn-nginx.conf"
			conf := "error_log /dev/null;\nevents {}\nhttp {\naccess_log /dev/null;\nserver { listen 80; location / { return 200 'ok'; } }\n}\n"

			err := d.writeFile(ctx, confPath, conf)
			require.NoError(t, err)

			_, err = d.shell(ctx, "sudo", "nerdctl", "rm", "-f", "bridge-svc-fqdn")
			if err != nil {
				t.Logf("removing stale bridge-svc-fqdn container: %v", err)
			}

			t.Cleanup(func() {
				_, err := d.shell(ctx, "sudo", "nerdctl", "rm", "-f", "bridge-svc-fqdn")
				if err != nil {
					t.Logf("cleanup: removing bridge-svc-fqdn container: %v", err)
				}
			})

			// Remove stale 172.21.0.0/16 routes from interfaces
			// other than br-tproxy (same cleanup as bridge-external).
			_, err = d.shell(ctx, "sudo", "ip", "route", "flush", "172.21.0.0/16", "dev", "cni1")
			if err != nil {
				t.Logf("flushing cni1 routes: %v", err)
			}

			routeOut, err := d.shell(ctx, "ip", "route", "show", "172.21.0.0/16")
			if err != nil {
				t.Logf("listing routes for 172.21.0.0/16: %v", err)
			}

			for line := range strings.SplitSeq(routeOut, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.Contains(line, "br-tproxy") {
					continue
				}

				parts := strings.Fields(line)
				for i, p := range parts {
					if p == "dev" && i+1 < len(parts) {
						_, err = d.shell(
							ctx, "sudo", "ip", "route", "flush",
							"172.21.0.0/16", "dev", parts[i+1],
						)
						if err != nil {
							t.Logf("flushing route for dev %s: %v", parts[i+1], err)
						}
					}
				}
			}

			// Start nginx on the tproxy-test network.
			_, err = d.shell(ctx, "sudo", "nerdctl", "run", "-d",
				"--name", "bridge-svc-fqdn",
				"--network", "tproxy-test",
				"-v", confPath+":/etc/nginx/nginx.conf:ro",
				"terrarium-test:latest",
				"nginx", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;")
			require.NoError(t, err)

			// Discover bridge-svc-fqdn's IP on the tproxy-test network.
			ipOut, err := d.shell(ctx, "sudo", "nerdctl", "inspect",
				"-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", "bridge-svc-fqdn")
			require.NoError(t, err)

			ip := strings.TrimSpace(ipOut)
			require.NotEmpty(t, ip, "bridge-svc-fqdn container has no IP")

			// Write dnsmasq entry so the terrarium DNS proxy can
			// resolve the FQDN to the container's cross-bridge IP.
			err = d.writeFile(ctx, "/etc/dnsmasq-hosts",
				fmt.Sprintf("%s bridge-svc-fqdn\n", ip))
			require.NoError(t, err)

			_, err = d.shell(ctx, "sudo", "systemctl", "reload", "dnsmasq")
			require.NoError(t, err, "reloading dnsmasq after adding bridge-svc-fqdn entry")

			// Wait for nginx to be listening.
			var readyErr error
			for range 10 {
				_, readyErr = d.shell(ctx, "sudo", "nerdctl", "exec",
					"bridge-svc-fqdn", "curl", "-sf", "--max-time", "1",
					"http://127.0.0.1:80/")
				if readyErr == nil {
					break
				}

				time.Sleep(500 * time.Millisecond)
			}

			require.NoError(t, readyErr, "nginx not listening in bridge-svc-fqdn")

			// Curl the service by hostname from a bridge container.
			// DNS resolves to 172.21.x.x, traffic is L3-routed
			// through TPROXY. Without the socket transparent rule,
			// the TCP handshake never completes.
			out, err := d.runInBridgeContainer(ctx,
				"172.20.0.1",
				"curl", "-sf", "--max-time", "10",
				"http://bridge-svc-fqdn:80/")
			if err != nil {
				nft, nftErr := d.shell(ctx, "sudo", "nft",
					"list", "table", "inet", "terrarium")
				routes, routesErr := d.shell(ctx, "ip", "route", "show", "table", "all")
				ipRules, ipRulesErr := d.shell(ctx, "ip", "rule", "show")
				ss, ssErr := d.shell(ctx, "sudo", "ss", "-tlnp")
				ct, ctErr := d.shell(ctx, "sudo", "conntrack", "-L")
				arp, arpErr := d.shell(ctx, "ip", "neigh", "show")

				for name, derr := range map[string]error{
					"nft": nftErr, "routes": routesErr, "ip rule": ipRulesErr,
					"ss": ssErr, "conntrack": ctErr, "neigh": arpErr,
				} {
					if derr != nil {
						t.Logf("diagnostic %s: %v", name, derr)
					}
				}

				t.Errorf("bridge-external-fqdn: curl failed: %v\noutput: %s"+
					"\n\nnft terrarium:\n%s"+
					"\nip route:\n%s\nip rule:\n%s\nss:\n%s"+
					"\nconntrack:\n%s\nneigh:\n%s",
					err, out, nft, routes, ipRules, ss, ct, arp)
			}
		},
	},

	// VM-specific tests (not in container suite).
	{
		name: "vm-multi-uid",
		config: `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
			nginxService("target-deny", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("https://target-allow:443/", "multi-uid: UID 1000 can reach target-allow"),
			networkDenied("https://target-deny:443/", "multi-uid: UID 1000 cannot reach target-deny"),
		},
		rootAssertions: []assertion{
			multiUIDDenied("http://target-deny:80/", "1000", "multi-uid: UID 1000 denied to target-deny"),
			multiUIDDenied("http://target-deny:80/", "2000", "multi-uid: UID 2000 denied to target-deny"),
		},
	},
	{
		name: "vm-guard-table",
		config: `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
		},
		setup: func(ctx context.Context, d *driver) error {
			// First start daemon and verify it works.
			err := d.restartDaemon(ctx)
			if err != nil {
				return fmt.Errorf("initial daemon start: %w", err)
			}

			// Stop daemon and flush its table to test the guard table.
			err = d.stopDaemon(ctx)
			if err != nil {
				return fmt.Errorf("stopping daemon: %w", err)
			}

			_, err = d.shell(ctx, "sudo", "nft", "delete", "table", "inet", "terrarium")
			if err != nil {
				return fmt.Errorf("flushing terrarium table: %w", err)
			}

			// Verify the guard table blocks egress while daemon is down.
			// The guard table drops all non-root, non-envoy egress.
			guardSpec := daemonSpec{
				DaemonMode:      true,
				SkipDaemonCheck: true,
				RootAssertions: []assertion{
					nftTableAbsent("terrarium", "guard-table: terrarium table absent after flush"),
					nftTableExists("terrarium-guard", "guard-table: guard table still exists"),
				},
				Assertions: []assertion{
					networkDenied("http://target-allow:80/", "guard-table: egress blocked while daemon down"),
				},
			}

			err = d.writeSpec(ctx, guardSpec)
			if err != nil {
				return fmt.Errorf("writing guard spec: %w", err)
			}

			exitCode, output, err := d.runTestrunner(ctx)
			if err != nil {
				return fmt.Errorf("running guard assertions: %w\noutput:\n%s", err, output)
			}

			fmt.Print(output)

			if exitCode != 0 {
				return fmt.Errorf("guard table assertions failed (exit %d)", exitCode)
			}

			// Now the main test restarts the daemon and verifies recovery.
			return nil
		},
		rootAssertions: []assertion{
			// After restart, the daemon recreates its table.
			nftTableExists("terrarium", "guard-table: terrarium table restored after restart"),
			nftTableExists("terrarium-guard", "guard-table: guard table persists"),
			systemctlActive("terrarium", "guard-table: daemon is active after restart"),
		},
		assertions: []assertion{
			httpAllowed("https://target-allow:443/", "guard-table: traffic flows after daemon restart"),
		},
	},
	{
		name: "vm-config-reload",
		config: `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
			nginxService("target-b", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("https://target-allow:443/", "config-reload: target-allow reachable under config A"),
			networkDenied("https://target-b:443/", "config-reload: target-b denied under config A"),
		},
		teardown: func(ctx context.Context, d *driver) error {
			// Switch to config B that allows target-b instead.
			configB := `egress:
  - toFQDNs:
      - matchName: "target-b"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`
			err := d.writeConfig(ctx, configB)
			if err != nil {
				return fmt.Errorf("writing config B: %w", err)
			}

			err = d.reloadDaemon(ctx)
			if err != nil {
				return fmt.Errorf("reloading daemon with config B: %w", err)
			}

			// Write spec for config B assertions.
			specB := daemonSpec{
				DaemonMode: true,
				Assertions: []assertion{
					httpAllowed("https://target-b:443/", "config-reload: target-b reachable under config B"),
					networkDenied("https://target-allow:443/", "config-reload: target-allow denied under config B"),
				},
			}

			err = d.writeSpec(ctx, specB)
			if err != nil {
				return fmt.Errorf("writing spec B: %w", err)
			}

			exitCode, output, err := d.runTestrunner(ctx)
			if err != nil {
				return fmt.Errorf("running testrunner for config B: %w\noutput:\n%s", err, output)
			}

			fmt.Print(output)

			if exitCode != 0 {
				return fmt.Errorf("config B assertions failed (exit %d)", exitCode)
			}

			return nil
		},
	},
}
