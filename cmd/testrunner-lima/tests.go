package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.jacobcolvin.com/terrarium/eventstore"
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

func jailProfileAttached(profile, desc string) assertion {
	return assertion{Type: "jail_profile_attached", Expected: profile, Desc: desc}
}

func jailPathDenied(path, op, desc string) assertion {
	return assertion{Type: "jail_path_denied", File: path, Op: op, Desc: desc}
}

func jailSignalDenied(cmd, desc string) assertion {
	return assertion{Type: "jail_signal_denied", Cmd: cmd, Desc: desc}
}

func jailNftDenied(args []string, desc string) assertion {
	return assertion{Type: "jail_nft_denied", Args: args, Desc: desc}
}

func jailExecDenied(cmd, desc string) assertion {
	return assertion{Type: "jail_exec_denied", Cmd: cmd, Desc: desc}
}

func jailExecAllowed(cmd, desc string) assertion {
	return assertion{Type: "jail_exec_allowed", Cmd: cmd, Desc: desc}
}

func jailSelfProcReadAllowed(desc string) assertion {
	return assertion{Type: "jail_self_proc_read_allowed", Desc: desc}
}

func jailRefusesNesting(desc string) assertion {
	return assertion{Type: "jail_refuses_nesting", Desc: desc}
}

func apparmorProfileParses(path, desc string) assertion {
	return assertion{Type: "apparmor_profile_parses", File: path, Desc: desc}
}

func lockdownIntegrityMode(desc string) assertion {
	return assertion{Type: "lockdown_integrity_mode", Desc: desc}
}

func lockdownModprobeDenied(desc string) assertion {
	return assertion{Type: "lockdown_modprobe_denied", Desc: desc}
}

func lockdownDevmemDenied(desc string) assertion {
	return assertion{Type: "lockdown_devmem_denied", Desc: desc}
}

func initSubcommandRegistered(desc string) assertion {
	return assertion{Type: "init_subcommand_registered", Desc: desc}
}

// profilePath is the deterministic location of the terrarium.workload
// profile source file inside the VM, populated via
// [environment.etc] in configuration.nix.
const profilePath = "/etc/terrarium/terrarium-workload.profile"

// denyAllConfig is the deny-all egress policy (an empty rule) shared by
// the test cases that assert all egress is blocked.
const denyAllConfig = `egress:
  - {}
`

// fqdnPort443Config restricts egress to target-allow on TCP/443 and is
// shared by the test cases that assert FQDN + port filtering.
const fqdnPort443Config = `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`

// vmTests defines all Lima VM e2e test cases run by the
// testrunner-lima command. Tests cover deny-all, FQDN exact/wildcard,
// CIDR, L7 HTTP filtering, port ranges, UDP, ICMP, egress deny rules,
// guard table behavior, config reload, and container-originated traffic.
var vmTests = []vmTest{
	{
		name:   "vm-deny-all",
		config: denyAllConfig,
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
		name:   "vm-fqdn-port-restrict",
		config: fqdnPort443Config,
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
		config: `stats:
  enabled: true
logging:
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
		name:   "vm-dns-proxy-filtering",
		config: fqdnPort443Config,
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
		name:   "vm-envoy-uid",
		config: fqdnPort443Config,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
		},
		rootAssertions: []assertion{
			envoyUID("1001", "envoy-uid: Envoy process running as UID 1001"),
		},
	},
	{
		name:   "vm-loopback-deny-all",
		config: denyAllConfig,
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
		config: `stats:
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
		name:   "vm-udp-deny-all",
		config: denyAllConfig,
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
		config: `stats:
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
		name:   "vm-container-deny-all",
		config: denyAllConfig,
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
		name:   "vm-multi-uid",
		config: fqdnPort443Config,
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
		name:   "vm-guard-table",
		config: fqdnPort443Config,
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
		name:   "vm-config-reload",
		config: fqdnPort443Config,
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

	// --- AppArmor / lockdown confinement tests for `terrarium jail`.
	// The assertions below mirror the threat model the profile
	// defends: terrarium state writes, CA key reads, process memory
	// introspection, signal/kill of the terrarium daemon, nftables
	// mutation, kernel module loads, and systemd/nixos rebuild paths.
	{
		name:   "vm-jail-profile-parses",
		config: ``,
		rootAssertions: []assertion{
			apparmorProfileParses(profilePath,
				"jail-profile-parses: apparmor_parser -Q -r accepts profile"),
		},
	},
	{
		name:   "vm-jail-lockdown-active",
		config: ``,
		rootAssertions: []assertion{
			lockdownIntegrityMode("jail-lockdown: kernel lockdown=integrity"),
			lockdownModprobeDenied("jail-lockdown: modprobe dummy denied by lockdown"),
			lockdownDevmemDenied("jail-lockdown: reading /dev/mem denied by lockdown"),
		},
	},
	{
		name:   "vm-jail-profile-loaded",
		config: ``,
		rootAssertions: []assertion{
			jailProfileAttached("terrarium.workload",
				"jail-profile-loaded: jailed process runs under terrarium.workload"),
		},
	},
	{
		name:   "vm-jail-confinement",
		config: ``,
		setup: func(ctx context.Context, d *driver) error {
			// Pre-create /etc/shadow- and /etc/security/opasswd so the
			// deny-read assertions see EACCES from AppArmor rather than
			// ENOENT. Without this, a regression that loosens the rule
			// from `shadow*` to `shadow` (or drops the opasswd deny
			// entirely) would still pass because cat exits nonzero on a
			// missing file.
			_, err := d.shell(ctx, "sudo", "sh", "-c",
				"mkdir -p /etc/security && touch /etc/shadow- /etc/security/opasswd")
			if err != nil {
				return fmt.Errorf("pre-creating shadow-/opasswd: %w", err)
			}

			return nil
		},
		teardown: func(ctx context.Context, d *driver) error {
			_, err := d.shell(ctx, "sudo", "rm", "-f",
				"/etc/shadow-", "/etc/security/opasswd")
			if err != nil {
				return fmt.Errorf("removing shadow-/opasswd: %w", err)
			}

			return nil
		},
		rootAssertions: []assertion{
			// Writes to terrarium state + config + apparmor controls.
			jailPathDenied("/var/lib/terrarium/config.yaml", "write",
				"jail-confinement: write /var/lib/terrarium/config.yaml denied"),
			jailPathDenied("/etc/nixos/configuration.nix", "write",
				"jail-confinement: write /etc/nixos/configuration.nix denied"),
			jailPathDenied("/sys/kernel/security/apparmor/.remove", "write",
				"jail-confinement: write apparmor .remove denied"),
			// Reads of sensitive material / process introspection.
			jailPathDenied("/var/lib/terrarium/ca/ca.key", "read",
				"jail-confinement: read CA key denied"),
			jailPathDenied("/proc/mainpid:terrarium/environ", "read",
				"jail-confinement: read terrarium environ denied"),
			jailPathDenied("/proc/mainpid:terrarium/mem", "read",
				"jail-confinement: read terrarium mem denied"),
			// Password-hash files. AppArmor /** r bypasses file-mode
			// protection, so an explicit deny is the only backstop.
			jailPathDenied("/etc/shadow", "read",
				"jail-confinement: read /etc/shadow denied"),
			jailPathDenied("/etc/gshadow", "read",
				"jail-confinement: read /etc/gshadow denied"),
			jailPathDenied("/etc/security/opasswd", "read",
				"jail-confinement: read /etc/security/opasswd denied"),
			jailPathDenied("/etc/shadow-", "read",
				"jail-confinement: read /etc/shadow- (glob sibling) denied"),
			// Signals to the terrarium daemon.
			jailSignalDenied("kill -9 mainpid:terrarium",
				"jail-confinement: SIGKILL to terrarium denied"),
			// nftables mutation. Protected by CAP_NET_ADMIN omission,
			// not by a netlink deny -- these assertions guard against
			// the cap allow-list regressing.
			jailNftDenied([]string{"list", "tables"},
				"jail-confinement: nft list tables denied"),
			jailNftDenied([]string{"flush", "table", "inet", "terrarium"},
				"jail-confinement: nft flush terrarium denied"),
			// Rebuild / kernel / systemd escape hatches.
			jailExecDenied("nixos-rebuild switch",
				"jail-confinement: nixos-rebuild denied"),
			jailExecDenied("modprobe dummy",
				"jail-confinement: modprobe denied"),
			jailExecDenied("cat /dev/mem",
				"jail-confinement: cat /dev/mem denied"),
			jailExecDenied("systemctl stop terrarium",
				"jail-confinement: systemctl stop terrarium denied"),
			jailExecDenied("systemd-run --user true",
				"jail-confinement: systemd-run --user denied"),
			// Deny pairs for the newly-granted sys_ptrace/syslog/perfmon
			// caps. Each sysctl write is the escalation the cap
			// complement defends against (lowering ptrace_scope,
			// dmesg_restrict, or perf_event_paranoid to widen access
			// for unconfined neighbors).
			jailExecDenied("echo 1 > /proc/sys/kernel/perf_event_paranoid",
				"jail-confinement: write perf_event_paranoid denied"),
			jailExecDenied("echo 1 > /proc/sys/kernel/dmesg_restrict",
				"jail-confinement: write dmesg_restrict denied"),
			jailExecDenied("echo 0 > /proc/sys/kernel/yama/ptrace_scope",
				"jail-confinement: write yama/ptrace_scope denied"),
			// Cross-profile ptrace must still be denied. The peer
			// rule in the profile (not the cap grant) is the
			// boundary; strace against the daemon's PID must die at
			// attach. jailExecDenied passes when the script exits
			// nonzero, so the script exits 0 only on regression
			// (strace stayed alive attached to the daemon).
			jailExecDenied(
				`strace -p mainpid:terrarium -e trace=read -o /dev/null >/dev/null 2>&1 &
sp=$!
sleep 1
if [ -d "/proc/$sp" ] && ! grep -q '^State:[[:space:]]*Z' "/proc/$sp/status" 2>/dev/null; then
  kill -9 "$sp" 2>/dev/null
  wait 2>/dev/null
  exit 0
fi
wait 2>/dev/null
exit 1`,
				"jail-confinement: cross-profile ptrace of terrarium daemon denied"),
			// Positive regression guards. If a future edit over-reaches
			// (e.g., re-adds `deny /proc/[0-9]*/fd/** r` or a netlink
			// read deny), these fail and force a deliberate revisit.
			jailSelfProcReadAllowed(
				"jail-confinement: readlink /proc/self/fd/0 allowed"),
			jailExecAllowed("ip -4 route show",
				"jail-confinement: ip -4 route show allowed (netlink read)"),
			// Pos guards for sys_ptrace/syslog/perfmon caps. Pinned
			// sysctls (configuration.nix) ensure these only pass when
			// the cap is actually granted.
			//
			// sys_ptrace: strace attaches to a sibling non-descendant
			// sleep. Under ptrace_scope=1 PTRACE_ATTACH to a
			// non-ancestor requires CAP_SYS_PTRACE. A live strace is
			// State: S (sleeping for tracee events); a dead/EPERM'd
			// strace is Z or gone -- reading status avoids the kill -0
			// zombie race.
			jailExecAllowed(
				`sleep 30 >/dev/null 2>&1 &
tp=$!
strace -p "$tp" -e trace=clock_nanosleep -o /dev/null >/dev/null 2>&1 &
sp=$!
sleep 1
state=$(awk '/^State:/ {print $2; exit}' "/proc/$sp/status" 2>/dev/null || echo Z)
kill -9 "$sp" "$tp" 2>/dev/null
wait 2>/dev/null
case "$state" in S|R|D|t) exit 0 ;; *) exit 1 ;; esac`,
				"jail-confinement: strace attach to sibling allowed (sys_ptrace)"),
			// syslog: dmesg -c issues SYSLOG_ACTION_READ_ALL +
			// SYSLOG_ACTION_CLEAR; CLEAR is cap-gated regardless of
			// dmesg_restrict.
			jailExecAllowed("dmesg -c >/dev/null 2>&1",
				"jail-confinement: dmesg -c allowed (syslog)"),
			// perfmon: perf_event_paranoid=2 blocks kernel/CPU events
			// for unprivileged callers; CAP_PERFMON restores userspace
			// event access. PATH-resolved `true` (NixOS does not
			// guarantee /bin/true).
			jailExecAllowed("perf stat -e cycles -- true >/dev/null 2>&1",
				"jail-confinement: perf stat -e cycles allowed (perfmon)"),
		},
	},
	{
		// Hard gate #5: parent->child SIGTERM inside the jail must
		// succeed, and the kernel audit log must not record any
		// apparmor DENIED signal events tied to the workload profile
		// (namespaced or bare). If this ever fails, fix the peer
		// qualifier in lima/terrarium-workload.profile -- do not
		// relax the test.
		name:   "vm-jail-same-profile-signals",
		config: ``,
		verify: func(ctx context.Context, t *testing.T, d *driver) {
			t.Helper()

			// Capture a journal cursor so the grep sees only the
			// audit records this subtest produced.
			cursorOut, err := d.shell(ctx, "sudo", "journalctl", "-k", "-n", "1",
				"--show-cursor", "--no-pager")
			require.NoError(t, err, "capturing journal cursor")

			var cursor string

			for line := range strings.SplitSeq(cursorOut, "\n") {
				if _, after, ok := strings.Cut(line, "cursor: "); ok {
					cursor = strings.TrimSpace(after)
				}
			}

			require.NotEmpty(t, cursor, "journal cursor not found in output")

			// Parent->child SIGTERM inside the jail. Child sleeps 2s
			// in a shell that traps TERM and exits 0. Parent sends
			// TERM after 200ms. Both must exit 0.
			script := `set -e
(trap 'exit 0' TERM; sleep 2) & child=$!
(sleep 0.2; kill -TERM "$child") &
wait "$child"`

			out, err := d.shell(ctx, "sudo", "terrarium", "jail", "--",
				"sh", "-c", script)
			require.NoError(t, err, "parent->child SIGTERM failed: %s", out)

			// Run a noop Go binary (/bin/true via jail) for ~2s to
			// give the kernel time to emit any audit events.
			_, err = d.shell(ctx, "sudo", "terrarium", "jail", "--",
				"sh", "-c", "sleep 2 & wait")
			require.NoError(t, err)

			auditOut, err := d.shell(ctx, "sudo", "journalctl", "-k",
				"--after-cursor="+cursor, "--no-pager")
			require.NoError(t, err, "reading journal after cursor")

			re := regexp.MustCompile(`DENIED.*signal.*profile="(:root://)?terrarium\.workload"`)
			if re.MatchString(auditOut) {
				t.Errorf("jail-same-profile-signals: audit log shows DENIED signal for terrarium.workload peer\n%s",
					auditOut)
			}
		},
	},
	{
		name:   "vm-jail-fail-closed",
		config: ``,
		rootAssertions: []assertion{
			jailRefusesNesting("jail-fail-closed: nested jail refused with ErrAlreadyConfined"),
		},
	},
	{
		name:   "vm-jail-fail-closed-missing-profile",
		config: ``,
		setup: func(ctx context.Context, d *driver) error {
			// Unload the terrarium.workload profile to force the
			// missing-profile error path. Teardown restores it.
			_, err := d.shell(ctx, "sudo", "sh", "-c",
				`echo -n 'terrarium.workload' > /sys/kernel/security/apparmor/.remove`)
			if err != nil {
				return fmt.Errorf("removing profile: %w", err)
			}

			return nil
		},
		teardown: func(ctx context.Context, d *driver) error {
			// apparmor reloads the full policy set from disk on
			// restart, restoring the profile.
			_, err := d.shell(ctx, "sudo", "systemctl", "restart", "apparmor")
			if err != nil {
				return fmt.Errorf("restarting apparmor: %w", err)
			}

			return nil
		},
		verify: func(ctx context.Context, t *testing.T, d *driver) {
			t.Helper()

			out, err := d.shell(ctx, "sudo", "terrarium", "jail", "--", "/bin/true")
			if err == nil {
				t.Errorf("jail-missing-profile: expected nonzero exit, got success: %s", out)

				return
			}

			if !strings.Contains(out, "profile not loaded") {
				t.Errorf("jail-missing-profile: expected 'profile not loaded' in stderr, got:\n%s", out)
			}
		},
	},
	{
		name:   "vm-jail-admin-paths-unaffected",
		config: ``,
		rootAssertions: []assertion{
			initSubcommandRegistered(
				"jail-admin-paths: terrarium init --help still registered (jail dispatch did not swallow init)"),
		},
	},

	// vm-daemon-reload-cli exercises the `terrarium daemon reload`
	// CLI's pre-validation and SIGHUP plumbing. Companion to
	// vm-config-reload, which goes through systemctl reload and
	// bypasses the CLI's pre-validation.
	{
		name:   "vm-daemon-reload-cli",
		config: fqdnPort443Config,
		services: []serviceSpec{
			nginxService("target-allow", defaultNginxConf),
			nginxService("target-b", defaultNginxConf),
		},
		assertions: []assertion{
			httpAllowed("https://target-allow:443/",
				"daemon-reload-cli: target-allow reachable under config A"),
			networkDenied("https://target-b:443/",
				"daemon-reload-cli: target-b denied under config A"),
		},
		teardown: runDaemonReloadCliTeardown,
	},

	// vm-stats-firewall-events proves the kernel-side nflog binding
	// actually works in VM mode (where openNflog is fatal on bind
	// failure). Generates HTTP traffic and asserts a
	// firewall-source allow row with a non-empty domain field.
	{
		name: "vm-stats-firewall-events",
		config: `stats:
  enabled: true
logging:
  firewall:
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
		},
		assertions: []assertion{
			httpAllowed("https://target-allow:443/",
				"stats-firewall-events: HTTPS to target-allow allowed"),
		},
		verify: verifyVMStatsFirewallEvents,
	},

	// vm-status-stats-section asserts `terrarium status --no-logs`
	// renders the STATS section after traffic, with a non-zero
	// 24-hour event count and a parseable last-event timestamp.
	{
		name: "vm-status-stats-section",
		config: `stats:
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
		},
		assertions: []assertion{
			httpAllowed("https://target-allow:443/",
				"status-stats: HTTPS to target-allow allowed"),
		},
		verify: verifyVMStatusStatsSection,
	},

	// vm-heartbeat-on-shutdown exercises the eventstore shutdown
	// drain. The heartbeat goroutine's final snapshot is pushed
	// onto the buffer-1 channel during cancel; the writer
	// goroutine drains heartbeats before closing s.done. By the
	// time `systemctl stop terrarium` returns the row must exist
	// in the DB.
	{
		name: "vm-heartbeat-on-shutdown",
		config: `stats:
  enabled: true
logging:
  firewall:
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
		},
		assertions: []assertion{
			httpAllowed("https://target-allow:443/",
				"heartbeat-shutdown: HTTPS to target-allow allowed"),
		},
		verify: verifyVMHeartbeatOnShutdown,
	},
}

// runDaemonReloadCliTeardown drives the daemon-reload-CLI sub-cases
// sequentially: invalid YAML rejected by pre-validation, dead PID
// rejected by the liveness probe, then valid config B succeeds.
// Each sub-case is a distinct rejection path inside [DaemonReload]
// (cmd/terrarium/reload.go); a single test exercises all three to
// avoid additional VM boots.
func runDaemonReloadCliTeardown(ctx context.Context, d *driver) error {
	configA := `egress:
  - toFQDNs:
      - matchName: "target-allow"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`

	// Bad YAML must be rejected by pre-validation; config A stays
	// in effect because the CLI never sent SIGHUP. Restore config
	// A on disk before continuing.
	err := d.writeConfig(ctx, "egress: { this is not valid yaml")
	if err != nil {
		return fmt.Errorf("writing invalid config: %w", err)
	}

	exitCode, stdout, stderr, err := d.reloadDaemonViaCli(ctx)
	if err != nil {
		return fmt.Errorf("running daemon reload (invalid yaml): %w", err)
	}

	if exitCode == 0 {
		return fmt.Errorf("daemon-reload-cli: expected nonzero exit for invalid YAML, got 0\nstdout:\n%s\nstderr:\n%s",
			stdout, stderr)
	}

	// Pre-validation must surface as a YAML parse error, not as
	// "config not found". The latter would mean the CLI read the
	// wrong path (sudo HOME stripping) and the test never
	// exercised pre-validation.
	if !strings.Contains(stderr, "parsing config") && !strings.Contains(stdout, "parsing config") {
		return fmt.Errorf("daemon-reload-cli: expected 'parsing config' in output, got:\nstdout:\n%s\nstderr:\n%s",
			stdout, stderr)
	}

	// Restore config A on disk for hygiene before the next
	// sub-case. The daemon is still running with config A in
	// memory because pre-validation never sent SIGHUP, so this
	// writeConfig is a file-only operation -- not a load step.
	err = d.writeConfig(ctx, configA)
	if err != nil {
		return fmt.Errorf("restoring config A: %w", err)
	}

	err = runDaemonReloadCliConfigACheck(ctx, d)
	if err != nil {
		return fmt.Errorf("after invalid YAML rejection: %w", err)
	}

	// PID file points at a dead process. Save the real PID file
	// aside, swap in an unused PID, run the CLI, expect the
	// ErrDaemonNotRunning sentinel. Restore the real PID file
	// before the next sub-case.
	const pidFile = "/run/terrarium/terrarium.pid"

	const pidBackup = "/tmp/terrarium-real.pid"

	_, err = d.shell(ctx, "sudo", "cp", pidFile, pidBackup)
	if err != nil {
		return fmt.Errorf("backing up PID file: %w", err)
	}

	// Best-effort cleanup of the staged backup so a crashed run
	// doesn't leave an orphaned file at a stable path.
	defer func() {
		_, rmErr := d.shell(ctx, "sudo", "rm", "-f", pidBackup)
		if rmErr != nil {
			slog.DebugContext(ctx, "removing pid backup",
				slog.String("error", rmErr.Error()))
		}
	}()

	deadPID, err := unusedVMPID(ctx, d)
	if err != nil {
		return fmt.Errorf("finding unused PID: %w", err)
	}

	err = d.writeFile(ctx, pidFile, deadPID+"\n")
	if err != nil {
		return fmt.Errorf("overwriting PID file: %w", err)
	}

	exitCode, stdout, stderr, err = d.reloadDaemonViaCli(ctx)
	if err != nil {
		return fmt.Errorf("running daemon reload (dead PID): %w", err)
	}

	if exitCode == 0 {
		return fmt.Errorf("daemon-reload-cli: expected nonzero exit for dead PID, got 0\nstdout:\n%s\nstderr:\n%s",
			stdout, stderr)
	}

	combined := stdout + stderr
	if !strings.Contains(combined, "daemon not running") {
		return fmt.Errorf("daemon-reload-cli: expected 'daemon not running', got:\nstdout:\n%s\nstderr:\n%s",
			stdout, stderr)
	}

	_, err = d.shell(ctx, "sudo", "cp", pidBackup, pidFile)
	if err != nil {
		return fmt.Errorf("restoring PID file: %w", err)
	}

	// Valid config B replaces config A; reload must succeed and
	// the config-B assertions must pass.
	configB := `egress:
  - toFQDNs:
      - matchName: "target-b"
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
`

	err = d.writeConfig(ctx, configB)
	if err != nil {
		return fmt.Errorf("writing config B: %w", err)
	}

	exitCode, stdout, stderr, err = d.reloadDaemonViaCli(ctx)
	if err != nil {
		return fmt.Errorf("running daemon reload (config B): %w", err)
	}

	if exitCode != 0 {
		return fmt.Errorf("daemon-reload-cli: expected exit 0 for config B, got %d\nstdout:\n%s\nstderr:\n%s",
			exitCode, stdout, stderr)
	}

	// Restart nscd to clear stale DNS failures from config A.
	_, nscdErr := d.shell(ctx, "sudo", "systemctl", "restart", "nscd")
	if nscdErr != nil {
		slog.DebugContext(ctx, "restarting nscd", slog.String("error", nscdErr.Error()))
	}

	specB := daemonSpec{
		DaemonMode: true,
		Assertions: []assertion{
			httpAllowed("https://target-b:443/",
				"daemon-reload-cli: target-b reachable under config B"),
			networkDenied("https://target-allow:443/",
				"daemon-reload-cli: target-allow denied under config B"),
		},
	}

	err = d.writeSpec(ctx, specB)
	if err != nil {
		return fmt.Errorf("writing config B spec: %w", err)
	}

	exitCode, output, err := d.runTestrunner(ctx)
	if err != nil {
		return fmt.Errorf("running config B testrunner: %w\noutput:\n%s", err, output)
	}

	fmt.Print(output)

	if exitCode != 0 {
		return fmt.Errorf("config B assertions failed (exit %d)", exitCode)
	}

	return nil
}

// unusedVMPID returns a PID-shaped string guaranteed not to map to a
// live process inside the VM. Reads /proc/sys/kernel/pid_max and
// returns its value: by definition the kernel never allocates a PID
// at or above pid_max, so kill(0) on it returns ESRCH every time.
// This avoids the small-but-real risk that a hardcoded large PID
// (e.g. 999999) collides with a live process on a busy system.
func unusedVMPID(ctx context.Context, d *driver) (string, error) {
	out, err := d.shell(ctx, "cat", "/proc/sys/kernel/pid_max")
	if err != nil {
		return "", fmt.Errorf("reading pid_max: %w", err)
	}

	v := strings.TrimSpace(out)
	if v == "" {
		return "", fmt.Errorf("pid_max returned empty")
	}

	return v, nil
}

// runDaemonReloadCliConfigACheck re-runs the config-A assertions
// (target-allow allowed, target-b denied) inside the testrunner.
// Used to confirm that pre-validation prevented a bad config from
// reaching the daemon.
func runDaemonReloadCliConfigACheck(ctx context.Context, d *driver) error {
	specA := daemonSpec{
		DaemonMode: true,
		Assertions: []assertion{
			httpAllowed("https://target-allow:443/",
				"daemon-reload-cli: target-allow still reachable after invalid-yaml rejection"),
			networkDenied("https://target-b:443/",
				"daemon-reload-cli: target-b still denied after invalid-yaml rejection"),
		},
	}

	err := d.writeSpec(ctx, specA)
	if err != nil {
		return fmt.Errorf("writing config A re-check spec: %w", err)
	}

	exitCode, output, err := d.runTestrunner(ctx)
	if err != nil {
		return fmt.Errorf("running config A re-check: %w\noutput:\n%s", err, output)
	}

	fmt.Print(output)

	if exitCode != 0 {
		return fmt.Errorf("config A re-check failed (exit %d)", exitCode)
	}

	return nil
}

// verifyVMStatsFirewallEvents queries `terrarium stats list --source
// firewall` and asserts at least one row carries decision=allow with
// a non-empty domain field, then confirms the daemon is still
// active. This proves the kernel-side nflog binding worked
// end-to-end -- in VM mode openNflog (cmd/terrarium/init.go) is
// fatal on bind failure, so a working bind plus a
// dnscache-attributed row is the integration signal that unit tests
// cannot produce.
func verifyVMStatsFirewallEvents(ctx context.Context, t *testing.T, d *driver) {
	t.Helper()

	exitCode, stdout, stderr, err := d.runTerrarium(ctx,
		"stats", "list",
		"--db", VMTerrariumStatsDB,
		"--source", "firewall",
		"--format", "json",
		"--limit", "200",
	)
	require.NoError(t, err, "running terrarium stats list")
	require.Equal(t, 0, exitCode, "stats list exit code\nstdout:\n%s\nstderr:\n%s", stdout, stderr)

	type row struct {
		Decision string `json:"decision"`
		Domain   string `json:"domain"`
	}

	var rows []row

	err = json.Unmarshal([]byte(stdout), &rows)
	require.NoError(t, err, "decoding stats list\nstdout:\n%s\nstderr:\n%s", stdout, stderr)

	found := false

	for _, r := range rows {
		if r.Decision == "allow" && r.Domain != "" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("stats-firewall-events: no firewall row with decision=allow and non-empty domain\noutput:\n%s",
			stdout)
	}

	active, err := d.shell(ctx, "systemctl", "is-active", "terrarium")
	require.NoError(t, err, "checking systemctl is-active: %s", active)
	require.Equal(t, "active", strings.TrimSpace(active),
		"stats-firewall-events: daemon must still be active after nflog ingest")
}

// verifyVMStatusStatsSection asserts `terrarium status --no-logs`
// exits 0 and prints a STATS section that mentions the resolved DB
// path, a last-event line, and the events-24h counter. Uses a regex
// on the count line because [status.NewTabwriter] expands tabs to a
// variable number of padding spaces.
//
// The empty-DB render path (events 24h: 0, last event: (none)) is
// covered by status/stats_test.go and status/render_test.go at the
// unit level. Reproducing it as a black-box VM check would require
// stopping the daemon, blowing away stats.db, restarting, and
// invoking status before any DNS or testrunner traffic landed --
// which is fragile because the daemon emits a startup heartbeat row
// and DNS resolution for the test services hits the proxy
// immediately.
func verifyVMStatusStatsSection(ctx context.Context, t *testing.T, d *driver) {
	t.Helper()

	exitCode, stdout, stderr, err := d.runTerrarium(ctx, "status", "--no-logs")
	require.NoError(t, err, "running terrarium status")
	require.Equal(t, 0, exitCode, "status --no-logs exit code\nstdout:\n%s\nstderr:\n%s",
		stdout, stderr)

	for _, want := range []string{
		"STATS",
		VMTerrariumStatsDB,
		"last event:",
		"events 24h:",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("status-stats-section: missing %q in stdout:\n%s", want, stdout)
		}
	}

	// Match `events 24h:` followed by any whitespace and a count,
	// then ensure the count is non-zero.
	re := regexp.MustCompile(`events 24h:\s+(\d+)`)

	matches := re.FindStringSubmatch(stdout)
	if len(matches) < 2 {
		t.Errorf("status-stats-section: could not parse events 24h count\nstdout:\n%s", stdout)

		return
	}

	if matches[1] == "0" {
		t.Errorf("status-stats-section: events 24h count is zero after generating traffic\nstdout:\n%s",
			stdout)
	}
}

// verifyVMHeartbeatOnShutdown stops the daemon, copies stats.db to
// the host, and reads the most recent instance_metrics row through
// [eventstore.LatestHeartbeat]. Asserts the writer drained the final
// snapshot before Close returned (eventstore_last_write_unix > 0,
// recorded_at > 0).
//
// Going through the eventstore API rather than raw sqlite3 keeps the
// test decoupled from the schema column names and avoids requiring
// sqlite3 in the lima VM image. SQLite checkpoints the WAL on the
// final connection close, so by the time `systemctl stop terrarium`
// returns the main DB file is complete and a copy of just the .db
// file is sufficient.
func verifyVMHeartbeatOnShutdown(ctx context.Context, t *testing.T, d *driver) {
	t.Helper()

	// Stop the daemon so the heartbeat goroutine's cancel path
	// runs and the writer drains heartbeats before closing.
	err := d.stopDaemon(ctx)
	require.NoError(t, err, "stopping daemon")

	// Copy the DB out of the VM. With the daemon stopped, SQLite
	// has checkpointed the WAL into the main DB file, so the .db
	// alone is a complete snapshot.
	hbHostPath := copyStatsDBFromVM(ctx, t, d)
	defer func() {
		err := os.RemoveAll(filepath.Dir(hbHostPath))
		if err != nil {
			t.Logf("removing temp dir: %v", err)
		}
	}()

	db, err := eventstore.OpenReadOnly(ctx, hbHostPath)
	require.NoError(t, err, "opening stats db read-only")

	defer func() {
		closeErr := db.Close()
		if closeErr != nil {
			t.Logf("closing db: %v", closeErr)
		}
	}()

	instanceID, _, err := eventstore.LatestInstanceID(ctx, db)
	require.NoError(t, err, "resolving instance id")
	require.NotEmpty(t, instanceID, "no instance row written; daemon never reached steady state")

	hb, ok, err := eventstore.LatestHeartbeat(ctx, db, instanceID)
	require.NoError(t, err, "reading latest heartbeat")
	require.True(t, ok, "no heartbeat row for instance %s after shutdown", instanceID)

	if hb.RecordedAt.IsZero() {
		t.Errorf("heartbeat-on-shutdown: recorded_at is zero")
	}

	if hb.EventStoreLastWrite.IsZero() {
		t.Errorf("heartbeat-on-shutdown: eventstore_last_write is zero (writer did not drain)")
	}

	// With stats.firewall enabled and traffic generated, nflog
	// must have observed at least one event before shutdown.
	if hb.NFLogLastEvent.IsZero() {
		t.Errorf("heartbeat-on-shutdown: nflog_last_event is zero (firewall ingestion did not run)")
	}

	// dnscache_size is INTEGER NOT NULL DEFAULT 0; the meaningful
	// guard is that LatestHeartbeat returned a row at all
	// (already covered by require.True above).
	//
	// No need to restart the daemon here: runVMTest invokes
	// restartDaemon at the start of each test, and the post-suite
	// cleanup hook in lima_test.go covers the suite-end case.
}

// copyStatsDBFromVM copies /var/lib/terrarium/stats.db from the VM
// into a freshly-created host temp directory and returns the host
// path. The caller owns removing the parent directory.
func copyStatsDBFromVM(ctx context.Context, t *testing.T, d *driver) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "terrarium-stats-*")
	require.NoError(t, err, "creating temp dir")

	// Stage a world-readable copy on the VM so limactl cp can
	// pull it without sudo.
	stage := "/tmp/stats-snapshot.db"

	_, err = d.shell(ctx, "sudo", "cp", VMTerrariumStatsDB, stage)
	require.NoError(t, err, "staging stats db copy")

	_, err = d.shell(ctx, "sudo", "chmod", "644", stage)
	require.NoError(t, err, "chmod staged db")

	hostPath := filepath.Join(dir, "stats.db")

	cmd := exec.CommandContext(ctx, "limactl", "cp", //nolint:gosec // args controlled by test code.
		fmt.Sprintf("%s:%s", d.vmName, stage), hostPath)

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "limactl cp stats.db: %s", string(out))

	// Best-effort remove the staged file; not fatal if cleanup
	// fails because subsequent tests run restartDaemon which
	// truncates the DB anyway.
	_, rmErr := d.shell(ctx, "sudo", "rm", "-f", stage)
	if rmErr != nil {
		t.Logf("removing staged stats db: %v", rmErr)
	}

	return hostPath
}
