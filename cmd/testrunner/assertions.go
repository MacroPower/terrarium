package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	statusPass     = "PASS"
	statusFail     = "FAIL"
	retryAttempts  = 3
	retryBackoff   = 2 * time.Second
	dialTimeout    = 5 * time.Second
	udpDenyTimeout = 3 * time.Second
)

// debugMode enables per-assertion diagnostic dumps on failure. Set from
// [spec.Debug] at process startup. Package-level because the testrunner
// is a single-shot CLI binary, not a library.
var debugMode bool

// dumpDebugInfo execs diagnostic commands and prints their output to
// stdout (captured by the driver). Commands requiring privileges use
// sudo since assertions run as UID 1000.
func dumpDebugInfo(ctx context.Context) {
	fmt.Println("  --- debug dump ---")

	cmds := []struct {
		label string
		args  []string
	}{
		{"nft list ruleset", []string{"sudo", "nft", "list", "ruleset"}},
		{"conntrack -L", []string{"sudo", "conntrack", "-L"}},
		{"resolv.conf", []string{"cat", "/etc/resolv.conf"}},
		{"ss -tlnp", []string{"ss", "-tlnp"}},
	}

	for _, c := range cmds {
		//nolint:gosec // diagnostic commands
		out, err := exec.CommandContext(ctx, c.args[0], c.args[1:]...).CombinedOutput()
		if err != nil {
			fmt.Printf("  [%s] error: %v\n", c.label, err)
		} else {
			fmt.Printf("  [%s]\n%s\n", c.label, strings.TrimSpace(string(out)))
		}
	}

	fmt.Println("  --- end debug dump ---")
}

// maybeDebugDump calls [dumpDebugInfo] if debug mode is enabled.
func maybeDebugDump(ctx context.Context) {
	if debugMode {
		dumpDebugInfo(ctx)
	}
}

// runAssertion dispatches a single [assertion] to the appropriate
// implementation based on [assertion.Type] and returns the [result].
func runAssertion(ctx context.Context, a assertion) result {
	switch a.Type {
	case "http_allowed":
		return assertHTTPAllowed(ctx, a)
	case "http_denied":
		return assertHTTPDenied(ctx, a)
	case "network_denied":
		return assertNetworkDenied(ctx, a)
	case "l7_allowed":
		return assertL7Allowed(ctx, a)
	case "l7_denied":
		return assertL7Denied(ctx, a)
	case "l7_body_with_header":
		return assertL7BodyWithHeader(ctx, a)
	case "l7_denied_with_header":
		return assertL7DeniedWithHeader(ctx, a)
	case "https_passthrough":
		return assertHTTPSPassthrough(ctx, a)
	case "udp_allowed":
		return assertUDPAllowed(ctx, a)
	case "udp_denied":
		return assertUDPDenied(ctx, a)
	case "udp_send":
		return assertUDPSend(ctx, a)
	case "tcp_forward":
		return assertTCPForward(ctx, a)
	case "dns_noerror":
		return assertDNSNoError(a)
	case "dns_forwarded":
		return assertDNSForwarded(a)
	case "dns_blocked":
		return assertDNSBlocked(a)
	case "file_grep":
		return assertFileGrep(a)
	case "envoy_uid":
		return assertEnvoyUID(a)
	case "ping_allowed":
		return assertPingAllowed(ctx, a)
	case "ping_denied":
		return assertPingDenied(ctx, a)
	case "nft_table_exists":
		return assertNftTableExists(ctx, a)
	case "nft_table_absent":
		return assertNftTableAbsent(ctx, a)
	case "systemctl_active":
		return assertSystemctlActive(ctx, a)
	case "multi_uid_denied":
		return assertMultiUIDDenied(ctx, a)
	case "jail_profile_attached":
		return assertJailProfileAttached(ctx, a)
	case "jail_path_denied":
		return assertJailPathDenied(ctx, a)
	case "jail_signal_denied":
		return assertJailSignalDenied(ctx, a)
	case "jail_nft_denied":
		return assertJailNftDenied(ctx, a)
	case "jail_exec_denied":
		return assertJailExecDenied(ctx, a)
	case "jail_exec_allowed":
		return assertJailExecAllowed(ctx, a)
	case "jail_self_proc_read_allowed":
		return assertJailSelfProcReadAllowed(ctx, a)
	case "jail_refuses_nesting":
		return assertJailRefusesNesting(ctx, a)
	case "apparmor_profile_parses":
		return assertApparmorProfileParses(ctx, a)
	case "lockdown_integrity_mode":
		return assertLockdownIntegrityMode(ctx, a)
	case "lockdown_modprobe_denied":
		return assertLockdownModprobeDenied(ctx, a)
	case "lockdown_devmem_denied":
		return assertLockdownDevmemDenied(ctx, a)
	case "init_subcommand_registered":
		return assertInitSubcommandRegistered(ctx, a)
	default:
		return result{
			Status: statusFail, Desc: a.Desc,
			Detail: fmt.Sprintf("unknown assertion type: %s", a.Type),
		}
	}
}

// httpClient returns an [*http.Client] configured for e2e testing:
// TLS verification disabled (handles self-signed and MITM certs),
// 10s timeout, no automatic redirects, keep-alives disabled so
// connections close immediately (ensures Envoy writes TCP proxy
// access logs before the test sends SIGTERM).
func httpClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // e2e test client
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// newRequest creates an [*http.Request] with the given context and
// no body.
func newRequest(ctx context.Context, method, url string) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, method, url, http.NoBody)
}

// dialUDP dials a UDP address with the given timeout.
func dialUDP(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "udp", addr)
}

// withRetries runs fn up to [retryAttempts] times with [retryBackoff]
// between attempts. It returns the first successful result, or the
// last failure.
func withRetries(ctx context.Context, desc string, fn func() result) result {
	var r result

	for i := 1; i <= retryAttempts; i++ {
		r = fn()

		if r.Status == statusPass {
			return r
		}

		if i < retryAttempts {
			fmt.Printf(
				"  RETRY: %s (attempt %d/%d, retrying in %s)\n",
				desc, i, retryAttempts, retryBackoff,
			)
			time.Sleep(retryBackoff)
		}
	}

	maybeDebugDump(ctx)

	return r
}

// assertHTTPAllowed verifies that an HTTP GET to the URL succeeds with
// a 2xx or 3xx status code.
func assertHTTPAllowed(ctx context.Context, a assertion) result {
	return withRetries(ctx, a.Desc, func() result {
		req, err := newRequest(ctx, http.MethodGet, a.URL)
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("building request: %v", err)}
		}

		resp, err := httpClient().Do(req)
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("expected ALLOWED, got: %v", err)}
		}

		defer func() {
			err := resp.Body.Close()
			if err != nil {
				slog.Debug("closing response body", slog.Any("err", err))
			}
		}()

		if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusBadRequest {
			return result{Status: statusPass, Desc: a.Desc}
		}

		return result{
			Status: statusFail, Desc: a.Desc,
			Detail: fmt.Sprintf("expected 2xx/3xx, got HTTP %d", resp.StatusCode),
		}
	})
}

// assertHTTPDenied verifies that an HTTP GET to the URL is blocked.
// Connection errors, TLS errors, HTTP 403, and HTTP 404 all count as
// denied. DNS resolution failures are treated as infrastructure errors
// since the test expects network-level denial, not DNS failure.
func assertHTTPDenied(ctx context.Context, a assertion) result {
	client := httpClient()

	req, err := newRequest(ctx, http.MethodGet, a.URL)
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("building request: %v", err)}
	}

	resp, err := client.Do(req)
	if err != nil {
		// Classify the error.
		var dnsErr *net.DNSError

		var opErr *net.OpError

		if errors.As(err, &dnsErr) {
			return result{
				Status: statusFail, Desc: a.Desc,
				Detail: "DNS resolution failed -- expected network-level denial, not DNS error",
			}
		}

		// TLS errors are valid denials: Envoy's catch-all filter
		// chain may reject the TLS handshake for unlisted domains.
		if isTLSError(err) {
			return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("TLS error: %v", err)}
		}

		// Connection refused, timeout, or other network error = PASS.
		if errors.As(err, &opErr) || os.IsTimeout(err) || isConnectionRefused(err) {
			return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("connection error: %v", err)}
		}

		// Treat unknown errors as connection-level denial.
		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("connection error: %v", err)}
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			slog.Debug("closing response body", slog.Any("err", err))
		}
	}()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	maybeDebugDump(ctx)

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected DENIED, got HTTP %d -- SECURITY VIOLATION", resp.StatusCode),
	}
}

// assertNetworkDenied verifies that the URL is unreachable at the
// network level. Any connection error, HTTP 403, or HTTP 404 counts
// as denied.
func assertNetworkDenied(ctx context.Context, a assertion) result {
	client := httpClient()

	req, err := newRequest(ctx, http.MethodGet, a.URL)
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("building request: %v", err)}
	}

	resp, err := client.Do(req)
	if err != nil {
		// Any connection error is a pass (network-level denial).
		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("connection error: %v", err)}
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			slog.Debug("closing response body", slog.Any("err", err))
		}
	}()

	// When Envoy's HTTP listener intercepts the connection, unknown
	// domains get 404 (no matching virtual host) or 403 (RBAC deny).
	// Both are valid denials at the proxy layer.
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	maybeDebugDump(ctx)

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected network denial, got HTTP %d", resp.StatusCode),
	}
}

// assertL7Allowed verifies that an HTTP request returns 2xx and
// optionally contains the expected body substring.
func assertL7Allowed(ctx context.Context, a assertion) result {
	method := a.Method
	if method == "" {
		method = http.MethodGet
	}

	return withRetries(ctx, a.Desc, func() result {
		req, err := newRequest(ctx, method, a.URL)
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("building request: %v", err)}
		}

		resp, err := httpClient().Do(req)
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("connection: %v", err)}
		}

		defer func() {
			err := resp.Body.Close()
			if err != nil {
				slog.Debug("closing response body", slog.Any("err", err))
			}
		}()

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return result{
				Status: statusFail, Desc: a.Desc,
				Detail: fmt.Sprintf("expected HTTP 2xx, got HTTP %d", resp.StatusCode),
			}
		}

		if a.Body != "" {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("reading body: %v", readErr)}
			}

			if !strings.Contains(string(body), a.Body) {
				return result{
					Status: statusFail, Desc: a.Desc,
					Detail: fmt.Sprintf("expected body containing %q, got %q", a.Body, string(body)),
				}
			}
		}

		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	})
}

// assertL7Denied verifies that an HTTP request is rejected with
// HTTP 403 by Envoy's RBAC filter.
func assertL7Denied(ctx context.Context, a assertion) result {
	method := a.Method
	if method == "" {
		method = http.MethodGet
	}

	req, err := newRequest(ctx, method, a.URL)
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("building request: %v", err)}
	}

	resp, err := httpClient().Do(req)
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("connection: %v", err)}
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			slog.Debug("closing response body", slog.Any("err", err))
		}
	}()

	if resp.StatusCode == http.StatusForbidden {
		return result{Status: statusPass, Desc: a.Desc, Detail: "HTTP 403"}
	}

	maybeDebugDump(ctx)

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected HTTP 403, got HTTP %d", resp.StatusCode),
	}
}

// assertL7BodyWithHeader verifies that an HTTP request with a custom
// header returns 2xx and optionally contains the expected body substring.
func assertL7BodyWithHeader(ctx context.Context, a assertion) result {
	method := a.Method
	if method == "" {
		method = http.MethodGet
	}

	return withRetries(ctx, a.Desc, func() result {
		req, err := newRequest(ctx, method, a.URL)
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("building request: %v", err)}
		}

		if a.Header != "" {
			parts := strings.SplitN(a.Header, ": ", 2)
			if len(parts) == 2 {
				if strings.EqualFold(parts[0], "Host") {
					req.Host = parts[1]
				} else {
					req.Header.Set(parts[0], parts[1])
				}
			}
		}

		resp, err := httpClient().Do(req)
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("connection: %v", err)}
		}

		defer func() {
			err := resp.Body.Close()
			if err != nil {
				slog.Debug("closing response body", slog.Any("err", err))
			}
		}()

		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return result{
				Status: statusFail, Desc: a.Desc,
				Detail: fmt.Sprintf("expected HTTP 2xx, got HTTP %d", resp.StatusCode),
			}
		}

		if a.Body != "" {
			body, readErr := io.ReadAll(resp.Body)
			if readErr != nil {
				return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("reading body: %v", readErr)}
			}

			if !strings.Contains(string(body), a.Body) {
				return result{
					Status: statusFail, Desc: a.Desc,
					Detail: fmt.Sprintf("expected body containing %q, got %q", a.Body, string(body)),
				}
			}
		}

		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	})
}

// assertL7DeniedWithHeader verifies that an HTTP request with a custom
// header is rejected with HTTP 403 or 404.
func assertL7DeniedWithHeader(ctx context.Context, a assertion) result {
	method := a.Method
	if method == "" {
		method = http.MethodGet
	}

	req, err := newRequest(ctx, method, a.URL)
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("building request: %v", err)}
	}

	if a.Header != "" {
		parts := strings.SplitN(a.Header, ": ", 2)
		if len(parts) == 2 {
			// In HTTP/2, the :authority pseudo-header is derived from
			// req.Host, not from req.Header["Host"]. Setting the Host
			// header via req.Header.Set would be ignored by the h2
			// transport. Use req.Host so the value is sent correctly
			// in both HTTP/1.1 and HTTP/2.
			if strings.EqualFold(parts[0], "Host") {
				req.Host = parts[1]
			} else {
				req.Header.Set(parts[0], parts[1])
			}
		}
	}

	resp, err := httpClient().Do(req)
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("connection: %v", err)}
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			slog.Debug("closing response body", slog.Any("err", err))
		}
	}()

	// Accept both 403 (RBAC denied at route level) and 404 (no
	// virtual host match for the spoofed :authority). Both indicate
	// the request was blocked.
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound {
		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}

	maybeDebugDump(ctx)

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected HTTP 403 or 404, got HTTP %d", resp.StatusCode),
	}
}

// assertHTTPSPassthrough verifies that an HTTPS request reaches the
// origin server without MITM interception, optionally checking the
// response body for an expected substring.
func assertHTTPSPassthrough(ctx context.Context, a assertion) result {
	return withRetries(ctx, a.Desc, func() result {
		req, err := newRequest(ctx, http.MethodGet, a.URL)
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("building request: %v", err)}
		}

		resp, err := httpClient().Do(req)
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("connection: %v", err)}
		}

		defer func() {
			err := resp.Body.Close()
			if err != nil {
				slog.Debug("closing response body", slog.Any("err", err))
			}
		}()

		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("reading body: %v", readErr)}
		}

		if a.Body != "" && !strings.Contains(string(body), a.Body) {
			return result{
				Status: statusFail, Desc: a.Desc,
				Detail: fmt.Sprintf("expected body containing %q, got %q", a.Body, string(body)),
			}
		}

		return result{Status: statusPass, Desc: a.Desc}
	})
}

// assertUDPAllowed verifies that a UDP datagram can be sent and a
// response containing the expected string is received.
func assertUDPAllowed(ctx context.Context, a assertion) result {
	return withRetries(ctx, a.Desc, func() result {
		addr := net.JoinHostPort(a.Host, fmt.Sprintf("%d", a.Port))

		conn, err := dialUDP(ctx, addr, dialTimeout)
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("dial: %v", err)}
		}

		defer func() {
			err := conn.Close()
			if err != nil {
				slog.Debug("closing connection", slog.Any("err", err))
			}
		}()

		err = conn.SetDeadline(time.Now().Add(dialTimeout))
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("set deadline: %v", err)}
		}

		_, err = conn.Write([]byte("hello\n"))
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("write: %v", err)}
		}

		buf := make([]byte, 1024)

		n, err := conn.Read(buf)
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("read: %v", err)}
		}

		response := strings.TrimSpace(string(buf[:n]))

		if strings.Contains(response, a.Expected) {
			return result{Status: statusPass, Desc: a.Desc}
		}

		return result{
			Status: statusFail, Desc: a.Desc,
			Detail: fmt.Sprintf("expected %q, got %q", a.Expected, response),
		}
	})
}

// assertUDPDenied verifies that a UDP datagram receives no response
// within the deny timeout, indicating the traffic was dropped.
func assertUDPDenied(ctx context.Context, a assertion) result {
	addr := net.JoinHostPort(a.Host, fmt.Sprintf("%d", a.Port))

	conn, err := dialUDP(ctx, addr, udpDenyTimeout)
	if err != nil {
		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("dial error: %v", err)}
	}

	defer func() {
		err := conn.Close()
		if err != nil {
			slog.Debug("closing connection", slog.Any("err", err))
		}
	}()

	err = conn.SetDeadline(time.Now().Add(udpDenyTimeout))
	if err != nil {
		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("deadline error: %v", err)}
	}

	_, err = conn.Write([]byte("hello\n"))
	if err != nil {
		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("write error: %v", err)}
	}

	buf := make([]byte, 1024)

	n, err := conn.Read(buf)
	if err != nil {
		// Timeout or read error = denied.
		return result{Status: statusPass, Desc: a.Desc, Detail: "no response"}
	}

	response := strings.TrimSpace(string(buf[:n]))

	if response == "" {
		return result{Status: statusPass, Desc: a.Desc, Detail: "empty response"}
	}

	maybeDebugDump(ctx)

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected no response, got %q", response),
	}
}

// assertUDPSend sends a UDP datagram without waiting for a response.
// Used for tests that only need to verify the datagram was sent (e.g.,
// checking access logs).
func assertUDPSend(ctx context.Context, a assertion) result {
	addr := net.JoinHostPort(a.Host, fmt.Sprintf("%d", a.Port))

	conn, err := dialUDP(ctx, addr, dialTimeout)
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("dial: %v", err)}
	}

	defer func() {
		err := conn.Close()
		if err != nil {
			slog.Debug("closing connection", slog.Any("err", err))
		}
	}()

	_, err = conn.Write([]byte("hello\n"))
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("write: %v", err)}
	}

	// Fire and forget -- wait briefly for the datagram to leave.
	time.Sleep(2 * time.Second)

	return result{Status: statusPass, Desc: a.Desc}
}

// assertTCPForward verifies that a TCP connection to the given address
// receives a response containing the expected string.
func assertTCPForward(ctx context.Context, a assertion) result {
	return withRetries(ctx, a.Desc, func() result {
		dialer := net.Dialer{Timeout: dialTimeout}

		conn, err := dialer.DialContext(ctx, "tcp", a.Addr)
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("dial: %v", err)}
		}

		defer func() {
			err := conn.Close()
			if err != nil {
				slog.Debug("closing connection", slog.Any("err", err))
			}
		}()

		err = conn.SetDeadline(time.Now().Add(dialTimeout))
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("set deadline: %v", err)}
		}

		// Send an empty line to trigger the echo server.
		_, err = conn.Write([]byte("\n"))
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("write: %v", err)}
		}

		buf := make([]byte, 1024)

		n, err := conn.Read(buf)
		if err != nil && n == 0 {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("read: %v", err)}
		}

		response := strings.TrimSpace(string(buf[:n]))

		if strings.Contains(response, a.Expected) {
			return result{Status: statusPass, Desc: a.Desc}
		}

		return result{
			Status: statusFail, Desc: a.Desc,
			Detail: fmt.Sprintf("expected %q in response, got %q", a.Expected, response),
		}
	})
}

// assertDNSNoError verifies that a DNS A query for the domain returns
// NOERROR with at least one answer record.
func assertDNSNoError(a assertion) result {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(a.Domain), dns.TypeA)

	c := new(dns.Client)
	c.Timeout = dialTimeout

	r, _, err := c.Exchange(m, "127.0.0.1:53")
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("DNS query: %v", err)}
	}

	if r.Rcode != dns.RcodeSuccess {
		return result{
			Status: statusFail, Desc: a.Desc,
			Detail: fmt.Sprintf("expected NOERROR, got %s", dns.RcodeToString[r.Rcode]),
		}
	}

	if len(r.Answer) == 0 {
		return result{Status: statusFail, Desc: a.Desc, Detail: "expected answer section, got none"}
	}

	return result{Status: statusPass, Desc: a.Desc, Detail: r.Answer[0].String()}
}

// assertDNSForwarded verifies that the DNS proxy forwarded the query
// to upstream rather than refusing it. Any response code other than
// REFUSED (e.g. NOERROR, NXDOMAIN) proves the proxy allowed the domain.
func assertDNSForwarded(a assertion) result {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(a.Domain), dns.TypeA)

	c := new(dns.Client)
	c.Timeout = dialTimeout

	r, _, err := c.Exchange(m, "127.0.0.1:53")
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("DNS query: %v", err)}
	}

	if r.Rcode == dns.RcodeRefused {
		return result{
			Status: statusFail, Desc: a.Desc,
			Detail: "expected forwarded query, got REFUSED",
		}
	}

	return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("rcode=%s", dns.RcodeToString[r.Rcode])}
}

// assertDNSBlocked verifies that a DNS A query for the domain returns
// NXDOMAIN, indicating the DNS proxy's allowlist rejected it. NXDOMAIN
// (not REFUSED) is used so stub resolvers fall back through the
// resolv.conf search domain list correctly.
func assertDNSBlocked(a assertion) result {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(a.Domain), dns.TypeA)

	c := new(dns.Client)
	c.Timeout = dialTimeout

	r, _, err := c.Exchange(m, "127.0.0.1:53")
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("DNS query: %v", err)}
	}

	if r.Rcode == dns.RcodeNameError {
		return result{Status: statusPass, Desc: a.Desc}
	}

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected NXDOMAIN, got %s", dns.RcodeToString[r.Rcode]),
	}
}

// assertFileGrep verifies that a file contains content matching the
// given pattern. The pattern is tried as a regex first; if it fails
// to compile, a substring match is used instead.
func assertFileGrep(a assertion) result {
	data, err := os.ReadFile(a.File)
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("reading %s: %v", a.File, err)}
	}

	re, err := regexp.Compile(a.Pattern)
	if err != nil {
		// Fall back to substring match if not valid regex.
		if strings.Contains(string(data), a.Pattern) {
			return result{Status: statusPass, Desc: a.Desc}
		}

		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("pattern not found in %s", string(data))}
	}

	if re.Match(data) {
		return result{Status: statusPass, Desc: a.Desc}
	}

	return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("pattern not found in %s", string(data))}
}

// assertEnvoyUID verifies that the Envoy process is running under the
// expected UID by scanning /proc for a process whose cmdline contains
// "envoy".
func assertEnvoyUID(a assertion) result {
	// Read /proc to find envoy process and check its UID.
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("reading /proc: %v", err)}
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if directory name is numeric (PID).
		pid := entry.Name()
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}

		cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%s/cmdline", pid))
		if err != nil {
			continue
		}

		if !strings.Contains(string(cmdline), "envoy") {
			continue
		}

		status, err := os.ReadFile(fmt.Sprintf("/proc/%s/status", pid))
		if err != nil {
			continue
		}

		for line := range strings.SplitSeq(string(status), "\n") {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[1] == a.UID {
					return result{Status: statusPass, Desc: a.Desc}
				}

				return result{
					Status: statusFail, Desc: a.Desc,
					Detail: fmt.Sprintf("expected UID %s, got %s", a.UID, fields[1]),
				}
			}
		}
	}

	return result{Status: statusFail, Desc: a.Desc, Detail: "no envoy process found"}
}

// assertPingAllowed verifies that ICMP ping to the host succeeds when
// run as UID/GID 1000 via terrarium exec.
func assertPingAllowed(ctx context.Context, a assertion) result {
	return withRetries(ctx, a.Desc, func() result {
		cmd := exec.CommandContext( //nolint:gosec // host from test spec
			ctx,
			"terrarium", "exec",
			"--reuid=1000", "--regid=1000", "--clear-groups",
			"--", "ping", "-c", "1", "-W", "5", a.Host,
		)

		err := cmd.Run()
		if err != nil {
			return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("ping: %v", err)}
		}

		return result{Status: statusPass, Desc: a.Desc}
	})
}

// assertPingDenied verifies that ICMP ping to the host fails when run
// as UID/GID 1000 via terrarium exec.
func assertPingDenied(ctx context.Context, a assertion) result {
	cmd := exec.CommandContext( //nolint:gosec // host from test spec
		ctx,
		"terrarium", "exec",
		"--reuid=1000", "--regid=1000", "--clear-groups",
		"--", "ping", "-c", "1", "-W", "3", a.Host,
	)

	err := cmd.Run()
	if err != nil {
		return result{Status: statusPass, Desc: a.Desc}
	}

	maybeDebugDump(ctx)

	return result{Status: statusFail, Desc: a.Desc, Detail: "ping succeeded unexpectedly"}
}

// assertNftTableExists verifies that an nftables table with the
// expected name exists in the inet family.
func assertNftTableExists(ctx context.Context, a assertion) result {
	cmd := exec.CommandContext( //nolint:gosec // table name from test spec
		ctx,
		"nft", "list", "table", "inet", a.Expected,
	)

	err := cmd.Run()
	if err != nil {
		return result{
			Status: statusFail,
			Desc:   a.Desc,
			Detail: fmt.Sprintf("nft list table inet %s: %v", a.Expected, err),
		}
	}

	return result{Status: statusPass, Desc: a.Desc}
}

// assertNftTableAbsent verifies that an nftables table with the
// expected name does not exist in the inet family.
func assertNftTableAbsent(ctx context.Context, a assertion) result {
	cmd := exec.CommandContext( //nolint:gosec // table name from test spec
		ctx,
		"nft", "list", "table", "inet", a.Expected,
	)

	err := cmd.Run()
	if err != nil {
		// Non-zero exit means the table does not exist -- pass.
		return result{Status: statusPass, Desc: a.Desc}
	}

	return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("table inet %s still exists", a.Expected)}
}

// assertSystemctlActive verifies that a systemd unit is in "active"
// state.
func assertSystemctlActive(ctx context.Context, a assertion) result {
	out, err := exec.CommandContext( //nolint:gosec // unit name from test spec
		ctx,
		"systemctl", "is-active", a.Expected,
	).Output()
	if err != nil {
		return result{
			Status: statusFail,
			Desc:   a.Desc,
			Detail: fmt.Sprintf("systemctl is-active %s: %v", a.Expected, err),
		}
	}

	status := strings.TrimSpace(string(out))
	if status == "active" {
		return result{Status: statusPass, Desc: a.Desc}
	}

	return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("expected active, got %s", status)}
}

// assertMultiUIDDenied verifies that an HTTP request run as the given
// UID via terrarium exec is denied. Connection failure, HTTP 403, or
// HTTP 404 all count as denied.
func assertMultiUIDDenied(ctx context.Context, a assertion) result {
	uid := a.UID
	if uid == "" {
		uid = "1000"
	}

	cmd := exec.CommandContext( //nolint:gosec // uid and url from test spec
		ctx,
		"terrarium", "exec",
		"--reuid="+uid, "--regid="+uid, "--clear-groups",
		"--", "sh", "-c",
		fmt.Sprintf(
			`curl --max-time 5 --silent --output /dev/null --write-out "%%{http_code}" %s || echo "CONNFAIL"`,
			a.URL,
		),
	)

	out, err := cmd.Output()
	if err != nil {
		// Command failure means the request could not complete -- denied.
		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("exec error (denied): %v", err)}
	}

	output := strings.TrimSpace(string(out))

	// Connection failure or HTTP 403/404 = denied. When curl fails,
	// --write-out prints "000" and the || echo fallback appends
	// "CONNFAIL", producing "000CONNFAIL".
	if strings.Contains(output, "CONNFAIL") || output == "000" || output == "403" || output == "404" {
		return result{Status: statusPass, Desc: a.Desc, Detail: fmt.Sprintf("UID %s denied (output: %s)", uid, output)}
	}

	maybeDebugDump(ctx)

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected UID %s denied, got HTTP %s", uid, output),
	}
}

// isTLSError checks if the error chain contains a TLS-related error.
func isTLSError(err error) bool {
	if err == nil {
		return false
	}

	msg := err.Error()

	return strings.Contains(msg, "tls:") ||
		strings.Contains(msg, "certificate") ||
		strings.Contains(msg, "x509:")
}

// isConnectionRefused checks if the error represents a connection
// refusal.
func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}

	return strings.Contains(err.Error(), "connection refused")
}
