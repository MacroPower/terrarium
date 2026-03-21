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

// runAssertion dispatches a single [assertion] to the appropriate
// implementation based on [assertion.Type] and returns the [result].
func runAssertion(a assertion) result {
	switch a.Type {
	case "http_allowed":
		return assertHTTPAllowed(a)
	case "http_denied":
		return assertHTTPDenied(a)
	case "network_denied":
		return assertNetworkDenied(a)
	case "l7_allowed":
		return assertL7Allowed(a)
	case "l7_denied":
		return assertL7Denied(a)
	case "l7_body_with_header":
		return assertL7BodyWithHeader(a)
	case "l7_denied_with_header":
		return assertL7DeniedWithHeader(a)
	case "https_passthrough":
		return assertHTTPSPassthrough(a)
	case "udp_allowed":
		return assertUDPAllowed(a)
	case "udp_denied":
		return assertUDPDenied(a)
	case "udp_send":
		return assertUDPSend(a)
	case "tcp_forward":
		return assertTCPForward(a)
	case "dns_noerror":
		return assertDNSNoError(a)
	case "dns_forwarded":
		return assertDNSForwarded(a)
	case "dns_refused":
		return assertDNSRefused(a)
	case "file_grep":
		return assertFileGrep(a)
	case "envoy_uid":
		return assertEnvoyUID(a)
	case "ping_allowed":
		return assertPingAllowed(a)
	case "ping_denied":
		return assertPingDenied(a)
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

func newRequest(method, url string) (*http.Request, error) {
	return http.NewRequestWithContext(context.Background(), method, url, http.NoBody)
}

func dialUDP(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	dialer := net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "udp", addr)
}

// withRetries runs fn up to [retryAttempts] times with [retryBackoff]
// between attempts. It returns the first successful result, or the
// last failure.
func withRetries(desc string, fn func() result) result {
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

	return r
}

func assertHTTPAllowed(a assertion) result {
	return withRetries(a.Desc, func() result {
		req, err := newRequest(http.MethodGet, a.URL)
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

func assertHTTPDenied(a assertion) result {
	client := httpClient()

	req, err := newRequest(http.MethodGet, a.URL)
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

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected DENIED, got HTTP %d -- SECURITY VIOLATION", resp.StatusCode),
	}
}

func assertNetworkDenied(a assertion) result {
	client := httpClient()

	req, err := newRequest(http.MethodGet, a.URL)
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

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected network denial, got HTTP %d", resp.StatusCode),
	}
}

func assertL7Allowed(a assertion) result {
	method := a.Method
	if method == "" {
		method = http.MethodGet
	}

	return withRetries(a.Desc, func() result {
		req, err := newRequest(method, a.URL)
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

func assertL7Denied(a assertion) result {
	method := a.Method
	if method == "" {
		method = http.MethodGet
	}

	req, err := newRequest(method, a.URL)
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

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected HTTP 403, got HTTP %d", resp.StatusCode),
	}
}

func assertL7BodyWithHeader(a assertion) result {
	method := a.Method
	if method == "" {
		method = http.MethodGet
	}

	return withRetries(a.Desc, func() result {
		req, err := newRequest(method, a.URL)
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

func assertL7DeniedWithHeader(a assertion) result {
	method := a.Method
	if method == "" {
		method = http.MethodGet
	}

	req, err := newRequest(method, a.URL)
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

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected HTTP 403 or 404, got HTTP %d", resp.StatusCode),
	}
}

func assertHTTPSPassthrough(a assertion) result {
	return withRetries(a.Desc, func() result {
		req, err := newRequest(http.MethodGet, a.URL)
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

func assertUDPAllowed(a assertion) result {
	return withRetries(a.Desc, func() result {
		addr := net.JoinHostPort(a.Host, fmt.Sprintf("%d", a.Port))

		conn, err := dialUDP(context.Background(), addr, dialTimeout)
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

func assertUDPDenied(a assertion) result {
	addr := net.JoinHostPort(a.Host, fmt.Sprintf("%d", a.Port))

	conn, err := dialUDP(context.Background(), addr, udpDenyTimeout)
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

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected no response, got %q", response),
	}
}

func assertUDPSend(a assertion) result {
	addr := net.JoinHostPort(a.Host, fmt.Sprintf("%d", a.Port))

	conn, err := dialUDP(context.Background(), addr, dialTimeout)
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

func assertTCPForward(a assertion) result {
	return withRetries(a.Desc, func() result {
		dialer := net.Dialer{Timeout: dialTimeout}

		conn, err := dialer.DialContext(context.Background(), "tcp", a.Addr)
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

func assertDNSRefused(a assertion) result {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(a.Domain), dns.TypeA)

	c := new(dns.Client)
	c.Timeout = dialTimeout

	r, _, err := c.Exchange(m, "127.0.0.1:53")
	if err != nil {
		return result{Status: statusFail, Desc: a.Desc, Detail: fmt.Sprintf("DNS query: %v", err)}
	}

	if r.Rcode == dns.RcodeRefused {
		return result{Status: statusPass, Desc: a.Desc}
	}

	return result{
		Status: statusFail, Desc: a.Desc,
		Detail: fmt.Sprintf("expected REFUSED, got %s", dns.RcodeToString[r.Rcode]),
	}
}

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

func assertPingAllowed(a assertion) result {
	return withRetries(a.Desc, func() result {
		cmd := exec.CommandContext( //nolint:gosec // host from test spec
			context.Background(),
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

func assertPingDenied(a assertion) result {
	cmd := exec.CommandContext( //nolint:gosec // host from test spec
		context.Background(),
		"terrarium", "exec",
		"--reuid=1000", "--regid=1000", "--clear-groups",
		"--", "ping", "-c", "1", "-W", "3", a.Host,
	)

	err := cmd.Run()
	if err != nil {
		return result{Status: statusPass, Desc: a.Desc}
	}

	return result{Status: statusFail, Desc: a.Desc, Detail: "ping succeeded unexpectedly"}
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
