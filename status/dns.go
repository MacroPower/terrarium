package status

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// defaultProbeTimeout bounds how long an active DNS probe can block.
// Short enough that a status command stays snappy even when the
// proxy is unresponsive.
const defaultProbeTimeout = 200 * time.Millisecond

// collectDNS reports the DNS proxy listen state. The state depends on
// the daemon's liveness: if the daemon is [DaemonRunning], the
// in-process proxy must be bound, so the section reports
// [DNSListening]; otherwise the section reports [DNSUnknown]. An
// active probe runs only when opts.ProbeDNS is set.
func collectDNS(opts Options, daemon DaemonState) DNSSection {
	s := DNSSection{
		ListenAddrs: dnsListenAddrs(),
	}

	if daemon == DaemonRunning {
		s.State = DNSListening
	}

	if !opts.ProbeDNS || len(s.ListenAddrs) == 0 {
		return s
	}

	err := probeDNS(s.ListenAddrs[0], defaultProbeTimeout)
	s.Probed = true

	if err != nil {
		s.State = DNSUnreachable
		s.ProbeErr = err
	}

	return s
}

// dnsListenAddrs returns the addresses the DNS proxy binds under the
// current system configuration. IPv4 is always present. IPv6 is
// included unless the kernel reports IPv6 globally disabled via
// /proc/sys/net/ipv6/conf/all/disable_ipv6. A read failure is not
// fatal: we default to the IPv6-enabled case so the rendered output
// matches what the daemon almost always binds.
func dnsListenAddrs() []string {
	addrs := []string{"127.0.0.1:53"}
	if !ipv6Disabled() {
		addrs = append(addrs, "[::1]:53")
	}

	return addrs
}

// ipv6Disabled parses /proc/sys/net/ipv6/conf/all/disable_ipv6. Any
// error reading the file is swallowed and treated as "IPv6 enabled."
func ipv6Disabled() bool {
	data, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(data)) == "1"
}

// probeDNS sends a minimal A query to addr and returns an error if
// the exchange does not complete within timeout or the server
// returns a fatal error. The query is for a fixed inert name so
// repeated probes are idempotent.
func probeDNS(addr string, timeout time.Duration) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %s: %w", addr, err)
	}

	// dns.Client expects the host form with brackets when IPv6, and
	// without brackets when IPv4. net.JoinHostPort handles both.
	target := net.JoinHostPort(host, port)

	client := &dns.Client{Timeout: timeout}

	msg := &dns.Msg{}
	msg.SetQuestion("status.terrarium.invalid.", dns.TypeA)

	_, _, err = client.Exchange(msg, target)
	if err != nil {
		return fmt.Errorf("dns exchange: %w", err)
	}

	return nil
}
