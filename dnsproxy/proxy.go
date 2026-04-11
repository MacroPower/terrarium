package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"

	"go.jacobcolvin.com/terrarium/config"
)

const (
	protoTCP = "tcp"
	protoUDP = "udp"
)

// mode determines how the DNS proxy handles queries.
type mode int

const (
	// modeForwardAll forwards all queries to the upstream resolver.
	// Used for unrestricted and bare wildcard configs.
	modeForwardAll mode = iota

	// modeRefuseAll returns REFUSED for all queries without
	// contacting upstream. Used for blocked configs (egress: [{}]).
	modeRefuseAll

	// modeAllowlist forwards queries matching the allowed domain
	// list and returns REFUSED for everything else.
	modeAllowlist
)

// minIPSetTTL is the minimum timeout (in seconds) for ipset entries
// populated from DNS responses.
const minIPSetTTL = 60

// Proxy is a filtering DNS proxy that handles domain-level
// filtering and ipset population. It forwards allowed queries to the
// real upstream resolver and returns REFUSED for blocked domains,
// replacing the previous dnsmasq + RefuseDNS two-hop chain with a
// single process.
type Proxy struct {
	logFile          io.Closer
	ctx              context.Context
	logger           *slog.Logger
	cancel           context.CancelFunc
	fqdnSetFunc      func(ctx context.Context, setName string, ips []net.IP, ttl time.Duration) error
	udp4             *dns.Server
	udp6             *dns.Server
	tcp4             *dns.Server
	tcp6             *dns.Server
	Addr             string
	upstream         string
	patterns         []config.FQDNPattern
	catchAllPatterns []config.FQDNPattern
	icmpFQDNPatterns []config.FQDNPattern
	domains          []Domain
	clientTimeout    time.Duration
	filterMode       mode
	logging          bool
	ipv6Disabled     bool
	vmMode           bool
}

// Option configures optional behavior of a [Proxy].
//
// The following options are available:
//
//   - [WithClientTimeout]
//   - [WithFQDNSetFunc]
//   - [WithVMMode]
type Option func(*Proxy)

// WithClientTimeout overrides the default 10-second upstream DNS
// client timeout. An [Option].
func WithClientTimeout(d time.Duration) Option {
	return func(p *Proxy) {
		p.clientTimeout = d
	}
}

// WithFQDNSetFunc replaces the default nftables set update with fn.
// Intended for testing set population without requiring root
// privileges or netlink access. An [Option].
func WithFQDNSetFunc(
	fn func(ctx context.Context, setName string, ips []net.IP, ttl time.Duration) error,
) Option {
	return func(p *Proxy) {
		p.fqdnSetFunc = fn
	}
}

// WithVMMode enables VM mode, which binds IPv6 listeners to [::]
// instead of [::1] and sets IPV6_TRANSPARENT on the sockets. This
// allows the DNS proxy to receive TPROXY'd forwarded IPv6 DNS queries
// with non-local destination addresses. An [Option].
func WithVMMode() Option {
	return func(p *Proxy) {
		p.vmMode = true
	}
}

// Start starts the DNS proxy on listenAddr (and optionally
// [::1] at the same port when ipv6Disabled is false). The proxy
// determines its filtering mode from cfg:
//
//   - nil/unrestricted/bare-wildcard: forward all queries
//   - blocked (egress: [{}]): return REFUSED for all queries
//   - restricted with specific domains: forward allowed, refuse others
//
// When cfg has FQDN rules with non-TCP ports, both UDP and TCP
// responses matching the compiled patterns populate ipsets with
// TTL-aware timeouts. Blocks until ready.
//
// IPv6 listener: if ipv6Disabled is true, only IPv4 listeners are
// created. If ipv6Disabled is false and binding [::1] fails, startup
// returns an error (IPv6 bypass risk).
func Start(
	ctx context.Context, cfg *config.Config, upstream, listenAddr string, ipv6Disabled bool,
	opts ...Option,
) (*Proxy, error) {
	ctx, cancel := context.WithCancel(ctx)

	p := &Proxy{
		upstream:      upstream,
		cancel:        cancel,
		ctx:           ctx,
		clientTimeout: 10 * time.Second,
	}

	// Determine filtering mode.
	switch {
	case cfg == nil || cfg.IsEgressUnrestricted():
		p.filterMode = modeForwardAll

		slog.InfoContext(ctx, "dns proxy mode: forward-all (unrestricted)")

	case cfg.IsEgressBlocked():
		p.filterMode = modeRefuseAll

		slog.InfoContext(ctx, "dns proxy mode: refuse-all (blocked)")

	default:
		domains := CollectDomains(cfg)

		slog.InfoContext(ctx, "dns proxy collected domains",
			slog.Int("count", len(domains)),
			slog.Any("domains", domains),
		)

		if len(domains) == 0 || slices.ContainsFunc(domains, func(d Domain) bool {
			return d.Name == "*"
		}) {
			p.filterMode = modeForwardAll

			slog.InfoContext(ctx, "dns proxy mode: forward-all (no domains or bare wildcard)")
		} else {
			p.filterMode = modeAllowlist
			p.domains = domains

			slog.InfoContext(ctx, "dns proxy mode: allowlist")
		}
	}

	// Compile FQDN patterns for set population (non-TCP ports only).
	if cfg != nil && cfg.HasFQDNNonTCPPorts(ctx) {
		p.patterns = cfg.CompileFQDNPatterns()
	}

	// Compile catch-all FQDN patterns (all-port ipset enforcement).
	if cfg != nil && len(cfg.ResolveCatchAllFQDNRules()) > 0 {
		p.catchAllPatterns = cfg.CompileCatchAllFQDNPatterns()
	}

	// Compile ICMP FQDN patterns (ICMP+toFQDNs ipset enforcement).
	if cfg != nil && len(cfg.ResolveICMPFQDNRules()) > 0 {
		p.icmpFQDNPatterns = cfg.CompileICMPFQDNPatterns()
	}

	if cfg != nil {
		p.logging = cfg.DNSLoggingEnabled()

		if p.logging {
			w, closer, err := openLogWriter(cfg.DNSLogPath())
			if err != nil {
				cancel()

				return nil, fmt.Errorf("opening DNS log: %w", err)
			}

			p.logFile = closer
			p.logger = newLogger(w, cfg.DNSLogFormat())
		}
	}

	p.ipv6Disabled = ipv6Disabled

	for _, opt := range opts {
		opt(p)
	}

	// Collect servers and listeners for cleanup on error.
	type closer interface{ Close() error }

	var closers []closer

	cleanup := func() {
		cancel()

		for _, c := range closers {
			err := c.Close()
			if err != nil {
				slog.WarnContext(ctx, "closing listener", slog.Any("err", err))
			}
		}
	}

	lc := net.ListenConfig{}

	// UDP IPv4.
	udp4PC, err := lc.ListenPacket(ctx, "udp", listenAddr)
	if err != nil {
		cleanup()

		return nil, fmt.Errorf("listening UDP %s: %w", listenAddr, err)
	}

	closers = append(closers, udp4PC)

	// Resolve actual address (port may be 0).
	udpAddr, ok := udp4PC.LocalAddr().(*net.UDPAddr)
	if !ok {
		cleanup()

		return nil, fmt.Errorf("unexpected address type: %T", udp4PC.LocalAddr())
	}

	p.Addr = udpAddr.String()

	p.udp4 = &dns.Server{
		PacketConn: udp4PC,
		Handler:    dns.HandlerFunc(p.handleUDPQuery),
	}

	// TCP IPv4 on the same port.
	tcp4Ln, err := lc.Listen(ctx, "tcp", p.Addr)
	if err != nil {
		cleanup()

		return nil, fmt.Errorf("listening TCP %s: %w", p.Addr, err)
	}

	closers = append(closers, tcp4Ln)

	p.tcp4 = &dns.Server{
		Listener: tcp4Ln,
		Handler:  dns.HandlerFunc(p.handleTCPQuery),
	}

	// IPv6 listeners.
	if !ipv6Disabled {
		host6 := "::1"
		if p.vmMode {
			host6 = "::"
		}

		addr6 := fmt.Sprintf("[%s]:%d", host6, udpAddr.Port)

		// VM mode: set IPV6_TRANSPARENT so the socket can accept
		// TPROXY'd packets with non-local destination addresses.
		lc6 := lc
		if p.vmMode {
			lc6 = net.ListenConfig{
				Control: setIPv6Transparent,
			}
		}

		udp6PC, err := lc6.ListenPacket(ctx, "udp", addr6)
		if err != nil {
			cleanup()

			return nil, fmt.Errorf("listening UDP %s: %w", addr6, err)
		}

		closers = append(closers, udp6PC)

		p.udp6 = &dns.Server{
			PacketConn: udp6PC,
			Handler:    dns.HandlerFunc(p.handleUDPQuery),
		}

		tcp6Ln, err := lc6.Listen(ctx, "tcp", addr6)
		if err != nil {
			cleanup()

			return nil, fmt.Errorf("listening TCP %s: %w", addr6, err)
		}

		closers = append(closers, tcp6Ln)

		p.tcp6 = &dns.Server{
			Listener: tcp6Ln,
			Handler:  dns.HandlerFunc(p.handleTCPQuery),
		}
	}

	// Start all servers and wait for ready.
	var wg sync.WaitGroup

	for _, s := range []*dns.Server{p.udp4, p.tcp4, p.udp6, p.tcp6} {
		if s == nil {
			continue
		}

		wg.Add(1)

		s.NotifyStartedFunc = sync.OnceFunc(func() { wg.Done() })

		go func() {
			err := s.ActivateAndServe()
			if err != nil {
				slog.Debug("dns server exited", slog.Any("err", err))
			}
		}()
	}

	wg.Wait()

	return p, nil
}

// Shutdown gracefully stops the proxy. In-flight queries are dropped
// (acceptable for a short-lived terrarium).
func (p *Proxy) Shutdown() error {
	p.cancel()

	var errs []error

	for _, s := range []*dns.Server{p.udp4, p.udp6, p.tcp4, p.tcp6} {
		if s != nil {
			err := s.Shutdown()
			if err != nil {
				errs = append(errs, err)
			}
		}
	}

	if p.logFile != nil {
		err := p.logFile.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutting down DNS proxy: %v", errs)
	}

	return nil
}

// handleUDPQuery handles UDP DNS queries with mode-aware filtering
// and ipset population for matching responses.
func (p *Proxy) handleUDPQuery(w dns.ResponseWriter, r *dns.Msg) {
	p.handleQuery(w, r, protoUDP)
}

// handleTCPQuery handles TCP DNS queries with mode-aware filtering
// and ipset population for matching responses.
func (p *Proxy) handleTCPQuery(w dns.ResponseWriter, r *dns.Msg) {
	p.handleQuery(w, r, protoTCP)
}

// handleQuery is the unified query handler for both UDP and TCP.
// It applies mode-based filtering, forwards allowed queries to
// upstream, populates ipsets for matching responses, and logs when
// enabled.
func (p *Proxy) handleQuery(w dns.ResponseWriter, r *dns.Msg, proto string) {
	if len(r.Question) == 0 {
		fail := new(dns.Msg)
		fail.SetRcode(r, dns.RcodeServerFailure)

		err := w.WriteMsg(fail)
		if err != nil {
			slog.Warn("writing dns error response", slog.Any("err", err))
		}

		return
	}

	qname := strings.ToLower(r.Question[0].Name)

	// Blocked mode: refuse everything without contacting upstream.
	if p.filterMode == modeRefuseAll {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeRefused)

		if p.logging {
			p.logger.Info("dns query refused",
				slog.String("name", qname),
			)
		}

		err := w.WriteMsg(resp)
		if err != nil {
			slog.Warn("writing dns refusal", slog.Any("err", err))
		}

		return
	}

	// Allowlist mode: refuse queries that don't match any allowed domain.
	if p.filterMode == modeAllowlist && !p.domainAllowed(qname) {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeRefused)

		if p.logging {
			p.logger.Info("dns query refused",
				slog.String("name", qname),
			)
		}

		err := w.WriteMsg(resp)
		if err != nil {
			slog.Warn("writing dns refusal", slog.Any("err", err))
		}

		return
	}

	// Forward to upstream.
	client := &dns.Client{
		Net:     proto,
		Timeout: p.clientTimeout,
	}

	resp, _, err := client.ExchangeContext(p.ctx, r, p.upstream)
	if err != nil {
		// On upstream timeout, return without sending a response
		// to let the client's own timeout expire naturally. This
		// matches Cilium's behavior and avoids triggering
		// immediate client retries via SERVFAIL.
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return
		}

		fail := new(dns.Msg)
		fail.SetRcode(r, dns.RcodeServerFailure)

		err := w.WriteMsg(fail)
		if err != nil {
			slog.Warn("writing dns error response", slog.Any("err", err))
		}

		return
	}

	// Populate FQDN sets for both UDP and TCP responses. TCP DNS
	// responses (e.g., from truncated UDP retries) contain IPs that
	// must be added to the firewall allow list.
	if resp.Rcode == dns.RcodeSuccess {
		if indices := matchingFQDNRuleIndices(p.patterns, qname); len(indices) > 0 {
			p.populateFQDNSets(qname, resp, indices, config.FQDNSetName)
		}

		if indices := matchingFQDNRuleIndices(p.catchAllPatterns, qname); len(indices) > 0 {
			p.populateFQDNSets(qname, resp, indices, config.CatchAllFQDNSetName)
		}

		if indices := matchingFQDNRuleIndices(p.icmpFQDNPatterns, qname); len(indices) > 0 {
			p.populateFQDNSets(qname, resp, indices, config.ICMPFQDNSetName)
		}
	}

	if p.logging {
		p.logger.Info("dns query",
			slog.String("name", qname),
			slog.Int("answers", len(resp.Answer)),
		)
	}

	// Compress oversized UDP responses to avoid unnecessary TCP
	// retries. Matches Cilium's shouldCompressResponse logic:
	// inspect EDNS0 UDPSize() (or 512 bytes when absent).
	if proto == protoUDP {
		edns := r.IsEdns0()
		respLen := resp.Len()

		if (edns != nil && respLen > int(edns.UDPSize())) || respLen > 512 {
			resp.Compress = true
		}
	}

	err = w.WriteMsg(resp)
	if err != nil {
		slog.Warn("writing dns response", slog.Any("err", err))
	}
}

// domainAllowed reports whether qname matches any domain in the
// allowlist.
func (p *Proxy) domainAllowed(qname string) bool {
	for _, d := range p.domains {
		if d.Matches(qname) {
			return true
		}
	}

	return false
}

// matchingFQDNRuleIndices returns the deduplicated rule indices whose
// compiled patterns match qname.
func matchingFQDNRuleIndices(patterns []config.FQDNPattern, qname string) []int {
	seen := make(map[int]bool)

	var indices []int

	for _, pat := range patterns {
		if pat.Regex.MatchString(qname) && !seen[pat.RuleIndex] {
			seen[pat.RuleIndex] = true
			indices = append(indices, pat.RuleIndex)
		}
	}

	return indices
}

// populateFQDNSets extracts A and AAAA records from the DNS response
// and adds them to the per-rule nftables sets for each matching rule
// index. The setNameFunc maps (ruleIndex, ipv6) to the nftables set
// name. The TTL is the minimum across all records in the response
// (including CNAME chain), matching Cilium's ExtractMsgDetails
// behavior. TTLs are clamped to a minimum of [minIPSetTTL].
func (p *Proxy) populateFQDNSets(qname string, resp *dns.Msg, ruleIndices []int, setNameFunc func(int, bool) string) {
	// Compute minimum TTL across all answer records (A, AAAA,
	// CNAME) to match Cilium's lowest-TTL-in-chain behavior.
	minTTL := -1

	for _, rr := range resp.Answer {
		rrTTL := int(rr.Header().Ttl)
		if minTTL < 0 || rrTTL < minTTL {
			minTTL = rrTTL
		}
	}

	if minTTL < 0 {
		return
	}

	ttl := time.Duration(max(minTTL, minIPSetTTL)) * time.Second

	// Extract and log CNAME targets for observability.
	for _, rr := range resp.Answer {
		if cname, ok := rr.(*dns.CNAME); ok && p.logging {
			p.logger.Info("dns cname",
				slog.String("name", qname),
				slog.String("target", cname.Target),
				slog.Int("ttl", int(cname.Hdr.Ttl)),
			)
		}
	}

	// Collect A and AAAA records separately.
	var v4IPs, v6IPs []net.IP

	for _, rr := range resp.Answer {
		switch a := rr.(type) {
		case *dns.A:
			v4IPs = append(v4IPs, a.A)
		case *dns.AAAA:
			v6IPs = append(v6IPs, a.AAAA)
		}
	}

	if len(v4IPs) == 0 && len(v6IPs) == 0 {
		return
	}

	// Update each matching rule's sets.
	for _, idx := range ruleIndices {
		if len(v4IPs) > 0 {
			setName := setNameFunc(idx, false)
			p.updateFQDNSet(qname, setName, v4IPs, ttl)
		}

		if len(v6IPs) > 0 && !p.ipv6Disabled {
			setName := setNameFunc(idx, true)
			p.updateFQDNSet(qname, setName, v6IPs, ttl)
		}
	}
}

// updateFQDNSet adds IPs to a single nftables set, using the
// injected fqdnSetFunc or the default UpdateFQDNSet implementation.
func (p *Proxy) updateFQDNSet(qname, setName string, ips []net.IP, ttl time.Duration) {
	if p.fqdnSetFunc != nil {
		err := p.fqdnSetFunc(p.ctx, setName, ips, ttl)
		if err != nil {
			slog.Debug("fqdn set update",
				slog.String("qname", qname),
				slog.String("set", setName),
				slog.Any("err", err),
			)
		}

		return
	}

	slog.Warn("fqdn set update called without fqdnSetFunc configured",
		slog.String("set", setName),
	)
}

// openLogWriter opens the output writer for the DNS query logger.
// "/dev/stderr" maps to [os.Stderr]; any other path opens a file.
// The returned [io.Closer] is nil when writing to stderr.
func openLogWriter(path string) (io.Writer, io.Closer, error) {
	if path == "" || path == "/dev/stderr" {
		return os.Stderr, nil, nil
	}

	//nolint:gosec // G304: path is from validated config.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("opening log file %q: %w", path, err)
	}

	return f, f, nil
}

// newLogger creates a [*slog.Logger] with the given format.
// "json" uses [slog.NewJSONHandler]; all other values use
// [slog.NewTextHandler] (logfmt).
func newLogger(w io.Writer, format string) *slog.Logger {
	var handler slog.Handler

	switch format {
	case "json":
		handler = slog.NewJSONHandler(w, nil)
	default:
		handler = slog.NewTextHandler(w, nil)
	}

	return slog.New(handler)
}

// setIPv6Transparent sets IPV6_TRANSPARENT and IPV6_V6ONLY on an IPv6
// socket so it can accept TPROXY'd packets with non-local destination
// addresses. IPV6_V6ONLY prevents the dual-stack socket from also
// binding IPv4, which would conflict with the separate IPv4 listener.
// Used as a [net.ListenConfig.Control] function in VM mode.
func setIPv6Transparent(_, _ string, c syscall.RawConn) error {
	var optErr error

	controlErr := c.Control(func(fd uintptr) {
		optErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_V6ONLY, 1)
		if optErr != nil {
			return
		}

		optErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	})
	if controlErr != nil {
		return fmt.Errorf("accessing raw socket: %w", controlErr)
	}

	if optErr != nil {
		return fmt.Errorf("setting IPv6 socket options: %w", optErr)
	}

	return nil
}
