package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/eventstore"
)

const (
	protoTCP = "tcp"
	protoUDP = "udp"
)

// mode determines how the DNS proxy handles queries.
type mode int

const (
	// Forwards all queries to the upstream resolver.
	// Used for unrestricted and bare wildcard configs.
	modeForwardAll mode = iota

	// Returns REFUSED for all queries without
	// contacting upstream. Used for blocked configs (egress: [{}]).
	modeRefuseAll

	// Forwards queries matching the allowed domain
	// list and returns NXDOMAIN for everything else.
	modeAllowlist
)

// bindAttempts is the number of ports that [Start] tries when the
// kernel picks the port.
const bindAttempts = 10

// minIPSetTTL is the minimum timeout (in seconds) for ipset entries
// populated from DNS responses.
const minIPSetTTL = 60

// Proxy is a filtering DNS proxy that handles domain-level
// filtering and ipset population. It forwards allowed queries to the
// real upstream resolver and returns NXDOMAIN for domains not on
// the allowlist (so stub resolvers fall back through search domains)
// or REFUSED in deny-all mode, replacing the previous
// dnsmasq + RefuseDNS two-hop chain with a single process.
type Proxy struct {
	logFile          io.Closer
	ctx              context.Context
	logger           *slog.Logger
	cancel           context.CancelFunc
	fqdnSetFunc      func(ctx context.Context, setName string, ips []net.IP, ttl time.Duration) error
	listenTCP        func(ctx context.Context, lc *net.ListenConfig, addr string) (net.Listener, error)
	eventStore       *eventstore.Store
	reverseCache     ReverseCache
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

// ReverseCache is the subset of the dnscache.Cache surface the DNS
// proxy needs. The interface lives here so the proxy can populate
// the cache without importing dnscache, which would otherwise pull
// in the netlink-adjacent firewall set update path through reload
// wiring.
//
// Implementations must be safe for concurrent use. The proxy calls
// [ReverseCache.Add] from each handler goroutine.
type ReverseCache interface {
	// Add records that ip resolved to qname for at least ttl. The
	// proxy passes [netip.Addr.Unmap]'d keys, so implementations may
	// assume the canonical 4-byte form for v4 addresses.
	Add(ip netip.Addr, qname string, ttl time.Duration)
}

// Option configures optional behavior of a [Proxy].
//
// The following options are available:
//
//   - [WithClientTimeout]
//   - [WithFQDNSetFunc]
//   - [WithVMMode]
//   - [WithEventStore]
//   - [WithReverseCache]
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

// WithEventStore wires the proxy to an [*eventstore.Store] so each
// terminal branch in handleQuery emits an [eventstore.Event]. A nil
// store disables emission (the data plane is never blocked). An
// [Option].
func WithEventStore(s *eventstore.Store) Option {
	return func(p *Proxy) {
		p.eventStore = s
	}
}

// WithReverseCache wires the proxy to a [ReverseCache]. The proxy
// populates it synchronously on every successful resolution, before
// the answer is written to the client. A nil cache disables
// population. An [Option].
func WithReverseCache(c ReverseCache) Option {
	return func(p *Proxy) {
		p.reverseCache = c
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
// Start serves UDP and TCP on one port. When listenAddr has the port
// 0, the kernel picks a port that is free for the IPv4 UDP socket.
// Another process can hold that port number for one of the other
// sockets of the proxy. Start then tries a different port, and it
// returns the bind error when 10 ports in a row are in use. The Addr
// field of the returned [Proxy] holds the address that Start bound.
// When listenAddr names a port and a socket of the proxy cannot bind
// it, Start returns the bind error.
//
// When cfg enables DNS logging to a file, Start opens that file, and
// [Proxy.Shutdown] closes it. Start closes its sockets and the file
// before it returns an error.
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
		listenTCP:     listenTCP,
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

	socks, err := p.listen(ctx, listenAddr)
	if err != nil {
		cancel()

		// The caller gets no Proxy to shut down, so close the DNS
		// log file here.
		if p.logFile != nil {
			closeErr := p.logFile.Close()
			if closeErr != nil {
				slog.WarnContext(ctx, "closing DNS log", slog.Any("err", closeErr))
			}
		}

		return nil, err
	}

	p.Addr = socks.udp4.LocalAddr().String()

	p.udp4 = &dns.Server{
		PacketConn: socks.udp4,
		Handler:    dns.HandlerFunc(p.handleUDPQuery),
	}

	p.tcp4 = &dns.Server{
		Listener: socks.tcp4,
		Handler:  dns.HandlerFunc(p.handleTCPQuery),
	}

	if socks.udp6 != nil {
		p.udp6 = &dns.Server{
			PacketConn: socks.udp6,
			Handler:    dns.HandlerFunc(p.handleUDPQuery),
		}

		p.tcp6 = &dns.Server{
			Listener: socks.tcp6,
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
				slog.DebugContext(ctx, "dns server exited", slog.Any("err", err))
			}
		}()
	}

	wg.Wait()

	return p, nil
}

// sockets holds the sockets that a [Proxy] serves, all bound to one
// port. The IPv6 sockets are nil when IPv6 is disabled.
type sockets struct {
	udp4 net.PacketConn
	tcp4 net.Listener
	udp6 net.PacketConn
	tcp6 net.Listener
}

// close closes every socket that s holds.
func (s *sockets) close(ctx context.Context) {
	for _, c := range []io.Closer{s.udp4, s.tcp4, s.udp6, s.tcp6} {
		if c == nil {
			continue
		}

		err := c.Close()
		if err != nil {
			slog.WarnContext(ctx, "closing listener", slog.Any("err", err))
		}
	}
}

// listen binds the sockets of the proxy on listenAddr.
//
// When listenAddr leaves the choice of the port to the kernel, the
// kernel picks a port that is free for the first socket, the IPv4 UDP
// socket. A socket of another process can hold the same port number
// for TCP or for IPv6. When a bind reports that the address is in use,
// listen closes the sockets that it bound and starts again. The kernel
// then picks a different port. After [bindAttempts] ports, listen
// returns the bind error. A listenAddr that names a port gets one
// attempt.
func (p *Proxy) listen(ctx context.Context, listenAddr string) (*sockets, error) {
	attempts := 1
	if kernelPicksPort(listenAddr) {
		attempts = bindAttempts
	}

	for attempt := 1; ; attempt++ {
		socks, err := p.bind(ctx, listenAddr)
		if err == nil {
			return socks, nil
		}

		if attempt == attempts || !errors.Is(err, syscall.EADDRINUSE) {
			return nil, err
		}

		slog.DebugContext(ctx, "dns proxy port is in use, trying another port",
			slog.Int("attempt", attempt),
			slog.Any("err", err),
		)
	}
}

// bind binds the IPv4 UDP socket on listenAddr, and then the other
// sockets of the proxy on the port of that socket. When a bind fails,
// bind closes the sockets that it bound.
func (p *Proxy) bind(ctx context.Context, listenAddr string) (*sockets, error) {
	lc := net.ListenConfig{}
	socks := &sockets{}

	var err error

	// UDP IPv4.
	socks.udp4, err = lc.ListenPacket(ctx, protoUDP, listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listening UDP %s: %w", listenAddr, err)
	}

	// Resolve actual address (port may be 0).
	udpAddr, ok := socks.udp4.LocalAddr().(*net.UDPAddr)
	if !ok {
		socks.close(ctx)

		return nil, fmt.Errorf("unexpected address type: %T", socks.udp4.LocalAddr())
	}

	// TCP IPv4 on the same port.
	socks.tcp4, err = p.listenTCP(ctx, &lc, udpAddr.String())
	if err != nil {
		socks.close(ctx)

		return nil, err
	}

	if p.ipv6Disabled {
		return socks, nil
	}

	// IPv6 listeners.
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

	socks.udp6, err = lc6.ListenPacket(ctx, protoUDP, addr6)
	if err != nil {
		socks.close(ctx)

		return nil, fmt.Errorf("listening UDP %s: %w", addr6, err)
	}

	socks.tcp6, err = p.listenTCP(ctx, &lc6, addr6)
	if err != nil {
		socks.close(ctx)

		return nil, err
	}

	return socks, nil
}

// listenTCP binds a TCP listener on addr with lc.
func listenTCP(ctx context.Context, lc *net.ListenConfig, addr string) (net.Listener, error) {
	ln, err := lc.Listen(ctx, protoTCP, addr)
	if err != nil {
		return nil, fmt.Errorf("listening TCP %s: %w", addr, err)
	}

	return ln, nil
}

// kernelPicksPort reports whether listenAddr leaves the choice of the
// port to the kernel, with the port 0 or with an empty port.
func kernelPicksPort(listenAddr string) bool {
	_, port, err := net.SplitHostPort(listenAddr)

	return err == nil && (port == "" || port == "0")
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

		p.emitDNS(eventstore.DecisionDeny, qname, eventstore.ReasonBlockedMode)

		err := w.WriteMsg(resp)
		if err != nil {
			slog.Warn("writing dns refusal", slog.Any("err", err))
		}

		return
	}

	// Allowlist mode: return NXDOMAIN for queries that don't match any
	// allowed domain. NXDOMAIN (not REFUSED) ensures stub resolvers like
	// nsncd fall back through the search domain list correctly.
	if p.filterMode == modeAllowlist && !p.domainAllowed(qname) {
		resp := new(dns.Msg)
		resp.SetRcode(r, dns.RcodeNameError)

		if p.logging {
			p.logger.Info("dns query blocked",
				slog.String("name", qname),
			)
		}

		p.emitDNS(eventstore.DecisionDeny, qname, eventstore.ReasonNotAllowlisted)

		err := w.WriteMsg(resp)
		if err != nil {
			slog.Warn("writing dns block response", slog.Any("err", err))
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

		p.emitDNS(eventstore.DecisionError, qname, eventstore.ReasonUpstream)

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

	p.emitDNS(eventstore.DecisionAllow, qname, "")

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

// emitDNS records a terminal-branch decision into the event store
// when one is configured. The early-return guard avoids the
// per-query [strings.TrimSuffix] allocation when stats is disabled
// (the default), since the trimmed name and the [eventstore.Event]
// struct are otherwise built only to be discarded.
func (p *Proxy) emitDNS(decision eventstore.Decision, qname string, reason eventstore.Reason) {
	if p.eventStore == nil {
		return
	}

	p.eventStore.Emit(eventstore.Event{
		Source:   eventstore.SourceDNS,
		Decision: decision,
		Domain:   strings.TrimSuffix(qname, "."),
		Protocol: eventstore.ProtocolDNS,
		Reason:   reason,
	})
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

	// Populate the reverse-attribution cache before mutating any
	// nftables set so a downstream consumer attributing logged
	// packets sees the qname for the workload's first SYN. This
	// runs synchronously on the handler goroutine, before WriteMsg
	// in handleQuery.
	if p.reverseCache != nil {
		for _, ip := range v4IPs {
			if a, ok := netip.AddrFromSlice(ip.To4()); ok {
				p.reverseCache.Add(a.Unmap(), qname, ttl)
			}
		}

		for _, ip := range v6IPs {
			if a, ok := netip.AddrFromSlice(ip.To16()); ok {
				p.reverseCache.Add(a.Unmap(), qname, ttl)
			}
		}
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
