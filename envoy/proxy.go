package envoy

// Proxy-mode builders. Proxy mode runs Envoy as an explicit HTTP
// forward proxy on the host (Claude Code's sandbox httpProxyPort)
// instead of a transparent TPROXY/DNAT gateway inside a container.
//
// The front listener terminates CONNECT requests and tunnels their
// raw payload into internal listeners that reuse the container-mode
// enforcement chains: SNI passthrough for FQDN-only rules, TLS
// termination (MITM) plus L7 route matching for restricted rules, and
// Host-header virtual hosts for plain HTTP. Authorities outside the
// policy receive a 403 at the front listener; the internal chains
// remain the authoritative enforcement point (the upstream connection
// is derived from the SNI, not the CONNECT target, so a lying
// authority gains nothing).

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"go.jacobcolvin.com/terrarium/config"
)

// internalHTTPName is the shared name of the proxy-mode internal HTTP
// listener and the static cluster that targets it.
const internalHTTPName = "http_internal"

// internalTLSName returns the shared name of the proxy-mode internal
// TLS listener for port and the static cluster that targets it.
func internalTLSName(port int) string {
	return fmt.Sprintf("tls_internal_%d", port)
}

// ProxyMode selects the front listener's policy posture, mirroring
// the three config security modes.
type ProxyMode int

// Proxy modes.
const (
	// ProxyModeFiltered routes CONNECT and plain HTTP through the
	// policy's internal listeners and denies everything else.
	ProxyModeFiltered ProxyMode = iota

	// ProxyModeOpen tunnels CONNECT and forwards plain HTTP for any
	// authority directly through the dynamic forward proxy.
	ProxyModeOpen

	// ProxyModeBlocked returns 403 for every request.
	ProxyModeBlocked
)

// ProxyListenerParams configures [BuildProxyListener].
type ProxyListenerParams struct {
	// ConnectTLS maps each TLS policy port to the rule domains whose
	// CONNECT requests are tunneled into that port's internal TLS
	// listener. Domains may be exact names or wildcard patterns
	// ("*.example.com", "**.example.com"); depth enforcement happens
	// in the internal listener's RBAC chains.
	ConnectTLS map[int][]string

	// BindAddress is the IP address the listener binds.
	BindAddress string

	// HTTPDomains are the rule domains whose CONNECT-to-port-80
	// requests are decapsulated into the internal HTTP listener.
	HTTPDomains []string

	// AccessLog is the HCM access log configuration.
	AccessLog []AccessLog

	// Resolvers are explicit DNS resolver addresses for the dynamic
	// forward proxy cache. Empty means the host's system resolver.
	Resolvers []netip.AddrPort

	// Port is the TCP port the listener binds.
	Port int

	// Mode selects the policy posture.
	Mode ProxyMode
}

// BuildProxyListener creates the forward-proxy front listener: an
// HTTP connection manager that terminates CONNECT requests and routes
// them by authority, forwards plain absolute-form HTTP requests, and
// returns 403 for authorities outside the policy.
//
// CONNECT vhost domains carry an explicit port ("example.com:443")
// because Envoy matches CONNECT targets against the full
// authority. The HCM intentionally does not strip authority ports:
// the port picks the internal listener.
func BuildProxyListener(p ProxyListenerParams) Listener {
	var vhosts []virtualHost

	switch p.Mode {
	case ProxyModeOpen:
		vhosts = append(vhosts, buildOpenProxyVhost())

	case ProxyModeFiltered:
		vhosts = append(vhosts, buildFilteredProxyVhosts(p)...)
		vhosts = append(vhosts, buildDenyProxyVhost(len(p.HTTPDomains) > 0))

	case ProxyModeBlocked:
		vhosts = append(vhosts, buildDenyProxyVhost(false))
	}

	httpFilters := []filter{{
		Name: httpRouterFilterName,
		TypedConfig: typeOnly{
			AtType: httpRouterTypeURL,
		},
	}}

	// Only open mode routes to the dynamic forward proxy from the
	// front listener; filtered mode resolves upstreams inside the
	// internal listeners.
	if p.Mode == ProxyModeOpen {
		httpFilters = append([]filter{{
			Name: httpDFPFilterName,
			TypedConfig: httpDFPFilterConfig{
				AtType:         httpDFPFilterTypeURL,
				DNSCacheConfig: systemDNSCacheConfig(p.Resolvers),
			},
		}}, httpFilters...)
	}

	return Listener{
		Name: "proxy",
		Address: &address{SocketAddress: socketAddress{
			Address:   p.BindAddress,
			PortValue: p.Port,
		}},
		FilterChains: []filterChain{{
			Filters: []filter{{
				Name: hcmFilterName,
				TypedConfig: httpConnManagerConfig{
					AtType:            hcmTypeURL,
					StatPrefix:        "proxy",
					StreamIdleTimeout: streamIdleTimeout5m,
					NormalizePath:     boolPtr(true),
					UseRemoteAddress:  boolPtr(true),
					SkipXffAppend:     boolPtr(true),
					MergeSlashes:      true,
					RouteConfig: routeConfig{
						VirtualHosts: vhosts,
					},
					AccessLog: p.AccessLog,
					UpgradeConfigs: []upgradeConfig{
						{UpgradeType: upgradeTypeConnect},
						{UpgradeType: upgradeTypeWebsocket},
					},
					HTTPFilters: httpFilters,
				},
			}},
		}},
	}
}

// connectTerminationRoute returns a route that terminates CONNECT
// requests and streams their payload to cluster as raw TCP. No route
// timeout is set: Envoy exempts upgraded streams from the route
// timeout, and the HCM stream idle timeout reaps abandoned tunnels.
func connectTerminationRoute(cluster string) route {
	return route{
		Match: routeMatch{ConnectMatcher: &connectMatcher{}},
		Route: &routeAction{
			Cluster: cluster,
			UpgradeConfigs: []routeUpgradeConfig{{
				UpgradeType:   upgradeTypeConnect,
				ConnectConfig: &connectConfig{},
			}},
		},
	}
}

// denyRoutes returns the explicit 403 routes for plain requests and
// CONNECT requests. Both kinds are needed: prefix matches never match
// CONNECT (it has no path), and connect_matcher never matches plain
// requests.
func denyRoutes() []route {
	deny := directResponseAction{
		Status: 403,
		Body:   &dataSource{InlineString: accessDeniedBody},
	}

	return []route{
		{
			Match:          routeMatch{Prefix: "/"},
			DirectResponse: &deny,
		},
		{
			Match:          routeMatch{ConnectMatcher: &connectMatcher{}},
			DirectResponse: &deny,
		},
	}
}

// buildOpenProxyVhost returns the unrestricted catch-all vhost:
// CONNECT tunnels and plain HTTP both go straight through the dynamic
// forward proxy, which resolves the authority itself.
func buildOpenProxyVhost() virtualHost {
	openRoute := route{
		Match: routeMatch{Prefix: "/"},
		Route: &routeAction{
			Cluster:         dynamicForwardProxyCluster,
			AutoHostRewrite: true,
			Timeout:         routeTimeout1h,
		},
	}

	return virtualHost{
		Name:    "open",
		Domains: []string{"*"},
		Routes: []route{
			connectTerminationRoute(dynamicForwardProxyCluster),
			grpcRouteVariant(openRoute),
			openRoute,
		},
	}
}

// buildFilteredProxyVhosts returns the per-port CONNECT vhosts for
// filtered mode. Each TLS policy port gets one vhost matching the
// allowed authorities on that port, tunneling into the port's
// internal TLS listener. Port-80 domains tunnel into the internal
// HTTP listener and also accept plain HTTP with an explicit :80
// authority.
func buildFilteredProxyVhosts(p ProxyListenerParams) []virtualHost {
	var vhosts []virtualHost

	for _, port := range slices.Sorted(maps.Keys(p.ConnectTLS)) {
		domains := connectAuthorities(p.ConnectTLS[port], port)
		if len(domains) == 0 {
			continue
		}

		vhosts = append(vhosts, virtualHost{
			Name:    fmt.Sprintf("connect_tls_%d", port),
			Domains: domains,
			Routes: append(
				[]route{connectTerminationRoute(internalTLSName(port))},
				denyRoutes()...,
			),
		})
	}

	if len(p.HTTPDomains) > 0 {
		// This vhost matches the "host:80" authority form. The CONNECT
		// route handles HTTPS-to-port-80 tunnels; the forward route
		// handles a plain HTTP request that carries an explicit ":80"
		// authority. Bare-authority plain HTTP (the common case) is
		// caught by the deny vhost's forward route instead.
		forward := internalHTTPForwardRoute()
		vhosts = append(vhosts, virtualHost{
			Name:    "connect_http",
			Domains: connectAuthorities(p.HTTPDomains, 80),
			Routes: append(
				[]route{connectTerminationRoute(internalHTTPName), forward},
				denyRoutes()...,
			),
		})
	}

	return vhosts
}

// buildDenyProxyVhost returns the catch-all vhost that 403s
// everything not matched by a more specific vhost. When httpForward
// is true, plain HTTP requests whose authority has no port (or an
// explicit :80) are forwarded to the internal HTTP listener first;
// its Host-header vhosts enforce the policy.
func buildDenyProxyVhost(httpForward bool) virtualHost {
	var routes []route

	if httpForward {
		fwd := internalHTTPForwardRoute()
		// Constrain forwarding to default-port authorities. Plain
		// proxy requests to other ports would lose their port during
		// authority stripping in the internal listener and silently
		// target the wrong upstream, so they are denied instead
		// (mirroring container mode, which only handles port 80).
		fwd.Match.Headers = []headerMatcher{{
			Name: authorityHeader,
			StringMatch: &stringMatch{
				SafeRegex: &safeRegex{Regex: `^[^:]+(:80)?$`},
			},
		}}
		routes = append(routes, fwd)
	}

	return virtualHost{
		Name:    "deny",
		Domains: []string{"*"},
		Routes:  append(routes, denyRoutes()...),
	}
}

// internalHTTPForwardRoute returns a route that proxies a plain HTTP
// request to the internal HTTP listener, preserving the Host header
// for its virtual-host policy matching.
func internalHTTPForwardRoute() route {
	return route{
		Match: routeMatch{Prefix: "/"},
		Route: &routeAction{
			Cluster: internalHTTPName,
			Timeout: routeTimeout1h,
		},
	}
}

// connectAuthorities converts rule domains to CONNECT authority vhost
// entries for port: "example.com" becomes "example.com:443",
// "**.example.com" becomes the Envoy suffix pattern
// "*.example.com:443", and a bare "*" becomes "*:443" (any authority
// on that port). Duplicates collapse after wildcard normalization.
func connectAuthorities(domains []string, port int) []string {
	out := make([]string, 0, len(domains))

	for _, d := range domains {
		var entry string

		if d == "*" {
			entry = fmt.Sprintf("*:%d", port)
		} else {
			entry = fmt.Sprintf("%s:%d", WildcardServerName(d), port)
		}

		out = append(out, entry)
	}

	slices.Sort(out)

	return slices.Compact(out)
}

// BuildInternalTLSListener creates the proxy-mode internal listener
// that enforces TLS policy for one port. It receives decapsulated
// CONNECT payloads from the front listener and applies the same SNI
// passthrough, wildcard RBAC, and MITM filter chains as the
// container-mode [BuildTLSListener]; upstream resolution uses the
// SNI, so the CONNECT authority cannot redirect allowed traffic.
func BuildInternalTLSListener(
	port int,
	rules []config.ResolvedRule,
	open bool,
	tcpAL, httpAL []AccessLog,
	certsDir string,
	resolvers []netip.AddrPort,
) Listener {
	name := internalTLSName(port)

	chains, defaultChain := buildTLSFilterChains(
		port, name, rules, open, tcpAL, httpAL, certsDir, systemDNSCacheConfig(resolvers),
	)

	return Listener{
		Name:               name,
		InternalListener:   &internalListenerOpts{},
		DefaultFilterChain: &defaultChain,
		ListenerFilters:    []NamedTyped{tlsInspectorListenerFilter()},
		FilterChains:       chains,
	}
}

// BuildInternalHTTPListener creates the proxy-mode internal listener
// that enforces plain-HTTP policy via Host-header virtual hosts, the
// same chains as the container-mode [BuildHTTPForwardListener]. It
// receives decapsulated CONNECT-to-port-80 payloads and proxied
// absolute-form requests from the front listener. Unmatched hosts
// receive an explicit 403.
func BuildInternalHTTPListener(
	rules []config.ResolvedRule,
	open bool,
	accessLog []AccessLog,
	resolvers []netip.AddrPort,
) Listener {
	hcm := buildHTTPForwardHCM(
		internalHTTPName, rules, open, true, accessLog, systemDNSCacheConfig(resolvers),
	)

	return Listener{
		Name:             internalHTTPName,
		InternalListener: &internalListenerOpts{},
		FilterChains:     []filterChain{{Filters: []filter{hcm}}},
	}
}

// BuildProxyClusters creates the cluster set for a proxy-mode
// bootstrap: the blackhole and internal-listener clusters the
// enforcement listeners need, plus dynamic forward proxy clusters
// using the system resolver (or explicit resolvers). The caBundlePath
// supplies upstream trust for the MITM cluster's re-encrypted
// connections; when rules contain L7 restrictions it must be
// non-empty, otherwise [ErrMITMCABundleMissing] is returned.
func BuildProxyClusters(
	rules []config.ResolvedRule,
	tlsPorts []int,
	httpInternal, open bool,
	caBundlePath string,
	resolvers []netip.AddrPort,
) ([]cluster, error) {
	dnsCache := systemDNSCacheConfig(resolvers)

	var clusters []cluster

	if len(tlsPorts) > 0 {
		// Static cluster with no endpoints backing the TLS default
		// reject chains; see [MissingSNIBlackholeCluster].
		clusters = append(clusters, cluster{
			Name:           MissingSNIBlackholeCluster,
			ConnectTimeout: "1s",
			Type:           clusterTypeStatic,
			LBPolicy:       lbPolicyRoundRobin,
		})
	}

	if len(rules) > 0 || open || httpInternal {
		clusters = append(clusters, buildDFPCluster(dnsCache))
	}

	if hasMITMRules(rules) {
		mitm, err := buildMITMCluster(caBundlePath, dnsCache)
		if err != nil {
			return nil, fmt.Errorf("building MITM cluster: %w", err)
		}

		clusters = append(clusters, mitm)
	}

	for _, p := range tlsPorts {
		clusters = append(clusters, buildInternalListenerCluster(internalTLSName(p)))
	}

	if httpInternal {
		clusters = append(clusters, buildInternalListenerCluster(internalHTTPName))
	}

	return clusters, nil
}

// buildInternalListenerCluster creates a static cluster whose single
// endpoint is the internal listener of the same name.
func buildInternalListenerCluster(name string) cluster {
	return cluster{
		Name:           name,
		ConnectTimeout: "1s",
		Type:           clusterTypeStatic,
		LBPolicy:       lbPolicyRoundRobin,
		LoadAssignment: &loadAssignment{
			ClusterName: name,
			Endpoints: []endpoint{{
				LBEndpoints: []lbEndpoint{{
					Endpoint: endpointAddress{
						Address: address{
							EnvoyInternalAddress: &envoyInternalAddress{
								ServerListenerName: name,
							},
						},
					},
				}},
			}},
		},
	}
}
