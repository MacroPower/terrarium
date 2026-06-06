package envoy

import (
	"fmt"
	"slices"
	"time"

	"go.jacobcolvin.com/terrarium/config"
)

const (
	// loopbackAddr is the default listener bind address for
	// container mode (non-transparent) listeners.
	loopbackAddr = "127.0.0.1"

	// ipv4AnyAddr is the wildcard IPv4 address for VM mode
	// transparent listeners. TPROXY requires AF_INET sockets
	// because the kernel's nf_tproxy_get_sock_v4 only searches
	// the IPv4 socket hash; dual-stack AF_INET6 sockets are
	// invisible to it.
	ipv4AnyAddr = "0.0.0.0"

	// ipv6AnyAddr is the wildcard IPv6 address, used as an
	// additional bind address alongside [ipv4AnyAddr] for
	// transparent listeners so IPv6 TPROXY can find the socket.
	ipv6AnyAddr = "::"
)

// listenSocketAddr returns the primary socket address for a listener.
// When transparent is true, the address is 0.0.0.0 (IPv4 wildcard)
// so the kernel's TPROXY IPv4 socket lookup can find the socket.
// Callers should also add an IPv6 additional address via
// [listenAdditionalAddrs] for IPv6 TPROXY support.
func listenSocketAddr(transparent bool, port int) socketAddress {
	if transparent {
		return socketAddress{
			Address:   ipv4AnyAddr,
			PortValue: port,
		}
	}

	return socketAddress{
		Address:   loopbackAddr,
		PortValue: port,
	}
}

// listenAdditionalAddrs returns additional addresses for transparent
// listeners: an IPv6 wildcard socket so IPv6 TPROXY dispatch rules
// can find the listener. Returns nil for non-transparent listeners.
func listenAdditionalAddrs(transparent bool, port int) []additionalAddr {
	if !transparent {
		return nil
	}

	return []additionalAddr{{
		Address: address{SocketAddress: socketAddress{
			Address:   ipv6AnyAddr,
			PortValue: port,
		}},
	}}
}

// BuildTLSListener creates a TLS listener that matches connections by
// SNI, with passthrough, wildcard RBAC, and MITM filter chains. When
// transparent is true, the listener binds to [::] (dual-stack) with
// IP_TRANSPARENT for TPROXY-delivered traffic in VM mode.
//
// tcpAL is the access log slice for the TCP-level chains (passthrough
// and wildcard passthrough); httpAL is the access log slice for the
// HCM-based MITM chain. Pass distinct slices when stats is enabled
// so receivers can tell passthrough events from MITM events.
func BuildTLSListener(
	name string,
	listenPort, upstreamPort int,
	statPrefix string,
	rules []config.ResolvedRule,
	open bool,
	tcpAL, httpAL []AccessLog,
	certsDir string,
	transparent bool,
) Listener {
	chains, defaultChain := buildTLSFilterChains(
		upstreamPort, statPrefix, rules, open, tcpAL, httpAL, certsDir, sharedDNSCacheConfig,
	)

	return Listener{
		Name:                name,
		Address:             &address{SocketAddress: listenSocketAddr(transparent, listenPort)},
		AdditionalAddresses: listenAdditionalAddrs(transparent, listenPort),
		Transparent:         transparent,
		DefaultFilterChain:  &defaultChain,
		ListenerFilters:     []NamedTyped{tlsInspectorListenerFilter()},
		FilterChains:        chains,
	}
}

// buildTLSFilterChains builds the SNI-matched filter chains shared by
// the container-mode TLS listener ([BuildTLSListener]) and the
// proxy-mode internal TLS listener ([BuildInternalTLSListener]):
// passthrough chains for SNI-only domains, wildcard chains with RBAC
// depth enforcement, MITM chains for L7-restricted rules, an optional
// open catch-all, and the default reject chain for connections
// without SNI.
func buildTLSFilterChains(
	upstreamPort int,
	statPrefix string,
	rules []config.ResolvedRule,
	open bool,
	tcpAL, httpAL []AccessLog,
	certsDir string,
	dnsCache dnsCacheConfig,
) ([]filterChain, filterChain) {
	var (
		passthroughDomains []string
		mitmRules          []config.ResolvedRule
	)

	for _, r := range rules {
		if r.IsRestricted() && certsDir != "" {
			mitmRules = append(mitmRules, r)
		} else {
			passthroughDomains = append(passthroughDomains, r.Domain)
		}
	}

	// Bare wildcard "*" matches all FQDNs. Envoy does not support "*"
	// in server_names (FilterChainMatch) -- the docs say to omit
	// server_names for catch-all matching. Convert to an unrestricted
	// passthrough chain (no SNI filter), same as the open-port path.
	if slices.Contains(passthroughDomains, "*") {
		passthroughDomains = slices.DeleteFunc(passthroughDomains, func(s string) bool {
			return s == "*"
		})
		open = true
	}

	// Wildcard domains ("*.example.com" or "**.example.com") are placed
	// in a separate filter chain with an RBAC filter that enforces the
	// correct wildcard depth (single-label for *, multi-label for **),
	// matching CiliumNetworkPolicy semantics. Without this, Envoy's
	// suffix-based server_names matching would allow arbitrarily deep
	// subdomains for single-star patterns like "*.example.com".
	var exactDomains, wildcardDomains []string

	for _, d := range passthroughDomains {
		if IsWildcardDomain(d) {
			wildcardDomains = append(wildcardDomains, d)
		} else {
			exactDomains = append(exactDomains, d)
		}
	}

	var chains []filterChain

	if len(exactDomains) > 0 {
		chains = append(chains, buildPassthroughFilterChain(
			upstreamPort, statPrefix, exactDomains, tcpAL, nil, dnsCache))
	}

	if len(wildcardDomains) > 0 {
		rbac := buildWildcardRBACFilter(wildcardDomains)

		envoyNames := make([]string, len(wildcardDomains))
		for i, d := range wildcardDomains {
			envoyNames[i] = WildcardServerName(d)
		}

		chains = append(chains, buildPassthroughFilterChain(
			upstreamPort, statPrefix+"_wildcard", envoyNames, tcpAL, &rbac, dnsCache))
	}

	for _, r := range mitmRules {
		var httpRBAC *filter

		if IsWildcardDomain(r.Domain) {
			f := buildWildcardHTTPRBACFilter([]string{r.Domain}, nil)
			httpRBAC = &f
		}

		chains = append(chains, buildMITMFilterChain(r, httpAL, certsDir, httpRBAC, dnsCache))
	}

	// Open ports get a catch-all passthrough chain (no SNI restriction).
	if open {
		chains = append(chains, buildPassthroughFilterChain(
			upstreamPort, statPrefix+"_open", nil, tcpAL, nil, dnsCache))
	}

	// Default filter chain catches connections without SNI (e.g., TLS
	// by IP address). Without this, Envoy silently drops the connection
	// with no log entry, making diagnosis difficult (ISSUE-34). The
	// access log always fires (regardless of the logging flag) since
	// missing-SNI connections indicate a configuration or client issue
	// that should be visible.
	return chains, buildDefaultRejectFilterChain(statPrefix)
}

// tlsInspectorListenerFilter returns the tls_inspector listener
// filter that extracts SNI for filter chain matching.
func tlsInspectorListenerFilter() NamedTyped {
	return NamedTyped{
		Name: "envoy.filters.listener.tls_inspector",
		TypedConfig: typeOnly{
			AtType: "type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector",
		},
	}
}

// BuildHTTPForwardListener creates an HTTP listener that forwards
// requests based on Host header virtual host matching. When
// transparent is true, the listener binds to [::] (dual-stack) with
// IP_TRANSPARENT for TPROXY-delivered traffic in VM mode.
func BuildHTTPForwardListener(
	rules []config.ResolvedRule, open bool, accessLog []AccessLog, transparent bool,
) Listener {
	hcm := buildHTTPForwardHCM(
		"http_forward", rules, open, false, accessLog, sharedDNSCacheConfig,
	)

	return Listener{
		Name:                "http_forward",
		Address:             &address{SocketAddress: listenSocketAddr(transparent, 15080)},
		AdditionalAddresses: listenAdditionalAddrs(transparent, 15080),
		Transparent:         transparent,
		FilterChains:        []filterChain{{Filters: []filter{hcm}}},
	}
}

// buildHTTPForwardHCM builds the host-header-routed HTTP connection
// manager shared by the container-mode HTTP listener
// ([BuildHTTPForwardListener]) and the proxy-mode internal HTTP
// listener ([BuildInternalHTTPListener]). When denyUnmatched is true,
// hosts outside the allowlist receive an explicit 403 instead of
// Envoy's default 404; proxy mode uses this so denied plain-HTTP
// requests are distinguishable from missing routes.
func buildHTTPForwardHCM(
	statPrefix string,
	rules []config.ResolvedRule,
	open, denyUnmatched bool,
	accessLog []AccessLog,
	dnsCache dnsCacheConfig,
) filter {
	vhosts, wildcardDomains, exactDomains := buildHTTPVirtualHosts(rules, dynamicForwardProxyCluster)

	// Envoy allows only one virtual host with Domains: ["*"] per route
	// config. When a bare wildcard rule already produced a "*" vhost,
	// adding the open catch-all would create a duplicate and cause Envoy
	// to reject the config.
	hasCatchAll := slices.ContainsFunc(vhosts, func(vh virtualHost) bool {
		return slices.Contains(vh.Domains, "*")
	})

	if open && !hasCatchAll {
		openRoute := route{
			Match: routeMatch{Prefix: "/"},
			Route: &routeAction{
				Cluster:         dynamicForwardProxyCluster,
				AutoHostRewrite: true,
				Timeout:         routeTimeout1h,
			},
		}
		vhosts = append(vhosts, virtualHost{
			Name:    "open",
			Domains: []string{"*"},
			Routes:  []route{grpcRouteVariant(openRoute), openRoute},
		})
	}

	if denyUnmatched && !open && !hasCatchAll {
		vhosts = append(vhosts, virtualHost{
			Name:    "deny",
			Domains: []string{"*"},
			Routes: []route{{
				Match: routeMatch{Prefix: "/"},
				DirectResponse: &directResponseAction{
					Status: 403,
					Body:   &dataSource{InlineString: accessDeniedBody},
				},
			}},
		})
	}

	// Build the HTTP filter chain. When wildcard domains are present
	// and the listener is not fully open and there is no catch-all
	// vhost, prepend an RBAC filter that enforces single-label depth
	// on the :authority header.
	httpFilters := []filter{
		{
			Name: httpDFPFilterName,
			TypedConfig: httpDFPFilterConfig{
				AtType:         httpDFPFilterTypeURL,
				DNSCacheConfig: dnsCache,
			},
		},
		{
			Name: httpRouterFilterName,
			TypedConfig: typeOnly{
				AtType: httpRouterTypeURL,
			},
		},
	}

	if len(wildcardDomains) > 0 && !open && !hasCatchAll {
		rbacFilter := buildWildcardHTTPRBACFilter(wildcardDomains, exactDomains)
		httpFilters = append([]filter{rbacFilter}, httpFilters...)
	}

	return filter{
		Name: hcmFilterName,
		TypedConfig: httpConnManagerConfig{
			AtType:                       hcmTypeURL,
			StatPrefix:                   statPrefix,
			StreamIdleTimeout:            streamIdleTimeout5m,
			NormalizePath:                boolPtr(true),
			UseRemoteAddress:             boolPtr(true),
			SkipXffAppend:                boolPtr(true),
			MergeSlashes:                 true,
			StripAnyHostPort:             true,
			PathWithEscapedSlashesAction: "UNESCAPE_AND_REDIRECT",
			RouteConfig: routeConfig{
				VirtualHosts: vhosts,
			},
			AccessLog:      accessLog,
			UpgradeConfigs: []upgradeConfig{{UpgradeType: upgradeTypeWebsocket}},
			HTTPFilters:    httpFilters,
		},
	}
}

// BuildTCPForwardListener creates a plain TCP proxy listener that
// forwards all connections to the named cluster. When transparent is
// true, the listener binds to [::] (dual-stack) with IP_TRANSPARENT
// for TPROXY-delivered traffic in VM mode.
func BuildTCPForwardListener(
	name string,
	listenPort int,
	clusterName string,
	accessLog []AccessLog,
	transparent bool,
) Listener {
	return Listener{
		Name:                name,
		Address:             &address{SocketAddress: listenSocketAddr(transparent, listenPort)},
		AdditionalAddresses: listenAdditionalAddrs(transparent, listenPort),
		Transparent:         transparent,
		FilterChains: []filterChain{{
			Filters: []filter{{
				Name: tcpProxyFilterName,
				TypedConfig: tcpProxyConfig{
					AtType:     tcpProxyTypeURL,
					StatPrefix: name,
					Cluster:    clusterName,
					AccessLog:  accessLog,
				},
			}},
		}},
	}
}

// BuildCatchAllTCPListener creates a TCP proxy [Listener] that handles
// traffic not matched by specialized per-port listeners. The
// original_dst listener filter recovers the real destination from
// conntrack for accurate access log output.
//
// When open is true (unrestricted mode), the listener forwards traffic
// to the original destination via the original_dst cluster. When false
// (filtered mode), it routes to missing_sni_blackhole which has no
// endpoints, immediately resetting the connection after logging. This
// prevents the catch-all from bypassing policy: NAT fires before the
// filter chain, so without Envoy-level rejection, non-policy-port
// traffic would be silently forwarded. When transparent is true, the
// listener binds to [::] (dual-stack) with IP_TRANSPARENT for
// TPROXY-delivered traffic in VM mode.
func BuildCatchAllTCPListener(listenPort int, open bool, accessLog []AccessLog, transparent bool) Listener {
	cluster := MissingSNIBlackholeCluster
	if open {
		cluster = originalDstCluster
	}

	return Listener{
		Name:                "catch_all_tcp",
		Address:             &address{SocketAddress: listenSocketAddr(transparent, listenPort)},
		AdditionalAddresses: listenAdditionalAddrs(transparent, listenPort),
		Transparent:         transparent,
		ListenerFilters: []NamedTyped{{
			Name: "envoy.filters.listener.original_dst",
			TypedConfig: typeOnly{
				AtType: "type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst",
			},
		}},
		FilterChains: []filterChain{{
			Filters: []filter{{
				Name: tcpProxyFilterName,
				TypedConfig: tcpProxyConfig{
					AtType:     tcpProxyTypeURL,
					StatPrefix: "catch_all_tcp",
					Cluster:    cluster,
					AccessLog:  accessLog,
				},
			}},
		}},
	}
}

// BuildCIDRCatchAllListener creates a TCP proxy [Listener] that
// handles CIDR-allowed traffic redirected by nftables. Unlike
// [BuildCatchAllTCPListener] (which rejects non-policy traffic via a
// blackhole cluster), this listener always forwards to the original
// destination via the original_dst cluster. The original_dst listener
// filter recovers the real destination from conntrack; the tls_inspector
// extracts SNI for access log visibility on TLS connections. When
// transparent is true, the listener binds to [::] (dual-stack) with
// IP_TRANSPARENT for TPROXY-delivered traffic in VM mode.
func BuildCIDRCatchAllListener(listenPort int, accessLog []AccessLog, transparent bool) Listener {
	return Listener{
		Name:                "cidr_catch_all",
		Address:             &address{SocketAddress: listenSocketAddr(transparent, listenPort)},
		AdditionalAddresses: listenAdditionalAddrs(transparent, listenPort),
		Transparent:         transparent,
		ListenerFilters: []NamedTyped{
			{
				Name: "envoy.filters.listener.original_dst",
				TypedConfig: typeOnly{
					AtType: "type.googleapis.com/envoy.extensions.filters.listener.original_dst.v3.OriginalDst",
				},
			},
			{
				Name: "envoy.filters.listener.tls_inspector",
				TypedConfig: typeOnly{
					AtType: "type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector",
				},
			},
		},
		FilterChains: []filterChain{{
			Filters: []filter{{
				Name: tcpProxyFilterName,
				TypedConfig: tcpProxyConfig{
					AtType:     tcpProxyTypeURL,
					StatPrefix: "cidr_catch_all",
					Cluster:    originalDstCluster,
					AccessLog:  accessLog,
				},
			}},
		}},
	}
}

// BuildCatchAllUDPListener creates a transparent UDP proxy [Listener]
// that handles UDP traffic intercepted via TPROXY. The listener binds
// to 0.0.0.0 (not 127.0.0.1) because TPROXY preserves the original
// destination IP; the transparent socket receives packets addressed to
// non-local IPs. The original_dst listener filter is NOT used (it is
// TCP-only); the ORIGINAL_DST cluster recovers the destination from
// the transparent socket address instead.
func BuildCatchAllUDPListener(port int, idleTimeout time.Duration, accessLog []AccessLog, transparent bool) Listener {
	// UDP listener is always transparent. Bind to 0.0.0.0 so the
	// kernel's IPv4 TPROXY socket lookup finds this socket. In VM
	// mode, an additional IPv6 address handles IPv6 TPROXY.
	udpSockAddr := socketAddress{
		Address:   "0.0.0.0",
		Protocol:  "UDP",
		PortValue: port,
	}

	var additionalAddrs []additionalAddr

	if transparent {
		additionalAddrs = []additionalAddr{{
			Address: address{SocketAddress: socketAddress{
				Address:   ipv6AnyAddr,
				Protocol:  "UDP",
				PortValue: port,
			}},
		}}
	}

	return Listener{
		Name:                "catch_all_udp",
		Address:             &address{SocketAddress: udpSockAddr},
		AdditionalAddresses: additionalAddrs,
		Transparent:         true,
		UDPListenerConfig: &udpListenerConfig{
			DownstreamSocketConfig: downstreamSocketConfig{
				PreferGRO: true,
			},
		},
		ListenerFilters: []NamedTyped{{
			Name: "envoy.filters.udp_listener.udp_proxy",
			TypedConfig: udpProxyConfig{
				AtType:     "type.googleapis.com/envoy.extensions.filters.udp.udp_proxy.v3.UdpProxyConfig",
				StatPrefix: "catch_all_udp",
				Matcher: udpRouteMatcher{
					OnNoMatch: udpRouteAction{
						Action: NamedTyped{
							Name: "route",
							TypedConfig: udpRoute{
								AtType:  "type.googleapis.com/envoy.extensions.filters.udp.udp_proxy.v3.Route",
								Cluster: originalDstCluster,
							},
						},
					},
				},
				IdleTimeout:               fmt.Sprintf("%.0fs", idleTimeout.Seconds()),
				AccessLog:                 accessLog,
				UsePerPacketLoadBalancing: true,
			},
		}},
	}
}
