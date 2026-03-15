package envoy

import (
	"slices"
	"strings"

	"go.jacobcolvin.com/terrarium/config"
)

// BuildTLSListener creates a TLS listener that matches connections by
// SNI, with passthrough, wildcard RBAC, and MITM filter chains.
func BuildTLSListener(
	name string,
	listenPort, upstreamPort int,
	statPrefix string,
	rules []config.ResolvedRule,
	open bool,
	accessLog []AccessLog,
	certsDir string,
) Listener {
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
		if strings.HasPrefix(d, "*.") || strings.HasPrefix(d, "**.") {
			wildcardDomains = append(wildcardDomains, d)
		} else {
			exactDomains = append(exactDomains, d)
		}
	}

	var chains []filterChain
	if len(exactDomains) > 0 {
		chains = append(chains, buildPassthroughFilterChain(upstreamPort, statPrefix, exactDomains, accessLog, nil))
	}

	if len(wildcardDomains) > 0 {
		rbac := buildWildcardRBACFilter(wildcardDomains)

		envoyNames := make([]string, len(wildcardDomains))
		for i, d := range wildcardDomains {
			envoyNames[i] = wildcardServerName(d)
		}

		chains = append(
			chains,
			buildPassthroughFilterChain(upstreamPort, statPrefix+"_wildcard", envoyNames, accessLog, &rbac),
		)
	}

	for _, r := range mitmRules {
		chains = append(chains, buildMITMFilterChain(r, accessLog, certsDir))
	}

	// Open ports get a catch-all passthrough chain (no SNI restriction).
	if open {
		chains = append(chains, buildPassthroughFilterChain(upstreamPort, statPrefix+"_open", nil, accessLog, nil))
	}

	// Default filter chain catches connections without SNI (e.g., TLS
	// by IP address). Without this, Envoy silently drops the connection
	// with no log entry, making diagnosis difficult (ISSUE-34). The
	// access log always fires (regardless of the logging flag) since
	// missing-SNI connections indicate a configuration or client issue
	// that should be visible.
	defaultChain := buildDefaultRejectFilterChain(statPrefix)

	return Listener{
		Name: name,
		Address: address{SocketAddress: socketAddress{
			Address: "127.0.0.1", PortValue: listenPort,
		}},
		DefaultFilterChain: &defaultChain,
		ListenerFilters: []NamedTyped{{
			Name: "envoy.filters.listener.tls_inspector",
			TypedConfig: typeOnly{
				AtType: "type.googleapis.com/envoy.extensions.filters.listener.tls_inspector.v3.TlsInspector",
			},
		}},
		FilterChains: chains,
	}
}

// BuildHTTPForwardListener creates an HTTP listener that forwards
// requests based on Host header virtual host matching.
func BuildHTTPForwardListener(rules []config.ResolvedRule, open bool, accessLog []AccessLog) Listener {
	vhosts, wildcardDomains, exactDomains := buildHTTPVirtualHosts(rules, "dynamic_forward_proxy_cluster")

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
				Cluster:         "dynamic_forward_proxy_cluster",
				AutoHostRewrite: true,
				Timeout:         "3600s",
			},
		}
		vhosts = append(vhosts, virtualHost{
			Name:    "open",
			Domains: []string{"*"},
			Routes:  []route{grpcRouteVariant(openRoute), openRoute},
		})
	}

	// Build the HTTP filter chain. When wildcard domains are present
	// and the listener is not fully open and there is no catch-all
	// vhost, prepend an RBAC filter that enforces single-label depth
	// on the :authority header.
	httpFilters := []filter{
		{
			Name: "envoy.filters.http.dynamic_forward_proxy",
			TypedConfig: httpDFPFilterConfig{
				AtType:         "type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig",
				DNSCacheConfig: sharedDNSCacheConfig,
			},
		},
		{
			Name: "envoy.filters.http.router",
			TypedConfig: typeOnly{
				AtType: "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
			},
		},
	}

	if len(wildcardDomains) > 0 && !open && !hasCatchAll {
		rbacFilter := buildWildcardHTTPRBACFilter(wildcardDomains, exactDomains)
		httpFilters = append([]filter{rbacFilter}, httpFilters...)
	}

	return Listener{
		Name: "http_forward",
		Address: address{SocketAddress: socketAddress{
			Address: "127.0.0.1", PortValue: 15080,
		}},
		FilterChains: []filterChain{{
			Filters: []filter{{
				Name: "envoy.filters.network.http_connection_manager",
				TypedConfig: httpConnManagerConfig{
					AtType:                       "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
					StatPrefix:                   "http_forward",
					StreamIdleTimeout:            "300s",
					NormalizePath:                boolPtr(true),
					UseRemoteAddress:             boolPtr(true),
					SkipXffAppend:                boolPtr(true),
					MergeSlashes:                 true,
					PathWithEscapedSlashesAction: "UNESCAPE_AND_REDIRECT",
					RouteConfig: routeConfig{
						VirtualHosts: vhosts,
					},
					AccessLog:      accessLog,
					UpgradeConfigs: []upgradeConfig{{UpgradeType: "websocket"}},
					HTTPFilters:    httpFilters,
				},
			}},
		}},
	}
}

// BuildTCPForwardListener creates a plain TCP proxy listener that
// forwards all connections to the named cluster.
func BuildTCPForwardListener(
	name string,
	listenPort int,
	clusterName string,
	accessLog []AccessLog,
) Listener {
	return Listener{
		Name: name,
		Address: address{SocketAddress: socketAddress{
			Address: "127.0.0.1", PortValue: listenPort,
		}},
		FilterChains: []filterChain{{
			Filters: []filter{{
				Name: "envoy.filters.network.tcp_proxy",
				TypedConfig: tcpProxyConfig{
					AtType:     "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
					StatPrefix: name,
					Cluster:    clusterName,
					AccessLog:  accessLog,
				},
			}},
		}},
	}
}
