package envoy

import (
	"fmt"
	"regexp"

	"go.jacobcolvin.com/terrarium/config"
)

// buildWildcardRBACFilter creates an RBAC network filter that
// restricts wildcard server_names matches to the correct depth,
// matching [CiliumNetworkPolicy] toFQDNs.matchPattern semantics.
// Single-star patterns ("*.example.com") are confined to one DNS
// label; double-star patterns ("**.example.com") allow arbitrary
// subdomain depth.
//
// Envoy's server_names uses suffix-based matching, so "*.example.com"
// matches arbitrarily deep subdomains like "a.b.example.com". Cilium
// confines "*" to a single DNS label. This filter is prepended to
// passthrough filter chains that contain wildcard patterns; it checks
// the TLS SNI (requested_server_name) against per-domain regexes
// (via [wildcardToSNIRegex]) and closes the connection if the SNI
// does not match.
//
// The RBAC action is ALLOW with one permission per wildcard domain.
// Multiple permissions are OR'd: the connection is allowed if the SNI
// matches any single permission. On mismatch, Envoy closes the
// connection -- there is no fallthrough to other filter chains because
// filter chain selection is already finalized by this point.
//
// [CiliumNetworkPolicy]: https://docs.cilium.io/en/stable/policy/language/#dns-based
func buildWildcardRBACFilter(wildcardDomains []string) filter {
	var permissions []rbacPermission
	for _, d := range wildcardDomains {
		permissions = append(permissions, rbacPermission{
			RequestedServerName: &stringMatch{
				SafeRegex: &safeRegex{Regex: wildcardToSNIRegex(d)},
			},
		})
	}

	return filter{
		Name: "envoy.filters.network.rbac",
		TypedConfig: rbacConfig{
			AtType: "type.googleapis.com/envoy.extensions.filters.network.rbac.v3.RBAC",
			Rules: rbacRules{
				Action: "ALLOW",
				Policies: map[string]rbacPolicy{
					"wildcard_depth": {
						Permissions: permissions,
						Principals:  []rbacPrincipal{{Any: true}},
					},
				},
			},
		},
	}
}

// buildWildcardHTTPRBACFilter creates an HTTP RBAC filter that
// restricts wildcard domain matches to the correct depth by checking
// the :authority pseudo-header. Single-star patterns ("*.example.com")
// are confined to one DNS label; double-star patterns
// ("**.example.com") allow arbitrary subdomain depth. This is the
// HTTP-layer equivalent of [buildWildcardRBACFilter] (which checks
// TLS SNI).
//
// Cilium enforces FQDN wildcard depth via its BPF identity system
// (DNS proxy regex -> identity allocation -> BPF map lookup), not at
// the Envoy layer. This RBAC approach is an architectural substitute
// that achieves equivalent filtering semantics within terrarium's
// Envoy-only architecture.
//
// Because the RBAC filter applies globally to the HCM (not per virtual
// host), the permissions must also allow exact domains through. Each
// wildcard gets a depth-enforcement regex (via [wildcardToHostRegex]);
// each exact domain gets a regex that matches the literal name with an
// optional port suffix. All permissions are OR'd.
func buildWildcardHTTPRBACFilter(wildcardDomains, exactDomains []string) filter {
	var permissions []rbacPermission

	for _, d := range wildcardDomains {
		permissions = append(permissions, rbacPermission{
			Header: &headerMatcher{
				Name: ":authority",
				StringMatch: &stringMatch{
					SafeRegex: &safeRegex{
						Regex: wildcardToHostRegex(d),
					},
				},
			},
		})
	}

	for _, d := range exactDomains {
		permissions = append(permissions, rbacPermission{
			Header: &headerMatcher{
				Name: ":authority",
				StringMatch: &stringMatch{
					SafeRegex: &safeRegex{
						Regex: `^` + regexp.QuoteMeta(d) + `(:\d+)?$`,
					},
				},
			},
		})
	}

	return filter{
		Name: "envoy.filters.http.rbac",
		TypedConfig: rbacConfig{
			AtType: "type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC",
			Rules: rbacRules{
				Action: "ALLOW",
				Policies: map[string]rbacPolicy{
					"wildcard_depth": {
						Permissions: permissions,
						Principals:  []rbacPrincipal{{Any: true}},
					},
				},
			},
		},
	}
}

func buildPassthroughFilterChain(
	upstreamPort int,
	statPrefix string,
	serverNames []string,
	accessLog []AccessLog,
	rbacFilter *filter,
) filterChain {
	var filters []filter
	if rbacFilter != nil {
		filters = append(filters, *rbacFilter)
	}

	filters = append(filters,
		filter{
			Name: "envoy.filters.network.sni_dynamic_forward_proxy",
			TypedConfig: sniFilterConfig{
				AtType:         "type.googleapis.com/envoy.extensions.filters.network.sni_dynamic_forward_proxy.v3.FilterConfig",
				PortValue:      upstreamPort,
				DNSCacheConfig: sharedDNSCacheConfig,
			},
		},
		filter{
			Name: "envoy.filters.network.tcp_proxy",
			TypedConfig: tcpProxyConfig{
				AtType:     "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
				StatPrefix: statPrefix,
				Cluster:    "dynamic_forward_proxy_cluster",
				AccessLog:  accessLog,
			},
		},
	)

	fc := filterChain{
		FilterChainMatch: &filterChainMatch{
			TransportProtocol: "tls",
			ServerNames:       serverNames,
		},
		Filters: filters,
	}

	return fc
}

func buildMITMFilterChain(
	rule config.ResolvedRule,
	accessLog []AccessLog,
	certsDir string,
	httpRBACFilter *filter,
) filterChain {
	sn := wildcardServerName(rule.Domain)
	certPath := fmt.Sprintf("%s/%s/cert.pem", certsDir, sn)
	keyPath := fmt.Sprintf("%s/%s/key.pem", certsDir, sn)

	vhosts, _, _ := buildHTTPVirtualHosts([]config.ResolvedRule{rule}, "mitm_forward_proxy_cluster")

	httpFilters := make([]filter, 0, 3)
	if httpRBACFilter != nil {
		httpFilters = append(httpFilters, *httpRBACFilter)
	}

	httpFilters = append(httpFilters,
		filter{
			Name: "envoy.filters.http.dynamic_forward_proxy",
			TypedConfig: httpDFPFilterConfig{
				AtType:         "type.googleapis.com/envoy.extensions.filters.http.dynamic_forward_proxy.v3.FilterConfig",
				DNSCacheConfig: sharedDNSCacheConfig,
			},
		},
		filter{
			Name: "envoy.filters.http.router",
			TypedConfig: typeOnly{
				AtType: "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router",
			},
		},
	)

	return filterChain{
		FilterChainMatch: &filterChainMatch{TransportProtocol: "tls", ServerNames: []string{sn}},
		TransportSocket: &transportSocket{
			Name: "envoy.transport_sockets.tls",
			TypedConfig: downstreamTlsContext{
				AtType: "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
				CommonTlsContext: commonTlsContext{
					TlsCertificates: []tlsCertificate{{
						CertificateChain: dataSource{Filename: certPath},
						PrivateKey:       dataSource{Filename: keyPath},
					}},
					// Advertise h2 and http/1.1 so HTTP/2 clients
					// don't fall back to HTTP/1.1 silently.
					// Note: mTLS passthrough is unsupported.
					AlpnProtocols: []string{"h2", "http/1.1"},
				},
			},
		},
		Filters: []filter{{
			Name: "envoy.filters.network.http_connection_manager",
			TypedConfig: httpConnManagerConfig{
				AtType:                       "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
				StatPrefix:                   "mitm_" + rule.Domain,
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
	}
}

// buildDefaultRejectFilterChain creates a filter chain that logs and
// immediately closes connections. Used as the default filter chain on
// TLS listeners to provide diagnostic output for connections without
// SNI instead of silently dropping them.
func buildDefaultRejectFilterChain(statPrefix string) filterChain {
	return filterChain{
		Filters: []filter{{
			Name: "envoy.filters.network.tcp_proxy",
			TypedConfig: tcpProxyConfig{
				AtType:     "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
				StatPrefix: statPrefix + "_no_sni",
				Cluster:    "missing_sni_blackhole",
				AccessLog: []AccessLog{{
					Name: "envoy.access_loggers.stderr",
					TypedConfig: stderrAccessLogConfig{
						AtType: "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StderrAccessLog",
						LogFormat: &substitutionFormatString{
							TextFormat: "missing_sni src=%DOWNSTREAM_REMOTE_ADDRESS% dst=%DOWNSTREAM_LOCAL_ADDRESS% %RESPONSE_FLAGS%\n",
						},
					},
				}},
			},
		}},
	}
}
