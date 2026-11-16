package envoy

import (
	"fmt"
	"regexp"
	"strconv"

	"go.jacobcolvin.com/terrarium/config"
)

// wildcardRBACPolicy names the RBAC policy (and stat prefix) that
// confines wildcard domain matches to the correct label depth in
// [buildWildcardRBACFilter] and [buildWildcardHTTPRBACFilter].
const wildcardRBACPolicy = "wildcard_depth"

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
// (via [WildcardToSNIRegex]) and closes the connection if the SNI
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
				SafeRegex: &safeRegex{Regex: WildcardToSNIRegex(d)},
			},
		})
	}

	return filter{
		Name: "envoy.filters.network.rbac",
		TypedConfig: rbacConfig{
			AtType:     "type.googleapis.com/envoy.extensions.filters.network.rbac.v3.RBAC",
			StatPrefix: wildcardRBACPolicy,
			Rules: rbacRules{
				Action: "ALLOW",
				Policies: map[string]rbacPolicy{
					wildcardRBACPolicy: {
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
// wildcard gets a depth-enforcement regex (via [WildcardToHostRegex]);
// each exact domain gets a regex that matches the literal name with an
// optional port suffix. All permissions are OR'd.
func buildWildcardHTTPRBACFilter(wildcardDomains, exactDomains []string) filter {
	var permissions []rbacPermission

	for _, d := range wildcardDomains {
		permissions = append(permissions, rbacPermission{
			Header: &headerMatcher{
				Name: authorityHeader,
				StringMatch: &stringMatch{
					SafeRegex: &safeRegex{
						Regex: WildcardToHostRegex(d),
					},
				},
			},
		})
	}

	for _, d := range exactDomains {
		permissions = append(permissions, rbacPermission{
			Header: &headerMatcher{
				Name: authorityHeader,
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
					wildcardRBACPolicy: {
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
	dnsCache dnsCacheConfig,
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
				DNSCacheConfig: dnsCache,
			},
		},
		filter{
			Name: tcpProxyFilterName,
			TypedConfig: tcpProxyConfig{
				AtType:     tcpProxyTypeURL,
				StatPrefix: statPrefix,
				Cluster:    dynamicForwardProxyCluster,
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

// mitmFilterChainPrefix is the prefix of the name of each MITM filter
// chain, see [mitmFilterChainName].
const mitmFilterChainPrefix = "mitm_"

// mitmFilterChainName returns the name of the MITM filter chain for
// the server name sn. The server names of the chains of a listener
// differ, so the names differ too.
func mitmFilterChainName(sn string) string {
	return mitmFilterChainPrefix + sn
}

// buildMITMFilterChain builds the filter chain that terminates TLS for
// the domain of rule and matches each decrypted request against the
// HTTP rules of rule.
//
// The connection manager removes the port and the trailing dot of the
// host from the Host header of each request before it matches the
// header against the virtual host of the domain. A request for
// "example.com." then matches the rule for "example.com".
//
// The upstream receives the host without the dot. When upstreamPort is
// 443, the upstream receives the host without a port, because 443 is
// the default port of the "https" scheme. For every other port, the
// routes append upstreamPort to the host, see [appendHostPort]. The
// upstream of a request for "https://example.com:8443/" then receives
// the Host header "example.com:8443", which RFC 9110 section 7.2
// requires. Some upstreams compare the header as text, such as an
// upstream that checks a request signature that covers the header.
//
// The chain sends each request that a route forwards to upstreamPort
// of the host that the Host header names. Two parts of the chain carry
// upstreamPort. An HTTP filter stores upstreamPort under the key
// "envoy.upstream.dynamic_port" in the filter state of each request.
// The dynamic forward proxy filter then resolves the host for
// upstreamPort, and the dynamic forward proxy cluster connects to that
// port.
//
// When upstreamPort is not 443, the routes also put upstreamPort into
// the Host header that the dynamic forward proxy cluster reads. The
// header and the filter state then name the same port. When
// upstreamPort is 443, the Host header has no port, and 443 is the
// default port of the TLS cluster of the routes. The connection manager removes the port
// that the client put in the Host header, so that port never selects
// the port of the upstream.
//
// The connection manager serves HTTP/1.0 requests, and the virtual
// host applies the same HTTP rules to the requests of every HTTP
// version. An HTTP/1.0 request without a Host header names no host to
// match, so Envoy answers it with status 400.
//
// When a headerMatches entry of rule has a value, the first HTTP
// filter of the chain is the filter of [headerValueFilter]. That
// filter stores the header values that the routes compare.
//
// The access loggers of the connection manager are accessLog and, when
// a headerMatches entry of rule has the LOG mismatch action, the logger
// of [withMismatchAccessLog].
//
// The chain has the name that [mitmFilterChainName] returns for the
// domain of rule.
func buildMITMFilterChain(
	rule config.ResolvedRule,
	upstreamPort int,
	accessLog []AccessLog,
	certsDir string,
	httpRBACFilter *filter,
	dnsCache dnsCacheConfig,
) filterChain {
	sn := WildcardServerName(rule.Domain)
	certPath := fmt.Sprintf("%s/%s/cert.pem", certsDir, sn)
	keyPath := fmt.Sprintf("%s/%s/key.pem", certsDir, sn)

	vhosts, _, _ := buildHTTPVirtualHosts([]config.ResolvedRule{rule}, mitmForwardProxyCluster)
	appendHostPort(vhosts, upstreamPort)

	httpFilters := make([]filter, 0, 5)

	// The filter clears the route of the request, so it comes before
	// every HTTP filter that reads the route.
	valueFilter, stored := headerValueFilter([]config.ResolvedRule{rule})
	if stored {
		httpFilters = append(httpFilters, valueFilter)
	}

	if httpRBACFilter != nil {
		httpFilters = append(httpFilters, *httpRBACFilter)
	}

	httpFilters = append(httpFilters,
		filter{
			Name: httpSetFilterStateFilterName,
			TypedConfig: setFilterStateConfig{
				AtType: httpSetFilterStateTypeURL,
				OnRequestHeaders: []filterStateValue{{
					ObjectKey: dynamicPortFilterStateKey,
					FormatString: substitutionFormatString{
						TextFormatSource: &dataSource{InlineString: strconv.Itoa(upstreamPort)},
					},
				}},
			},
		},
		filter{
			Name: httpDFPFilterName,
			TypedConfig: httpDFPFilterConfig{
				AtType:                          httpDFPFilterTypeURL,
				DNSCacheConfig:                  dnsCache,
				AllowDynamicHostFromFilterState: true,
			},
		},
		filter{
			Name: httpRouterFilterName,
			TypedConfig: typeOnly{
				AtType: httpRouterTypeURL,
			},
		},
	)

	return filterChain{
		Name:             mitmFilterChainName(sn),
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
			Name: hcmFilterName,
			TypedConfig: httpConnManagerConfig{
				AtType:                       hcmTypeURL,
				StatPrefix:                   "mitm_" + rule.Domain,
				StreamIdleTimeout:            streamIdleTimeout5m,
				NormalizePath:                boolPtr(true),
				UseRemoteAddress:             boolPtr(true),
				SkipXffAppend:                boolPtr(true),
				HTTPProtocolOptions:          &http1ProtocolOptions{AcceptHTTP10: true},
				MergeSlashes:                 true,
				StripAnyHostPort:             true,
				StripTrailingHostDot:         true,
				PathWithEscapedSlashesAction: "UNESCAPE_AND_REDIRECT",
				RouteConfig: routeConfig{
					VirtualHosts: vhosts,
				},
				AccessLog:      withMismatchAccessLog(accessLog, vhosts, stored),
				UpgradeConfigs: []upgradeConfig{{UpgradeType: upgradeTypeWebsocket}},
				HTTPFilters:    httpFilters,
			},
		}},
	}
}

// appendHostPort makes each route of vhosts that forwards a request
// append port to the Host header of the request. It changes nothing
// when port is [defaultHTTPSPort], because a Host header without a port
// names that port.
//
// The connection manager of a MITM filter chain removes the port from
// the Host header, so every request reaches the routes without a port.
// The upstream therefore receives port, whatever port the Host header
// of the client named. The router rewrites the header after the route
// matchers and the HTTP filters ran, so they see the host without the
// port.
//
// The router also stores the Host header that it replaced, which is the
// host without the port, in the "x-envoy-original-host" header of the
// request to the upstream.
func appendHostPort(vhosts []virtualHost, port int) {
	if port == defaultHTTPSPort {
		return
	}

	rewrite := "%REQ(:AUTHORITY)%:" + strconv.Itoa(port)

	for _, vh := range vhosts {
		for i := range vh.Routes {
			if action := vh.Routes[i].Route; action != nil {
				action.HostRewrite = rewrite
			}
		}
	}
}

// buildDefaultRejectFilterChain creates a filter chain that logs and
// immediately closes connections. Used as the default filter chain on
// TLS listeners, which handles each connection without SNI and each
// connection whose SNI matches no other chain. The chain always writes
// a diagnostic line to stderr instead of silently dropping the
// connection. It also logs the connection to each access logger of
// accessLog. Each TCP gRPC access logger adds [SNIRejectTag], so the
// stats store records the connection as a denial.
func buildDefaultRejectFilterChain(statPrefix string, accessLog []AccessLog) filterChain {
	return filterChain{
		Filters: []filter{{
			Name: tcpProxyFilterName,
			TypedConfig: tcpProxyConfig{
				AtType:     tcpProxyTypeURL,
				StatPrefix: statPrefix + "_no_sni",
				Cluster:    MissingSNIBlackholeCluster,
				AccessLog: append([]AccessLog{{
					Name: "envoy.access_loggers.stderr",
					TypedConfig: stderrAccessLogConfig{
						AtType: "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StderrAccessLog",
						LogFormat: &substitutionFormatString{
							TextFormatSource: &dataSource{
								InlineString: "missing_sni src=%DOWNSTREAM_REMOTE_ADDRESS% dst=%DOWNSTREAM_LOCAL_ADDRESS% %RESPONSE_FLAGS%\n",
							},
						},
					},
				}}, withSNIRejectTag(accessLog)...),
			},
		}},
	}
}
