package envoy_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoy"
)

// marshalYAML marshals v and returns the YAML string for content
// assertions, failing the test on error.
func marshalYAML(t *testing.T, v any) string {
	t.Helper()

	out, err := yaml.Marshal(v)
	require.NoError(t, err)

	return string(out)
}

func TestBuildProxyListener_Filtered(t *testing.T) {
	t.Parallel()

	l := envoy.BuildProxyListener(envoy.ProxyListenerParams{
		BindAddress: "127.0.0.1",
		Port:        8080,
		Mode:        envoy.ProxyModeFiltered,
		ConnectTLS: map[int][]string{
			443:  {"api.example.com", "**.wild.example.com", "api.example.com"},
			8443: {"alt.example.com"},
		},
		HTTPDomains: []string{"plain.example.com"},
	})

	assert.Equal(t, "proxy", l.Name)

	y := marshalYAML(t, l)

	// Bind address and port.
	assert.Contains(t, y, "address: 127.0.0.1")
	assert.Contains(t, y, "port_value: 8080")

	// CONNECT vhosts carry explicit authority ports; wildcards use
	// the TLS server-name form, and duplicates collapse.
	assert.Contains(t, y, "api.example.com:443")
	assert.Contains(t, y, "*.wild.example.com:443")
	assert.Contains(t, y, "alt.example.com:8443")
	assert.Contains(t, y, "plain.example.com:80")
	assert.Equal(t, 1, countOccurrences(y, "api.example.com:443"))

	// CONNECT termination routes into the internal listeners.
	assert.Contains(t, y, "connect_matcher:")
	assert.Contains(t, y, "connect_config:")
	assert.Contains(t, y, "cluster: tls_internal_443")
	assert.Contains(t, y, "cluster: tls_internal_8443")
	assert.Contains(t, y, "cluster: http_internal")

	// Default-deny vhost answers both request kinds with 403.
	assert.Contains(t, y, "name: deny")
	assert.Contains(t, y, "status: 403")

	// Plain-HTTP forwarding from the deny vhost is constrained to
	// default-port authorities.
	assert.Contains(t, y, "regex: ^[^:]+(:80)?$")

	// The authority port selects the internal listener, so the HCM
	// must not strip it.
	assert.NotContains(t, y, "strip_any_host_port")

	// CONNECT must be enabled at the HCM level.
	assert.Contains(t, y, "upgrade_type: CONNECT")

	// Filtered mode resolves upstreams in the internal listeners,
	// not at the front.
	assert.NotContains(t, y, "dynamic_forward_proxy")
}

func TestBuildProxyListener_Open(t *testing.T) {
	t.Parallel()

	l := envoy.BuildProxyListener(envoy.ProxyListenerParams{
		BindAddress: "127.0.0.1",
		Port:        8080,
		Mode:        envoy.ProxyModeOpen,
	})

	y := marshalYAML(t, l)

	// One catch-all vhost tunnels CONNECT and forwards plain HTTP
	// through the dynamic forward proxy.
	assert.Contains(t, y, `- "*"`)
	assert.Contains(t, y, "connect_matcher:")
	assert.Contains(t, y, "connect_config:")
	assert.Contains(t, y, "cluster: dynamic_forward_proxy_cluster")
	assert.Contains(t, y, "envoy.filters.http.dynamic_forward_proxy")

	// Open mode uses the system resolver: no explicit resolver list.
	assert.NotContains(t, y, "typed_dns_resolver_config")
	assert.NotContains(t, y, "port_value: 53")

	assert.NotContains(t, y, "status: 403")
}

func TestBuildProxyListener_Blocked(t *testing.T) {
	t.Parallel()

	l := envoy.BuildProxyListener(envoy.ProxyListenerParams{
		BindAddress: "127.0.0.1",
		Port:        8080,
		Mode:        envoy.ProxyModeBlocked,
	})

	y := marshalYAML(t, l)

	assert.Contains(t, y, "name: deny")
	assert.Contains(t, y, "status: 403")
	assert.NotContains(t, y, "dynamic_forward_proxy")
	assert.NotContains(t, y, "connect_config:")
}

// TestBuildProxyListener_NoReusePort checks that the front listener
// turns SO_REUSEPORT off in every mode. Envoy sets the option when the
// listener omits the field, and two Envoys then share one port.
func TestBuildProxyListener_NoReusePort(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mode envoy.ProxyMode
	}{
		"filtered": {mode: envoy.ProxyModeFiltered},
		"open":     {mode: envoy.ProxyModeOpen},
		"blocked":  {mode: envoy.ProxyModeBlocked},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			l := envoy.BuildProxyListener(envoy.ProxyListenerParams{
				BindAddress: "127.0.0.1",
				Port:        8080,
				Mode:        tt.mode,
			})

			require.NotNil(t, l.EnableReusePort)
			assert.False(t, *l.EnableReusePort)
			assert.Contains(t, marshalYAML(t, l), "enable_reuse_port: false")
		})
	}
}

// policyListeners returns one listener for each place where an HTTP
// connection manager matches the host of a request against the policy,
// keyed by a name for the place. Each listener has one HTTP connection
// manager.
func policyListeners() map[string]envoy.Listener {
	plain := []config.ResolvedRule{{Domain: "plain.example.com"}}
	restricted := []config.ResolvedRule{{
		Domain:    "restricted.example.com",
		HTTPRules: []config.ResolvedHTTPRule{{Path: "/v1/.*"}},
	}}

	front := func(mode envoy.ProxyMode) envoy.Listener {
		return envoy.BuildProxyListener(envoy.ProxyListenerParams{
			BindAddress: "127.0.0.1",
			Port:        8080,
			Mode:        mode,
			ConnectTLS:  map[int][]string{443: {"plain.example.com"}},
			HTTPDomains: []string{"plain.example.com"},
		})
	}

	return map[string]envoy.Listener{
		"proxy front listener, filtered": front(envoy.ProxyModeFiltered),
		"proxy front listener, open":     front(envoy.ProxyModeOpen),
		"proxy front listener, blocked":  front(envoy.ProxyModeBlocked),
		"proxy internal HTTP listener":   envoy.BuildInternalHTTPListener(plain, false, nil, nil),
		"proxy internal TLS listener with a MITM chain": envoy.BuildInternalTLSListener(
			443, restricted, false, nil, nil, "/certs", nil,
		),
		"container HTTP listener": envoy.BuildHTTPForwardListener(plain, false, nil, false),
		"container TLS listener with a MITM chain": envoy.BuildTLSListener(
			"tls_443", 15443, 443, "tls_443", restricted, false, nil, nil, "/certs", false,
		),
	}
}

// TestListeners_AcceptHTTP10 checks that every HTTP connection manager
// that matches the host of a request against the policy serves
// HTTP/1.0 requests. Without the option, Envoy answers each of them
// with status 426, also when the policy allows the host. Some clients
// send their CONNECT request in HTTP/1.0, and the requests inside a
// tunnel can have any HTTP version.
func TestListeners_AcceptHTTP10(t *testing.T) {
	t.Parallel()

	for name, l := range policyListeners() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			y := marshalYAML(t, l)

			assert.Equal(t, 1, countOccurrences(y, "envoy.filters.network.http_connection_manager\n"))
			assert.Equal(t, 1, countOccurrences(y, "accept_http_10: true"))
		})
	}
}

// TestListeners_StripTrailingHostDot checks that every HTTP connection
// manager that matches the host of a request against the policy
// removes the trailing dot of the host first. Without the option, a
// request for "example.com." does not match the rule for
// "example.com".
func TestListeners_StripTrailingHostDot(t *testing.T) {
	t.Parallel()

	for name, l := range policyListeners() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			y := marshalYAML(t, l)

			assert.Equal(t, 1, countOccurrences(y, "envoy.filters.network.http_connection_manager\n"))
			assert.Equal(t, 1, countOccurrences(y, "strip_trailing_host_dot: true"))
		})
	}
}

// TestListeners_KeepHost checks that no route of a listener sets
// auto_host_rewrite. With the option, Envoy replaces the Host header
// with the address of the upstream, which holds the port. The upstream
// of a request for "example.com" then receives "example.com:80".
func TestListeners_KeepHost(t *testing.T) {
	t.Parallel()

	for name, l := range policyListeners() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.NotContains(t, marshalYAML(t, l), "auto_host_rewrite")
		})
	}
}

// TestBuildProxyListener_Probe checks that the front listener answers
// the probe request for the probe token in every mode, and that its
// access loggers skip the probe request.
func TestBuildProxyListener_Probe(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mode envoy.ProxyMode
	}{
		"filtered": {mode: envoy.ProxyModeFiltered},
		"open":     {mode: envoy.ProxyModeOpen},
		"blocked":  {mode: envoy.ProxyModeBlocked},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			params := envoy.ProxyListenerParams{
				BindAddress: "127.0.0.1",
				Port:        8080,
				Mode:        tt.mode,
				AccessLog:   envoy.BuildHTTPGrpcAccessLog("proxy", 0, 0),
			}

			// Without a token, the listener has no probe vhost and
			// its access loggers have no filter.
			y := marshalYAML(t, envoy.BuildProxyListener(params))
			assert.NotContains(t, y, envoy.ProxyProbeHost)
			assert.NotContains(t, y, "filter:")

			params.ProbeToken = "probe-token"

			y = marshalYAML(t, envoy.BuildProxyListener(params))
			assert.Contains(t, y, "name: probe")
			assert.Contains(t, y, "- "+envoy.ProxyProbeHost)

			// The route identifies the bootstrap, and the body
			// identifies the Envoy process.
			assert.Contains(t, y, "path: /probe-token")
			assert.Contains(t, y, "environment_variable: "+envoy.ProxyProbeTokenEnv)
			assert.NotContains(t, y, "inline_string: probe-token")

			// The access loggers skip the probe request. They keep
			// the requests that have no authority.
			assert.Contains(t, y, "header_filter:")
			assert.Contains(t, y, "exact: "+envoy.ProxyProbeHost)
			assert.Contains(t, y, "invert_match: true")
			assert.Contains(t, y, "treat_missing_header_as_empty: true")

			// The filter must not reach the access loggers of the
			// caller, which other listeners can share.
			assert.NotContains(t, marshalYAML(t, params.AccessLog), "filter:")
		})
	}
}

// frontLogFilter is the filter of an access logger of the front
// listener. Envoy logs a request when the filter matches it.
type frontLogFilter struct {
	// SkipAuthority is the authority that the filter does not match.
	SkipAuthority string

	// Expression is the CEL expression that the filter evaluates.
	Expression string

	// And holds the filters that the filter combines. The filter
	// matches a request that each of them matches.
	And []frontLogFilter
}

// frontLogFilterDoc decodes the filter of an access logger.
type frontLogFilterDoc struct {
	HeaderFilter *struct {
		Header struct {
			Name        string `yaml:"name"`
			StringMatch struct {
				Exact string `yaml:"exact"`
			} `yaml:"string_match"`
			InvertMatch bool `yaml:"invert_match"`
		} `yaml:"header"`
	} `yaml:"header_filter"`
	AndFilter *struct {
		Filters []frontLogFilterDoc `yaml:"filters"`
	} `yaml:"and_filter"`
	ExtensionFilter *struct {
		Name        string `yaml:"name"`
		TypedConfig struct {
			Expression string `yaml:"expression"`
		} `yaml:"typed_config"`
	} `yaml:"extension_filter"`
}

// filter returns the [frontLogFilter] that d describes.
func (d frontLogFilterDoc) filter(t *testing.T) frontLogFilter {
	t.Helper()

	var f frontLogFilter

	if d.HeaderFilter != nil {
		require.Equal(t, ":authority", d.HeaderFilter.Header.Name)
		require.True(t, d.HeaderFilter.Header.InvertMatch)

		f.SkipAuthority = d.HeaderFilter.Header.StringMatch.Exact
	}

	if d.ExtensionFilter != nil {
		require.Equal(t, "envoy.access_loggers.extension_filters.cel", d.ExtensionFilter.Name)

		f.Expression = d.ExtensionFilter.TypedConfig.Expression
	}

	if d.AndFilter != nil {
		for _, sub := range d.AndFilter.Filters {
			f.And = append(f.And, sub.filter(t))
		}
	}

	return f
}

// frontLogFilters returns the filter of each access logger of the
// front listener that p describes. An access logger without a filter
// gives nil.
func frontLogFilters(t *testing.T, p envoy.ProxyListenerParams) []*frontLogFilter {
	t.Helper()

	var doc struct {
		FilterChains []struct {
			Filters []struct {
				TypedConfig struct {
					AccessLog []struct {
						Filter *frontLogFilterDoc `yaml:"filter"`
					} `yaml:"access_log"`
				} `yaml:"typed_config"`
			} `yaml:"filters"`
		} `yaml:"filter_chains"`
	}

	require.NoError(t, yaml.Unmarshal([]byte(marshalYAML(t, envoy.BuildProxyListener(p))), &doc))
	require.Len(t, doc.FilterChains, 1)
	require.Len(t, doc.FilterChains[0].Filters, 1)

	var got []*frontLogFilter

	for _, al := range doc.FilterChains[0].Filters[0].TypedConfig.AccessLog {
		if al.Filter == nil {
			got = append(got, nil)

			continue
		}

		got = append(got, new(al.Filter.filter(t)))
	}

	return got
}

// TestBuildProxyListener_SkipInternalListenerRequests checks that the
// access loggers of the front listener skip each request that the
// listener sends to an internal listener. The internal listener
// applies the policy to that request and logs it, so a second entry
// from the front listener records the request twice.
func TestBuildProxyListener_SkipInternalListenerRequests(t *testing.T) {
	t.Parallel()

	skipProbe := frontLogFilter{SkipAuthority: envoy.ProxyProbeHost}

	skipClusters := func(list string) frontLogFilter {
		return frontLogFilter{
			Expression: "!(has(xds.cluster_name) && xds.cluster_name in [" + list + "] && " +
				"has(upstream.local_address))",
		}
	}

	tests := map[string]struct {
		connectTLS  map[int][]string
		httpDomains []string
		probeToken  string
		mode        envoy.ProxyMode
		want        *frontLogFilter
	}{
		"filtered, TLS and HTTP rules": {
			mode:        envoy.ProxyModeFiltered,
			connectTLS:  map[int][]string{8443: {"alt.example.com"}, 443: {"api.example.com"}},
			httpDomains: []string{"plain.example.com"},
			want:        new(skipClusters("'http_internal', 'tls_internal_443', 'tls_internal_8443'")),
		},
		"filtered, TLS rules": {
			mode:       envoy.ProxyModeFiltered,
			connectTLS: map[int][]string{443: {"api.example.com"}},
			want:       new(skipClusters("'tls_internal_443'")),
		},
		"filtered, HTTP rules": {
			mode:        envoy.ProxyModeFiltered,
			httpDomains: []string{"plain.example.com"},
			want:        new(skipClusters("'http_internal'")),
		},
		"filtered, probe": {
			mode:        envoy.ProxyModeFiltered,
			connectTLS:  map[int][]string{443: {"api.example.com"}},
			httpDomains: []string{"plain.example.com"},
			probeToken:  "probe-token",
			want: &frontLogFilter{And: []frontLogFilter{
				skipProbe,
				skipClusters("'http_internal', 'tls_internal_443'"),
			}},
		},
		"filtered, no internal listener": {
			mode: envoy.ProxyModeFiltered,
		},
		"filtered, port without domains": {
			mode:       envoy.ProxyModeFiltered,
			connectTLS: map[int][]string{443: nil},
		},
		"open": {
			mode: envoy.ProxyModeOpen,
		},
		"open, probe": {
			mode:       envoy.ProxyModeOpen,
			probeToken: "probe-token",
			want:       &skipProbe,
		},
		"blocked": {
			mode: envoy.ProxyModeBlocked,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			params := envoy.ProxyListenerParams{
				BindAddress: "127.0.0.1",
				Port:        8080,
				Mode:        tt.mode,
				ConnectTLS:  tt.connectTLS,
				HTTPDomains: tt.httpDomains,
				ProbeToken:  tt.probeToken,
				AccessLog: append(
					envoy.BuildHTTPGrpcAccessLog("proxy", 0, 0),
					envoy.BuildHTTPGrpcAccessLog("second", 0, 0)...,
				),
			}

			// Each access logger gets the filter.
			assert.Equal(t, []*frontLogFilter{tt.want, tt.want}, frontLogFilters(t, params))

			// The filter must not reach the access loggers of the
			// caller, which other listeners can share.
			assert.NotContains(t, marshalYAML(t, params.AccessLog), "filter:")
		})
	}
}

func TestBuildProxyListener_BareWildcard(t *testing.T) {
	t.Parallel()

	l := envoy.BuildProxyListener(envoy.ProxyListenerParams{
		BindAddress: "127.0.0.1",
		Port:        8080,
		Mode:        envoy.ProxyModeFiltered,
		ConnectTLS:  map[int][]string{443: {"*"}},
	})

	y := marshalYAML(t, l)

	// A bare wildcard allows any authority on the port.
	assert.Contains(t, y, `"*:443"`)
}

func TestBuildInternalTLSListener(t *testing.T) {
	t.Parallel()

	rules := []config.ResolvedRule{
		{Domain: "passthrough.example.com"},
		{Domain: "restricted.example.com", HTTPRules: []config.ResolvedHTTPRule{
			{Path: "/v1/.*"},
		}},
	}

	l := envoy.BuildInternalTLSListener(443, rules, false, nil, nil, "/certs", nil)

	assert.Equal(t, "tls_internal_443", l.Name)
	assert.Nil(t, l.Address, "internal listeners have no socket address")
	require.Len(t, l.ListenerFilters, 1)
	assert.Equal(t, "envoy.filters.listener.tls_inspector", l.ListenerFilters[0].Name)

	y := marshalYAML(t, l)

	assert.Contains(t, y, "internal_listener:")

	// Passthrough chain matches the SNI and tunnels via the SNI
	// dynamic forward proxy on the policy port.
	assert.Contains(t, y, "passthrough.example.com")
	assert.Contains(t, y, "sni_dynamic_forward_proxy")
	assert.Contains(t, y, "port_value: 443")

	// MITM chain terminates TLS with the per-domain leaf.
	assert.Contains(t, y, "/certs/restricted.example.com/cert.pem")
	assert.Contains(t, y, "/certs/restricted.example.com/key.pem")
	assert.Contains(t, y, "regex: /v1/.*")
	assert.Contains(t, y, "cluster: mitm_forward_proxy_cluster")

	// Proxy mode resolves upstream names via the system resolver,
	// not the container-mode loopback DNS proxy.
	assert.NotContains(t, y, "port_value: 53")
	assert.NotContains(t, y, "typed_dns_resolver_config")
}

func TestBuildInternalTLSListener_Resolvers(t *testing.T) {
	t.Parallel()

	rules := []config.ResolvedRule{{Domain: "example.com"}}
	resolvers := []netip.AddrPort{netip.MustParseAddrPort("10.0.0.2:5353")}

	l := envoy.BuildInternalTLSListener(443, rules, false, nil, nil, "", resolvers)

	y := marshalYAML(t, l)

	assert.Contains(t, y, "typed_dns_resolver_config")
	assert.Contains(t, y, "address: 10.0.0.2")
	assert.Contains(t, y, "port_value: 5353")
}

// TestTLSListeners_DefaultChainAccessLog checks that the default
// filter chain of a TLS listener logs to the TCP access loggers of the
// listener. That chain closes each connection without an allowed SNI,
// and the stats store records the closed connection as a deny.
func TestTLSListeners_DefaultChainAccessLog(t *testing.T) {
	t.Parallel()

	rules := []config.ResolvedRule{{Domain: "example.com"}}
	tcpAL := envoy.BuildTCPGrpcAccessLog("tcp", 0, 0)
	httpAL := envoy.BuildHTTPGrpcAccessLog("mitm", 0, 0)

	tests := map[string]struct {
		listener envoy.Listener
	}{
		"container": {
			listener: envoy.BuildTLSListener(
				"tls_passthrough", 15443, 443, "tls_passthrough",
				rules, false, tcpAL, httpAL, "", false,
			),
		},
		"proxy internal": {
			listener: envoy.BuildInternalTLSListener(443, rules, false, tcpAL, httpAL, "", nil),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var doc struct {
				DefaultFilterChain struct {
					Filters []struct {
						TypedConfig struct {
							Cluster   string `yaml:"cluster"`
							AccessLog []struct {
								Name        string `yaml:"name"`
								TypedConfig struct {
									CommonConfig struct {
										CustomTags []struct {
											Tag     string `yaml:"tag"`
											Literal struct {
												Value string `yaml:"value"`
											} `yaml:"literal"`
										} `yaml:"custom_tags"`
									} `yaml:"common_config"`
								} `yaml:"typed_config"`
							} `yaml:"access_log"`
						} `yaml:"typed_config"`
					} `yaml:"filters"`
				} `yaml:"default_filter_chain"`
			}

			require.NoError(t, yaml.Unmarshal([]byte(marshalYAML(t, tt.listener)), &doc))
			require.Len(t, doc.DefaultFilterChain.Filters, 1)

			cfg := doc.DefaultFilterChain.Filters[0].TypedConfig
			assert.Equal(t, envoy.MissingSNIBlackholeCluster, cfg.Cluster)

			var names []string

			for _, al := range cfg.AccessLog {
				names = append(names, al.Name)
			}

			require.Equal(t, []string{
				"envoy.access_loggers.stderr",
				"envoy.access_loggers.tcp_grpc",
			}, names)

			// The gRPC logger marks each entry as a denial.
			tags := cfg.AccessLog[1].TypedConfig.CommonConfig.CustomTags
			require.Len(t, tags, 1)
			assert.Equal(t, envoy.SNIRejectTag, tags[0].Tag)
			assert.Equal(t, "true", tags[0].Literal.Value)

			// The tag must not reach the access loggers of the
			// passthrough chains, which log allowed connections.
			assert.NotContains(t, marshalYAML(t, tcpAL), "custom_tags")
			assert.Equal(t, 1, strings.Count(marshalYAML(t, tt.listener), envoy.SNIRejectTag))
		})
	}
}

// TestBuildInternalTLSListener_MITMTunnelAccessLog checks that an
// internal TLS listener with MITM chains logs each connection of those
// chains to its TCP access loggers. The front listener skips the
// CONNECT request of such a tunnel, and the connection manager of the
// chain logs only the requests inside it, so these loggers record a
// tunnel that carries no request.
func TestBuildInternalTLSListener_MITMTunnelAccessLog(t *testing.T) {
	t.Parallel()

	tcpAL := envoy.BuildTCPGrpcAccessLog("tcp", 0, 0)
	httpAL := envoy.BuildHTTPGrpcAccessLog("mitm", 0, 0)

	restricted := func(domain string) config.ResolvedRule {
		return config.ResolvedRule{
			Domain:    domain,
			HTTPRules: []config.ResolvedHTTPRule{{Path: "/allowed"}},
		}
	}

	tests := map[string]struct {
		rules    []config.ResolvedRule
		tcpAL    []envoy.AccessLog
		certsDir string
		want     string
	}{
		"MITM chains": {
			rules: []config.ResolvedRule{
				{Domain: "passthrough.example.com"},
				restricted("b.example.com"),
				restricted("*.wild.example.com"),
			},
			tcpAL:    tcpAL,
			certsDir: "/certs",
			want: "has(xds.filter_chain_name) && xds.filter_chain_name in " +
				"['mitm_b.example.com', 'mitm_*.wild.example.com']",
		},
		"no MITM chain": {
			rules:    []config.ResolvedRule{{Domain: "passthrough.example.com"}},
			tcpAL:    tcpAL,
			certsDir: "/certs",
		},
		"no certs dir": {
			rules: []config.ResolvedRule{restricted("b.example.com")},
			tcpAL: tcpAL,
		},
		"stats disabled": {
			rules:    []config.ResolvedRule{restricted("b.example.com")},
			certsDir: "/certs",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			l := envoy.BuildInternalTLSListener(443, tt.rules, false, tt.tcpAL, httpAL, tt.certsDir, nil)

			var doc struct {
				FilterChains []struct {
					Name string `yaml:"name"`
				} `yaml:"filter_chains"`
				AccessLog []struct {
					Name   string            `yaml:"name"`
					Filter frontLogFilterDoc `yaml:"filter"`
				} `yaml:"access_log"`
			}

			require.NoError(t, yaml.Unmarshal([]byte(marshalYAML(t, l)), &doc))

			if tt.want == "" {
				assert.Empty(t, doc.AccessLog)

				return
			}

			require.Len(t, doc.AccessLog, 1)
			assert.Equal(t, "envoy.access_loggers.tcp_grpc", doc.AccessLog[0].Name)
			assert.Equal(t, frontLogFilter{Expression: tt.want}, doc.AccessLog[0].Filter.filter(t))

			// The expression names each MITM chain of the listener.
			for _, c := range doc.FilterChains {
				if strings.HasPrefix(c.Name, "mitm_") {
					assert.Contains(t, tt.want, "'"+c.Name+"'")
				}
			}
		})
	}
}

func TestBuildInternalHTTPListener(t *testing.T) {
	t.Parallel()

	rules := []config.ResolvedRule{{Domain: "plain.example.com"}}

	l := envoy.BuildInternalHTTPListener(rules, false, nil, nil)

	assert.Equal(t, "http_internal", l.Name)
	assert.Nil(t, l.Address, "internal listeners have no socket address")

	y := marshalYAML(t, l)

	assert.Contains(t, y, "internal_listener:")
	assert.Contains(t, y, "plain.example.com")
	assert.Contains(t, y, "envoy.filters.http.dynamic_forward_proxy")

	// Unmatched hosts receive an explicit 403 in proxy mode.
	assert.Contains(t, y, "name: deny")
	assert.Contains(t, y, "status: 403")
}

func TestBuildInternalHTTPListener_Open(t *testing.T) {
	t.Parallel()

	l := envoy.BuildInternalHTTPListener(nil, true, nil, nil)

	y := marshalYAML(t, l)

	// Open mode forwards everything; the deny vhost would conflict
	// with the open catch-all.
	assert.Contains(t, y, "name: open")
	assert.NotContains(t, y, "status: 403")
}

func TestBuildProxyClusters(t *testing.T) {
	t.Parallel()

	rules := []config.ResolvedRule{
		{Domain: "passthrough.example.com"},
		{Domain: "restricted.example.com", HTTPRules: []config.ResolvedHTTPRule{
			{Method: "GET"},
		}},
	}

	clusters, err := envoy.BuildProxyClusters(
		rules, []int{443, 8443}, true, false, "/etc/ssl/bundle.pem", nil,
	)
	require.NoError(t, err)

	y := marshalYAML(t, clusters)

	assert.Contains(t, y, "name: missing_sni_blackhole")
	assert.Contains(t, y, "name: dynamic_forward_proxy_cluster")
	assert.Contains(t, y, "name: mitm_forward_proxy_cluster")
	assert.Contains(t, y, "name: tls_internal_443")
	assert.Contains(t, y, "name: tls_internal_8443")
	assert.Contains(t, y, "name: http_internal")

	// Internal clusters target the internal listeners by name.
	assert.Contains(t, y, "server_listener_name: tls_internal_443")
	assert.Contains(t, y, "server_listener_name: http_internal")

	// MITM upstream trust comes from the CA bundle.
	assert.Contains(t, y, "trusted_ca:")
	assert.Contains(t, y, "filename: /etc/ssl/bundle.pem")

	// Proxy clusters use the system resolver.
	assert.NotContains(t, y, "port_value: 53")
}

func TestBuildProxyClusters_Blocked(t *testing.T) {
	t.Parallel()

	clusters, err := envoy.BuildProxyClusters(nil, nil, false, false, "", nil)
	require.NoError(t, err)
	assert.Empty(t, clusters, "blocked mode needs no clusters")
}

func TestBuildProxyClusters_Open(t *testing.T) {
	t.Parallel()

	clusters, err := envoy.BuildProxyClusters(nil, nil, false, true, "", nil)
	require.NoError(t, err)

	y := marshalYAML(t, clusters)

	assert.Contains(t, y, "name: dynamic_forward_proxy_cluster")
	assert.NotContains(t, y, "missing_sni_blackhole")
	assert.NotContains(t, y, "mitm_forward_proxy_cluster")
}

func TestBuildProxyClusters_MITMWithoutCABundle(t *testing.T) {
	t.Parallel()

	rules := []config.ResolvedRule{
		{Domain: "restricted.example.com", HTTPRules: []config.ResolvedHTTPRule{
			{Method: "GET"},
		}},
	}

	clusters, err := envoy.BuildProxyClusters(rules, []int{443}, false, false, "", nil)
	require.ErrorIs(t, err, envoy.ErrMITMCABundleMissing)
	assert.Nil(t, clusters)
}

func TestInternalListenerBootstrapExtension(t *testing.T) {
	t.Parallel()

	ext := envoy.InternalListenerBootstrapExtension()
	assert.Equal(t, "envoy.bootstrap.internal_listener", ext.Name)

	y := marshalYAML(t, ext)
	assert.Contains(t, y, "internal_listener.v3.InternalListener")
}

// countOccurrences counts non-overlapping occurrences of substr in s.
func countOccurrences(s, substr string) int {
	count := 0

	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			count++
		}
	}

	return count
}
