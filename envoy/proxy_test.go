package envoy_test

import (
	"net/netip"
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
