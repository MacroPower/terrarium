package envoy_test

import (
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoy"
)

// mitmHTTPFilter describes one HTTP filter of a MITM filter chain.
type mitmHTTPFilter struct {
	// Name is the name of the filter.
	Name string
	// State lists the filter state values that the filter stores for
	// each request, as "key=value".
	State []string
	// FilterStatePort reports whether the filter takes the port of the
	// upstream from the filter state of the request.
	FilterStatePort bool
}

// mitmHTTPFilters returns the HTTP filters of the only filter chain of
// listener, which must hold one HTTP connection manager.
func mitmHTTPFilters(t *testing.T, listener envoy.Listener) []mitmHTTPFilter {
	t.Helper()

	out, err := yaml.Marshal(listener)
	require.NoError(t, err)

	var doc struct {
		FilterChains []struct {
			Filters []struct {
				TypedConfig struct {
					HTTPFilters []struct {
						Name        string `yaml:"name"`
						TypedConfig struct {
							OnRequestHeaders []struct {
								ObjectKey    string `yaml:"object_key"`
								FormatString struct {
									TextFormatSource struct {
										InlineString string `yaml:"inline_string"`
									} `yaml:"text_format_source"`
								} `yaml:"format_string"`
							} `yaml:"on_request_headers"`
							AllowDynamicHostFromFilterState bool `yaml:"allow_dynamic_host_from_filter_state"`
						} `yaml:"typed_config"`
					} `yaml:"http_filters"`
				} `yaml:"typed_config"`
			} `yaml:"filters"`
		} `yaml:"filter_chains"`
	}

	require.NoError(t, yaml.Unmarshal(out, &doc))
	require.Len(t, doc.FilterChains, 1)
	require.Len(t, doc.FilterChains[0].Filters, 1)

	var got []mitmHTTPFilter

	for _, f := range doc.FilterChains[0].Filters[0].TypedConfig.HTTPFilters {
		filter := mitmHTTPFilter{
			Name:            f.Name,
			FilterStatePort: f.TypedConfig.AllowDynamicHostFromFilterState,
		}

		for _, v := range f.TypedConfig.OnRequestHeaders {
			filter.State = append(filter.State,
				v.ObjectKey+"="+v.FormatString.TextFormatSource.InlineString)
		}

		got = append(got, filter)
	}

	return got
}

// TestMITMChain_UpstreamPort checks that a MITM filter chain gives the
// upstream port of its listener to the dynamic forward proxy filter.
// The chain must store the port under the filter state key
// "envoy.upstream.dynamic_port" before the dynamic forward proxy filter
// runs, and that filter must read the port from the filter state. The
// filter then resolves the host for the upstream port of the listener.
func TestMITMChain_UpstreamPort(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		domain string
		port   int
		want   []mitmHTTPFilter
	}{
		"port 443": {
			domain: "api.example.com",
			port:   443,
			want: []mitmHTTPFilter{
				{
					Name:  "envoy.filters.http.set_filter_state",
					State: []string{"envoy.upstream.dynamic_port=443"},
				},
				{Name: "envoy.filters.http.dynamic_forward_proxy", FilterStatePort: true},
				{Name: "envoy.filters.http.router"},
			},
		},
		"port other than 443": {
			domain: "api.example.com",
			port:   8443,
			want: []mitmHTTPFilter{
				{
					Name:  "envoy.filters.http.set_filter_state",
					State: []string{"envoy.upstream.dynamic_port=8443"},
				},
				{Name: "envoy.filters.http.dynamic_forward_proxy", FilterStatePort: true},
				{Name: "envoy.filters.http.router"},
			},
		},
		"wildcard domain": {
			domain: "*.example.com",
			port:   8443,
			want: []mitmHTTPFilter{
				{Name: "envoy.filters.http.rbac"},
				{
					Name:  "envoy.filters.http.set_filter_state",
					State: []string{"envoy.upstream.dynamic_port=8443"},
				},
				{Name: "envoy.filters.http.dynamic_forward_proxy", FilterStatePort: true},
				{Name: "envoy.filters.http.router"},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rules := []config.ResolvedRule{{
				Domain:    tt.domain,
				HTTPRules: []config.ResolvedHTTPRule{{Path: "/v1/.*"}},
			}}

			listeners := map[string]envoy.Listener{
				"container TLS listener": envoy.BuildTLSListener(
					"tls", 15000+tt.port, tt.port, "tls", rules, false, nil, nil, "/certs", false,
				),
				"proxy internal TLS listener": envoy.BuildInternalTLSListener(
					tt.port, rules, false, nil, nil, "/certs", nil,
				),
			}

			for listenerName, listener := range listeners {
				assert.Equal(t, tt.want, mitmHTTPFilters(t, listener), listenerName)
			}
		})
	}
}

// mitmRoute describes one route of a MITM filter chain.
type mitmRoute struct {
	// HostRewrite is the format of the Host header that the route
	// sends to the upstream. It is empty when the route does not
	// change the header.
	HostRewrite string
	// Forward reports whether the route forwards the request to an
	// upstream.
	Forward bool
}

// mitmRoutes returns the routes of the only filter chain of listener,
// which must hold one HTTP connection manager.
func mitmRoutes(t *testing.T, listener envoy.Listener) []mitmRoute {
	t.Helper()

	out, err := yaml.Marshal(listener)
	require.NoError(t, err)

	var doc struct {
		FilterChains []struct {
			Filters []struct {
				TypedConfig struct {
					RouteConfig struct {
						VirtualHosts []struct {
							Routes []struct {
								Route *struct {
									HostRewrite string `yaml:"host_rewrite"`
								} `yaml:"route"`
							} `yaml:"routes"`
						} `yaml:"virtual_hosts"`
					} `yaml:"route_config"`
				} `yaml:"typed_config"`
			} `yaml:"filters"`
		} `yaml:"filter_chains"`
	}

	require.NoError(t, yaml.Unmarshal(out, &doc))
	require.Len(t, doc.FilterChains, 1)
	require.Len(t, doc.FilterChains[0].Filters, 1)

	var got []mitmRoute

	for _, vh := range doc.FilterChains[0].Filters[0].TypedConfig.RouteConfig.VirtualHosts {
		for _, r := range vh.Routes {
			if r.Route == nil {
				got = append(got, mitmRoute{})

				continue
			}

			got = append(got, mitmRoute{Forward: true, HostRewrite: r.Route.HostRewrite})
		}
	}

	return got
}

// TestMITMChain_HostPort checks the Host header that a MITM filter
// chain sends to the upstream. The connection manager removes the port
// from the header. So each route that forwards a request must append
// the upstream port of the listener, except for port 443, which a Host
// header without a port names.
func TestMITMChain_HostPort(t *testing.T) {
	t.Parallel()

	// The first HTTP rule gives a route and its gRPC variant. The
	// second HTTP rule gives the routes of a mismatch action.
	httpRules := []config.ResolvedHTTPRule{
		{Path: "/v1/.*"},
		{
			Path: "/v2/.*",
			HeaderMatches: []config.HeaderMatch{{
				Name:     "X-Token",
				Value:    "secret",
				Mismatch: config.MismatchLOG,
			}},
		},
	}

	tests := map[string]struct {
		domain string
		want   string
		port   int
	}{
		"port 443": {
			domain: "api.example.com",
			port:   443,
			want:   "",
		},
		"port other than 443": {
			domain: "api.example.com",
			port:   8443,
			want:   "%REQ(:AUTHORITY)%:8443",
		},
		"wildcard domain": {
			domain: "*.example.com",
			port:   8443,
			want:   "%REQ(:AUTHORITY)%:8443",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rules := []config.ResolvedRule{{Domain: tt.domain, HTTPRules: httpRules}}

			listeners := map[string]envoy.Listener{
				"container TLS listener": envoy.BuildTLSListener(
					"tls", 15000+tt.port, tt.port, "tls", rules, false, nil, nil, "/certs", false,
				),
				"proxy internal TLS listener": envoy.BuildInternalTLSListener(
					tt.port, rules, false, nil, nil, "/certs", nil,
				),
			}

			// Two routes for the first HTTP rule, four routes for the
			// second HTTP rule, and the route that denies every other
			// request.
			want := []mitmRoute{
				{Forward: true, HostRewrite: tt.want},
				{Forward: true, HostRewrite: tt.want},
				{Forward: true, HostRewrite: tt.want},
				{Forward: true, HostRewrite: tt.want},
				{Forward: true, HostRewrite: tt.want},
				{Forward: true, HostRewrite: tt.want},
				{},
			}

			for listenerName, listener := range listeners {
				assert.Equal(t, want, mitmRoutes(t, listener), listenerName)
			}
		})
	}
}

// headerValueKeyPrefix is the prefix of the filter state key of the
// object that holds the joined values of a request header. The
// lowercase name of the header follows the prefix.
const headerValueKeyPrefix = "terrarium.header_value."

// headerValuesStoredKey is the filter state key of the object that
// marks a request whose header values an HTTP filter stored.
const headerValuesStoredKey = "terrarium.header_values_stored"

// headerValue describes one filter state object that an HTTP filter
// stores for a request header.
type headerValue struct {
	// Key is the filter state key of the object.
	Key string
	// Factory names the Envoy object factory that creates the object.
	Factory string
	// Format is the Envoy format string that gives the text of the
	// object.
	Format string
	// OmitEmpty reports whether Envoy formats an operator without a
	// result as the empty string. Without it, Envoy formats that
	// operator as "-".
	OmitEmpty bool
	// SkipIfEmpty reports whether Envoy stores no object when the text
	// is empty.
	SkipIfEmpty bool
}

// headerValueFilter returns the filter state objects that the HTTP
// filters of the only filter chain of listener store for request
// headers. The filter chain must hold one HTTP connection manager.
//
// The function requires that the first HTTP filter stores all the
// objects and that it clears the route of the request. Envoy selects
// the route before the HTTP filters run, so a route match can read the
// objects only after the filter cleared that route.
//
// The function also requires that the filter stores the object of
// [headerValuesStoredKey] exactly when it stores an object for a
// header. Envoy answers some requests before the HTTP filters run, and
// the access logger of the LOG action reads that object to skip them.
func headerValueFilter(t *testing.T, listener envoy.Listener) []headerValue {
	t.Helper()

	out, err := yaml.Marshal(listener)
	require.NoError(t, err)

	type storedValue struct {
		ObjectKey    string `yaml:"object_key"`
		FactoryKey   string `yaml:"factory_key"`
		FormatString struct {
			TextFormatSource struct {
				InlineString string `yaml:"inline_string"`
			} `yaml:"text_format_source"`
			OmitEmptyValues bool `yaml:"omit_empty_values"`
		} `yaml:"format_string"`
		SkipIfEmpty bool `yaml:"skip_if_empty"`
	}

	var doc struct {
		FilterChains []struct {
			Filters []struct {
				TypedConfig struct {
					HTTPFilters []struct {
						Name        string `yaml:"name"`
						TypedConfig struct {
							OnRequestHeaders []storedValue `yaml:"on_request_headers"`
							ClearRouteCache  bool          `yaml:"clear_route_cache"`
						} `yaml:"typed_config"`
					} `yaml:"http_filters"`
				} `yaml:"typed_config"`
			} `yaml:"filters"`
		} `yaml:"filter_chains"`
	}

	require.NoError(t, yaml.Unmarshal(out, &doc))
	require.Len(t, doc.FilterChains, 1)
	require.Len(t, doc.FilterChains[0].Filters, 1)

	var (
		got    []headerValue
		marked bool
	)

	for i, f := range doc.FilterChains[0].Filters[0].TypedConfig.HTTPFilters {
		for _, v := range f.TypedConfig.OnRequestHeaders {
			if v.ObjectKey == headerValuesStoredKey {
				require.False(t, marked, "one filter must store %s", headerValuesStoredKey)
				require.Zero(t, i, "the filter that stores %s must be the first HTTP filter", v.ObjectKey)
				require.Equal(t, "envoy.string", v.FactoryKey)
				require.Equal(t, "true", v.FormatString.TextFormatSource.InlineString)
				require.False(t, v.SkipIfEmpty)

				marked = true

				continue
			}

			if !strings.HasPrefix(v.ObjectKey, headerValueKeyPrefix) {
				continue
			}

			require.Zero(t, i, "the filter that stores %s must be the first HTTP filter", v.ObjectKey)
			require.Equal(t, "envoy.filters.http.set_filter_state", f.Name)
			require.True(t, f.TypedConfig.ClearRouteCache, "the filter must clear the route")

			got = append(got, headerValue{
				Key:         v.ObjectKey,
				Factory:     v.FactoryKey,
				Format:      v.FormatString.TextFormatSource.InlineString,
				OmitEmpty:   v.FormatString.OmitEmptyValues,
				SkipIfEmpty: v.SkipIfEmpty,
			})
		}
	}

	require.Equal(t, len(got) > 0, marked,
		"the filter must store %s exactly when it stores a header value", headerValuesStoredKey)

	return got
}

// TestHeaderValueFilter checks the HTTP filter that stores the joined
// values of request headers in the filter state. The routes of a
// headerMatches entry with a value compare that value with the stored
// object. The filter must therefore store one object for each header
// of such an entry. An entry without a value matches on the presence
// of the header, so it does not need an object.
//
// The filter must store no object for a request that lacks the header.
// Envoy formats an operator without a result as "-" by default, which
// a headerMatches entry can hold as its value.
func TestHeaderValueFilter(t *testing.T) {
	t.Parallel()

	stored := func(name, literal string) headerValue {
		return headerValue{
			Key:         headerValueKeyPrefix + name,
			Factory:     "envoy.string",
			Format:      "%CEL(request.headers[" + literal + "])%",
			OmitEmpty:   true,
			SkipIfEmpty: true,
		}
	}

	tests := map[string]struct {
		domain    string
		httpRules []config.ResolvedHTTPRule
		want      []headerValue
	}{
		"no headerMatches": {
			domain:    "api.example.com",
			httpRules: []config.ResolvedHTTPRule{{Path: "/v1/.*"}},
		},
		"entries without a value": {
			domain: "api.example.com",
			httpRules: []config.ResolvedHTTPRule{{
				HeaderMatches: []config.HeaderMatch{
					{Name: "X-Present"},
					{Name: "X-Log", Mismatch: config.MismatchLOG},
				},
			}},
		},
		"entry without a mismatch action": {
			domain: "api.example.com",
			httpRules: []config.ResolvedHTTPRule{{
				HeaderMatches: []config.HeaderMatch{{Name: "X-Token", Value: "secret"}},
			}},
			want: []headerValue{stored("x-token", "'x-token'")},
		},
		"each mismatch action": {
			domain: "api.example.com",
			httpRules: []config.ResolvedHTTPRule{{
				HeaderMatches: []config.HeaderMatch{
					{Name: "X-Add", Value: "a", Mismatch: config.MismatchADD},
					{Name: "X-Del", Value: "d", Mismatch: config.MismatchDELETE},
					{Name: "X-Rep", Value: "r", Mismatch: config.MismatchREPLACE},
					{Name: "X-Log", Value: "l", Mismatch: config.MismatchLOG},
				},
			}},
			want: []headerValue{
				stored("x-add", "'x-add'"),
				stored("x-del", "'x-del'"),
				stored("x-rep", "'x-rep'"),
				stored("x-log", "'x-log'"),
			},
		},
		"one header in two HTTP rules and in another case": {
			domain: "api.example.com",
			httpRules: []config.ResolvedHTTPRule{
				{
					Path:          "/v1/.*",
					HeaderMatches: []config.HeaderMatch{{Name: "X-Token", Value: "one"}},
				},
				{
					Path: "/v2/.*",
					HeaderMatches: []config.HeaderMatch{
						{Name: "x-token", Value: "two", Mismatch: config.MismatchREPLACE},
						{Name: "X-Other", Value: "other"},
					},
				},
			},
			want: []headerValue{
				stored("x-token", "'x-token'"),
				stored("x-other", "'x-other'"),
			},
		},
		// A "'" ends the string literal of the expression, and Envoy
		// ends the operator of a format string at ")" and at "%".
		"header name with characters that end the expression": {
			domain: "api.example.com",
			httpRules: []config.ResolvedHTTPRule{{
				HeaderMatches: []config.HeaderMatch{{Name: "X-It's)%:\\", Value: "secret"}},
			}},
			want: []headerValue{stored(
				"x-it's)%:\\",
				`'x-it\U00000027s\U00000029\U00000025\U0000003a\U0000005c'`,
			)},
		},
		"wildcard domain": {
			domain: "*.example.com",
			httpRules: []config.ResolvedHTTPRule{{
				HeaderMatches: []config.HeaderMatch{{Name: "X-Token", Value: "secret"}},
			}},
			want: []headerValue{stored("x-token", "'x-token'")},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rules := []config.ResolvedRule{{Domain: tt.domain, HTTPRules: tt.httpRules}}

			listeners := map[string]envoy.Listener{
				"container HTTP listener": envoy.BuildHTTPForwardListener(rules, false, nil, false),
				"container TLS listener": envoy.BuildTLSListener(
					"tls", 15443, 443, "tls", rules, false, nil, nil, "/certs", false,
				),
				"proxy internal HTTP listener": envoy.BuildInternalHTTPListener(rules, false, nil, nil),
				"proxy internal TLS listener": envoy.BuildInternalTLSListener(
					443, rules, false, nil, nil, "/certs", nil,
				),
			}

			for listenerName, listener := range listeners {
				assert.Equal(t, tt.want, headerValueFilter(t, listener), listenerName)
			}
		})
	}
}

// TestHeaderValueFilter_RulesShareFilter checks that the plain HTTP
// listener stores the header values of all its rules in one filter.
// The connection manager of that listener serves every rule, and a
// header that two rules name needs one object.
func TestHeaderValueFilter_RulesShareFilter(t *testing.T) {
	t.Parallel()

	rules := []config.ResolvedRule{
		{
			Domain: "api.example.com",
			HTTPRules: []config.ResolvedHTTPRule{{
				HeaderMatches: []config.HeaderMatch{{Name: "X-Token", Value: "one"}},
			}},
		},
		{
			Domain: "other.example.com",
			HTTPRules: []config.ResolvedHTTPRule{{
				HeaderMatches: []config.HeaderMatch{
					{Name: "X-Token", Value: "two"},
					{Name: "X-Other", Value: "other", Mismatch: config.MismatchADD},
				},
			}},
		},
		// A rule without HTTP rules forwards every request, so it
		// compares no header value.
		{Domain: "open.example.com"},
	}

	var keys []string

	for _, v := range headerValueFilter(t, envoy.BuildHTTPForwardListener(rules, false, nil, false)) {
		keys = append(keys, v.Key)
	}

	assert.Equal(t, []string{
		headerValueKeyPrefix + "x-token",
		headerValueKeyPrefix + "x-other",
	}, keys)
}
