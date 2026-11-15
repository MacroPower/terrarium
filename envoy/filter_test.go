package envoy_test

import (
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
