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

// TestMITMChain_UpstreamPort checks that a MITM filter chain sends the
// decrypted requests to the upstream port of its listener. The
// connection manager removes the port from the Host header, and the
// dynamic forward proxy then connects to port 443. So the chain must
// store the upstream port in the filter state before the dynamic
// forward proxy filter runs. That filter must read the port from the
// filter state.
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
