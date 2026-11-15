package envoy_test

import (
	"fmt"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoy"
)

func TestHostHeaderMatcherStripsAnchors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		host string
		want string
	}{
		"no anchors": {
			host: `api\.example\.com`,
			want: `^api\\.example\\.com(:[0-9]+)?$`,
		},
		"trailing dollar": {
			host: `api\.example\.com$`,
			want: `^api\\.example\\.com(:[0-9]+)?$`,
		},
		"leading caret": {
			host: `^api\.example\.com`,
			want: `^api\\.example\\.com(:[0-9]+)?$`,
		},
		"both anchors": {
			host: `^api\.example\.com$`,
			want: `^api\\.example\\.com(:[0-9]+)?$`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rules := []config.ResolvedRule{{
				Domain: "api.example.com",
				HTTPRules: []config.ResolvedHTTPRule{{
					Host: tt.host,
				}},
			}}

			listener := envoy.BuildHTTPForwardListener(rules, false, nil, false)

			out, err := yaml.Marshal(listener)
			require.NoError(t, err)

			assert.Contains(t, string(out), tt.want)
		})
	}
}

func TestMismatchActions(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		rules    []config.ResolvedRule
		contains []string
		excludes []string
	}{
		"ADD mismatch generates request_headers_to_add with APPEND_IF_EXISTS_OR_ADD": {
			rules: []config.ResolvedRule{{
				Domain: "api.example.com",
				HTTPRules: []config.ResolvedHTTPRule{{
					HeaderMatches: []config.HeaderMatch{
						{Name: "X-Custom", Value: "default", Mismatch: config.MismatchADD},
					},
				}},
			}},
			contains: []string{
				"request_headers_to_add:",
				"key: X-Custom",
				"value: default",
				"append_action: APPEND_IF_EXISTS_OR_ADD",
			},
		},
		"DELETE mismatch generates request_headers_to_remove": {
			rules: []config.ResolvedRule{{
				Domain: "api.example.com",
				HTTPRules: []config.ResolvedHTTPRule{{
					HeaderMatches: []config.HeaderMatch{
						{Name: "X-Bad", Mismatch: config.MismatchDELETE},
					},
				}},
			}},
			contains: []string{
				"request_headers_to_remove:",
				"- X-Bad",
			},
		},
		"REPLACE mismatch generates OVERWRITE_IF_EXISTS_OR_ADD": {
			rules: []config.ResolvedRule{{
				Domain: "api.example.com",
				HTTPRules: []config.ResolvedHTTPRule{{
					HeaderMatches: []config.HeaderMatch{
						{Name: "X-Version", Value: "v2", Mismatch: config.MismatchREPLACE},
					},
				}},
			}},
			contains: []string{
				"request_headers_to_add:",
				"key: X-Version",
				"value: v2",
				"append_action: OVERWRITE_IF_EXISTS_OR_ADD",
			},
		},
		"LOG mismatch generates typed_per_filter_config with upstream_log": {
			rules: []config.ResolvedRule{{
				Domain: "api.example.com",
				HTTPRules: []config.ResolvedHTTPRule{{
					HeaderMatches: []config.HeaderMatch{
						{Name: "X-Token", Value: "secret", Mismatch: config.MismatchLOG},
					},
				}},
			}},
			contains: []string{
				"typed_per_filter_config:",
				"envoy.filters.http.router:",
				"upstream_log:",
				"envoy.access_loggers.stderr",
				"HEADER_MISMATCH",
				"X-Token",
			},
		},
		"deny headerMatch without mismatch has no transforms": {
			rules: []config.ResolvedRule{{
				Domain: "api.example.com",
				HTTPRules: []config.ResolvedHTTPRule{{
					HeaderMatches: []config.HeaderMatch{
						{Name: "X-Token", Value: "abc"},
					},
				}},
			}},
			contains: []string{
				"name: X-Token",
				"exact: abc",
			},
			excludes: []string{
				"request_headers_to_add:",
				"request_headers_to_remove:",
				"typed_per_filter_config:",
			},
		},
		"mixed deny and mismatch headerMatches": {
			rules: []config.ResolvedRule{{
				Domain: "api.example.com",
				HTTPRules: []config.ResolvedHTTPRule{{
					HeaderMatches: []config.HeaderMatch{
						{Name: "X-Required", Value: "yes"},
						{Name: "X-Custom", Value: "default", Mismatch: config.MismatchADD},
					},
				}},
			}},
			contains: []string{
				"name: X-Required",
				"request_headers_to_add:",
				"key: X-Custom",
				"append_action: APPEND_IF_EXISTS_OR_ADD",
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			listener := envoy.BuildHTTPForwardListener(tt.rules, false, nil, false)

			out, err := yaml.Marshal(listener)
			require.NoError(t, err)

			y := string(out)
			for _, s := range tt.contains {
				assert.Contains(t, y, s)
			}

			for _, s := range tt.excludes {
				assert.NotContains(t, y, s)
			}
		})
	}
}

// mismatchRoute describes one forwarding route of an HTTP rule whose
// headerMatches carry a mismatch action.
type mismatchRoute struct {
	// match lists the exact header matchers of the route as
	// "name=value".
	match []string
	// add lists the request_headers_to_add entries of the route as
	// "name=value append_action".
	add []string
	// remove lists the request_headers_to_remove entries of the route.
	remove []string
}

// TestMismatchRouteOrder checks the routes of rules whose headerMatches
// carry a mismatch action. Envoy takes the first route that matches,
// so the order of the routes decides which header changes a request
// gets. A route must append the value of an ADD header only when no
// earlier route takes the requests that already hold the value.
func TestMismatchRouteOrder(t *testing.T) {
	t.Parallel()

	const (
		appendAction    = " APPEND_IF_EXISTS_OR_ADD"
		overwriteAction = " OVERWRITE_IF_EXISTS_OR_ADD"
	)

	tests := map[string]struct {
		matches []config.HeaderMatch
		want    []mismatchRoute
	}{
		"one ADD": {
			matches: []config.HeaderMatch{
				{Name: "X-One", Value: "one", Mismatch: config.MismatchADD},
			},
			want: []mismatchRoute{
				{match: []string{"X-One=one"}},
				{add: []string{"X-One=one" + appendAction}},
			},
		},
		"two ADD": {
			matches: []config.HeaderMatch{
				{Name: "X-One", Value: "one", Mismatch: config.MismatchADD},
				{Name: "X-Two", Value: "two", Mismatch: config.MismatchADD},
			},
			want: []mismatchRoute{
				{match: []string{"X-One=one", "X-Two=two"}},
				{match: []string{"X-One=one"}, add: []string{"X-Two=two" + appendAction}},
				{match: []string{"X-Two=two"}, add: []string{"X-One=one" + appendAction}},
				{add: []string{"X-One=one" + appendAction, "X-Two=two" + appendAction}},
			},
		},
		"three ADD": {
			matches: []config.HeaderMatch{
				{Name: "X-One", Value: "one", Mismatch: config.MismatchADD},
				{Name: "X-Two", Value: "two", Mismatch: config.MismatchADD},
				{Name: "X-Three", Value: "three", Mismatch: config.MismatchADD},
			},
			want: []mismatchRoute{
				{match: []string{"X-One=one", "X-Two=two", "X-Three=three"}},
				{
					match: []string{"X-One=one", "X-Two=two"},
					add:   []string{"X-Three=three" + appendAction},
				},
				{
					match: []string{"X-One=one", "X-Three=three"},
					add:   []string{"X-Two=two" + appendAction},
				},
				{
					match: []string{"X-Two=two", "X-Three=three"},
					add:   []string{"X-One=one" + appendAction},
				},
				{
					match: []string{"X-One=one"},
					add:   []string{"X-Two=two" + appendAction, "X-Three=three" + appendAction},
				},
				{
					match: []string{"X-Two=two"},
					add:   []string{"X-One=one" + appendAction, "X-Three=three" + appendAction},
				},
				{
					match: []string{"X-Three=three"},
					add:   []string{"X-One=one" + appendAction, "X-Two=two" + appendAction},
				},
				{
					add: []string{
						"X-One=one" + appendAction,
						"X-Two=two" + appendAction,
						"X-Three=three" + appendAction,
					},
				},
			},
		},
		"ADD with REPLACE": {
			matches: []config.HeaderMatch{
				{Name: "X-One", Value: "one", Mismatch: config.MismatchADD},
				{Name: "X-Rep", Value: "rep", Mismatch: config.MismatchREPLACE},
			},
			want: []mismatchRoute{
				{match: []string{"X-One=one", "X-Rep=rep"}},
				{match: []string{"X-One=one"}, add: []string{"X-Rep=rep" + overwriteAction}},
				{add: []string{"X-One=one" + appendAction, "X-Rep=rep" + overwriteAction}},
			},
		},
		"ADD with DELETE and a required header": {
			matches: []config.HeaderMatch{
				{Name: "X-Required", Value: "yes"},
				{Name: "X-One", Value: "one", Mismatch: config.MismatchADD},
				{Name: "X-Del", Value: "del", Mismatch: config.MismatchDELETE},
			},
			want: []mismatchRoute{
				{match: []string{"X-Required=yes", "X-One=one", "X-Del=del"}},
				{match: []string{"X-Required=yes", "X-One=one"}, remove: []string{"X-Del"}},
				{
					match:  []string{"X-Required=yes"},
					add:    []string{"X-One=one" + appendAction},
					remove: []string{"X-Del"},
				},
			},
		},
		"REPLACE without ADD": {
			matches: []config.HeaderMatch{
				{Name: "X-Rep", Value: "rep", Mismatch: config.MismatchREPLACE},
			},
			want: []mismatchRoute{
				{match: []string{"X-Rep=rep"}},
				{add: []string{"X-Rep=rep" + overwriteAction}},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rules := []config.ResolvedRule{{
				Domain:    "api.example.com",
				HTTPRules: []config.ResolvedHTTPRule{{HeaderMatches: tt.matches}},
			}}

			assert.Equal(t, tt.want, mismatchRoutes(t, envoy.BuildHTTPForwardListener(rules, false, nil, false)))
		})
	}
}

// mismatchRoutes returns the forwarding routes of the only virtual
// host of listener, in the order of the route table. The route table
// holds each forwarding route twice, first for gRPC requests and then
// for all requests. The function requires that both routes of a pair
// are equal, and it returns one entry for the pair.
func mismatchRoutes(t *testing.T, listener envoy.Listener) []mismatchRoute {
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
									Cluster string `yaml:"cluster"`
								} `yaml:"route"`
								Match struct {
									Grpc    *struct{} `yaml:"grpc"`
									Headers []struct {
										StringMatch struct {
											Exact string `yaml:"exact"`
										} `yaml:"string_match"`
										Name string `yaml:"name"`
									} `yaml:"headers"`
								} `yaml:"match"`
								RequestHeadersToAdd []struct {
									Header struct {
										Key   string `yaml:"key"`
										Value string `yaml:"value"`
									} `yaml:"header"`
									AppendAction string `yaml:"append_action"`
								} `yaml:"request_headers_to_add"`
								RequestHeadersToRemove []string `yaml:"request_headers_to_remove"`
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

	vhosts := doc.FilterChains[0].Filters[0].TypedConfig.RouteConfig.VirtualHosts
	require.Len(t, vhosts, 1)

	var (
		grpc, plain []mismatchRoute
		grpcNext    = true
	)

	for _, r := range vhosts[0].Routes {
		// The last route denies every other request.
		if r.Route == nil {
			continue
		}

		var mr mismatchRoute

		for _, h := range r.Match.Headers {
			mr.match = append(mr.match, h.Name+"="+h.StringMatch.Exact)
		}

		for _, h := range r.RequestHeadersToAdd {
			mr.add = append(mr.add, fmt.Sprintf("%s=%s %s", h.Header.Key, h.Header.Value, h.AppendAction))
		}

		mr.remove = append(mr.remove, r.RequestHeadersToRemove...)

		require.Equal(t, grpcNext, r.Match.Grpc != nil, "gRPC and plain routes must alternate")

		if grpcNext {
			grpc = append(grpc, mr)
		} else {
			plain = append(plain, mr)
		}

		grpcNext = !grpcNext
	}

	require.Equal(t, grpc, plain)

	return plain
}
