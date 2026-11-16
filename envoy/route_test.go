package envoy_test

import (
	"fmt"
	"slices"
	"strings"
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
						{Name: "X-Bad", Value: "good", Mismatch: config.MismatchDELETE},
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
		"LOG mismatch marks the route with metadata": {
			rules: []config.ResolvedRule{{
				Domain: "api.example.com",
				HTTPRules: []config.ResolvedHTTPRule{{
					HeaderMatches: []config.HeaderMatch{
						{Name: "X-Token", Value: "secret", Mismatch: config.MismatchLOG},
					},
				}},
			}},
			contains: []string{
				"filter_metadata:",
				"terrarium.header_mismatch:",
				"log_headers: X-Token",
				"envoy.access_loggers.stderr",
				"HEADER_MISMATCH",
			},
			// The Envoy router filter rejects a config for one route.
			excludes: []string{
				"typed_per_filter_config:",
				"upstream_log:",
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
				"key: terrarium.header_value.x-token",
				"exact: abc",
			},
			excludes: []string{
				"request_headers_to_add:",
				"request_headers_to_remove:",
				"filter_metadata:",
				"HEADER_MISMATCH",
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
				"key: terrarium.header_value.x-required",
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

// hcmAccessLog describes one access logger of an HTTP connection
// manager.
type hcmAccessLog struct {
	// Name is the name of the logger.
	Name string
	// Filter is the name of the extension filter of the logger.
	Filter string
	// Expression is the CEL expression of that filter.
	Expression string
	// Format is the text format of the logger.
	Format string
}

// hcmRouting describes the parts of an HTTP connection manager that
// the HEADER_MISMATCH access logger depends on.
type hcmRouting struct {
	// accessLog lists the access loggers of the connection manager.
	accessLog []hcmAccessLog
	// logHeaders lists the log_headers metadata value of each
	// forwarding route, in the order of the route table. The value
	// is empty for a route without the metadata.
	logHeaders []string
}

// TestMismatchAccessLog checks the access loggers and the route
// metadata of the HTTP connection managers that match HTTP rules.
// Envoy must write a HEADER_MISMATCH line only for the requests that
// a route with a LOG action takes. The connection manager therefore
// holds one logger whose filter matches the metadata of those routes.
//
// Envoy answers some requests before the HTTP filters run, such as a
// request for an upgrade that the connection manager does not allow.
// Envoy selects the route of such a request without the header values
// that an HTTP filter stores. The route can therefore be a LOG route
// for a request that holds every value. When a headerMatches entry of
// the connection manager has a value, the filter of the logger also
// requires the object that marks the stored values.
func TestMismatchAccessLog(t *testing.T) {
	t.Parallel()

	const routeHasMetadata = "'terrarium.header_mismatch' in xds.route_metadata.filter_metadata"

	grpcLogger := hcmAccessLog{Name: "envoy.access_loggers.http_grpc"}
	presenceLogger := hcmAccessLog{
		Name:       "envoy.access_loggers.stderr",
		Filter:     "envoy.access_loggers.extension_filters.cel",
		Expression: routeHasMetadata,
		Format: "[%START_TIME%] HEADER_MISMATCH" +
			" headers=%METADATA(ROUTE:terrarium.header_mismatch:log_headers)%" +
			" %REQ(:METHOD)% %REQ(:AUTHORITY)%%REQ(:PATH)% %RESPONSE_CODE%\n",
	}

	mismatchLogger := presenceLogger
	mismatchLogger.Expression = routeHasMetadata + " && 'terrarium.header_values_stored' in filter_state"

	tests := map[string]struct {
		matches []config.HeaderMatch
		want    hcmRouting
	}{
		"one LOG": {
			matches: []config.HeaderMatch{
				{Name: "X-Log", Value: "expected", Mismatch: config.MismatchLOG},
			},
			want: hcmRouting{
				accessLog:  []hcmAccessLog{grpcLogger, mismatchLogger},
				logHeaders: []string{"", "", "X-Log", "X-Log"},
			},
		},
		"two LOG": {
			matches: []config.HeaderMatch{
				{Name: "X-One", Value: "one", Mismatch: config.MismatchLOG},
				{Name: "X-Two", Value: "two", Mismatch: config.MismatchLOG},
			},
			want: hcmRouting{
				accessLog: []hcmAccessLog{grpcLogger, mismatchLogger},
				// Each route names only the LOG headers that its
				// requests mismatch on.
				logHeaders: []string{
					"", "",
					"X-Two", "X-Two",
					"X-One", "X-One",
					"X-One,X-Two", "X-One,X-Two",
				},
			},
		},
		"LOG with ADD": {
			matches: []config.HeaderMatch{
				{Name: "X-Log", Value: "expected", Mismatch: config.MismatchLOG},
				{Name: "X-Add", Value: "add", Mismatch: config.MismatchADD},
			},
			want: hcmRouting{
				accessLog: []hcmAccessLog{grpcLogger, mismatchLogger},
				// The requests that hold the value of X-Log take the
				// first route or the route that adds X-Add, so their
				// routes have no metadata.
				logHeaders: []string{"", "", "", "", "X-Log", "X-Log", "X-Log", "X-Log"},
			},
		},
		"LOG with REPLACE": {
			matches: []config.HeaderMatch{
				{Name: "X-Log", Value: "expected", Mismatch: config.MismatchLOG},
				{Name: "X-Rep", Value: "rep", Mismatch: config.MismatchREPLACE},
			},
			want: hcmRouting{
				accessLog: []hcmAccessLog{grpcLogger, mismatchLogger},
				// A request that holds the value of X-Log but not the
				// value of X-Rep takes the second route, which has no
				// metadata.
				logHeaders: []string{"", "", "", "", "X-Log", "X-Log"},
			},
		},
		"header name with a format character": {
			matches: []config.HeaderMatch{
				{Name: "X-%Log", Value: "expected", Mismatch: config.MismatchLOG},
			},
			want: hcmRouting{
				accessLog:  []hcmAccessLog{grpcLogger, mismatchLogger},
				logHeaders: []string{"", "", "X-%Log", "X-%Log"},
			},
		},
		// No HTTP filter stores a header value for these entries, so
		// the route that Envoy selects first is the route of the
		// request.
		"LOG without a value": {
			matches: []config.HeaderMatch{
				{Name: "X-Log", Mismatch: config.MismatchLOG},
			},
			want: hcmRouting{
				accessLog:  []hcmAccessLog{grpcLogger, presenceLogger},
				logHeaders: []string{"", "", "X-Log", "X-Log"},
			},
		},
		"LOG without a value with a required value": {
			matches: []config.HeaderMatch{
				{Name: "X-Log", Mismatch: config.MismatchLOG},
				{Name: "X-Required", Value: "yes"},
			},
			want: hcmRouting{
				accessLog:  []hcmAccessLog{grpcLogger, mismatchLogger},
				logHeaders: []string{"", "", "X-Log", "X-Log"},
			},
		},
		"ADD without LOG": {
			matches: []config.HeaderMatch{
				{Name: "X-Add", Value: "add", Mismatch: config.MismatchADD},
			},
			want: hcmRouting{
				accessLog:  []hcmAccessLog{grpcLogger},
				logHeaders: []string{"", "", "", ""},
			},
		},
		"required header without a mismatch action": {
			matches: []config.HeaderMatch{
				{Name: "X-Required", Value: "yes"},
			},
			want: hcmRouting{
				accessLog:  []hcmAccessLog{grpcLogger},
				logHeaders: []string{"", ""},
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

			// The builders must not change the loggers of the caller.
			httpAL := envoy.BuildHTTPGrpcAccessLog("http", 0, 0)
			given := slices.Clone(httpAL)

			listeners := map[string]envoy.Listener{
				"container HTTP listener":      envoy.BuildHTTPForwardListener(rules, false, httpAL, false),
				"proxy internal HTTP listener": envoy.BuildInternalHTTPListener(rules, false, httpAL, nil),
				"container TLS listener": envoy.BuildTLSListener(
					"tls_443", 15443, 443, "tls_443", rules, false, nil, httpAL, "/certs", false,
				),
				"proxy internal TLS listener": envoy.BuildInternalTLSListener(
					443, rules, false, nil, httpAL, "/certs", nil,
				),
			}

			for listenerName, listener := range listeners {
				assert.Equal(t, tt.want, routingOf(t, listener), listenerName)
			}

			assert.Equal(t, given, httpAL)
		})
	}
}

// routingOf returns the [hcmRouting] of the only filter chain of
// listener, which must hold one HTTP connection manager.
func routingOf(t *testing.T, listener envoy.Listener) hcmRouting {
	t.Helper()

	out, err := yaml.Marshal(listener)
	require.NoError(t, err)

	var doc struct {
		FilterChains []struct {
			Filters []struct {
				TypedConfig struct {
					AccessLog []struct {
						Name   string `yaml:"name"`
						Filter struct {
							ExtensionFilter struct {
								Name        string `yaml:"name"`
								TypedConfig struct {
									Expression string `yaml:"expression"`
								} `yaml:"typed_config"`
							} `yaml:"extension_filter"`
						} `yaml:"filter"`
						TypedConfig struct {
							LogFormat struct {
								TextFormatSource struct {
									InlineString string `yaml:"inline_string"`
								} `yaml:"text_format_source"`
							} `yaml:"log_format"`
						} `yaml:"typed_config"`
					} `yaml:"access_log"`
					RouteConfig struct {
						VirtualHosts []struct {
							Routes []struct {
								Route *struct {
									Cluster string `yaml:"cluster"`
								} `yaml:"route"`
								Metadata struct {
									FilterMetadata map[string]map[string]string `yaml:"filter_metadata"`
								} `yaml:"metadata"`
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

	hcm := doc.FilterChains[0].Filters[0].TypedConfig

	var got hcmRouting

	for _, al := range hcm.AccessLog {
		got.accessLog = append(got.accessLog, hcmAccessLog{
			Name:       al.Name,
			Filter:     al.Filter.ExtensionFilter.Name,
			Expression: al.Filter.ExtensionFilter.TypedConfig.Expression,
			Format:     al.TypedConfig.LogFormat.TextFormatSource.InlineString,
		})
	}

	for _, vh := range hcm.RouteConfig.VirtualHosts {
		for _, r := range vh.Routes {
			// The other routes deny their requests.
			if r.Route == nil {
				continue
			}

			// A route without the metadata holds no namespace, and
			// the lookups then return the empty string.
			require.LessOrEqual(t, len(r.Metadata.FilterMetadata), 1)

			got.logHeaders = append(got.logHeaders,
				r.Metadata.FilterMetadata["terrarium.header_mismatch"]["log_headers"])
		}
	}

	return got
}

// mismatchRoute describes one forwarding route of an HTTP rule whose
// headerMatches carry a mismatch action.
type mismatchRoute struct {
	// match lists the matchers of the route. A matcher on the presence
	// of a header is "name present". A matcher on the joined values of
	// a header is "name=value". Its name is the lowercase name in the
	// filter state key of the matcher. The matchers on the presence of
	// a header come first.
	match []string
	// add lists the request_headers_to_add entries of the route as
	// "name=value append_action". An entry that keeps an empty value
	// ends with " keep_empty_value".
	add []string
	// remove lists the request_headers_to_remove entries of the route.
	remove []string
}

// TestMismatchRouteOrder checks the routes of rules whose headerMatches
// carry a mismatch action. Envoy takes the first route that matches,
// so the order of the routes decides which header changes a request
// gets. A route must append the value of an ADD header only when no
// earlier route takes the requests that already hold the value. A
// route must remove a DELETE header under the same condition.
//
// A headerMatches entry without a value matches on the presence of
// the header. Envoy rejects an exact matcher on the empty string, so
// no route of such an entry holds one.
//
// A headerMatches entry with a value matches on the filter state
// object that holds the joined values of the header. A header matcher
// with a string matcher passes when one field of a repeated header
// holds the value, so no route holds one.
func TestMismatchRouteOrder(t *testing.T) {
	t.Parallel()

	const (
		appendAction    = " APPEND_IF_EXISTS_OR_ADD"
		overwriteAction = " OVERWRITE_IF_EXISTS_OR_ADD"
		absentAction    = " ADD_IF_ABSENT keep_empty_value"
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
				{match: []string{"x-one=one"}},
				{add: []string{"X-One=one" + appendAction}},
			},
		},
		"two ADD": {
			matches: []config.HeaderMatch{
				{Name: "X-One", Value: "one", Mismatch: config.MismatchADD},
				{Name: "X-Two", Value: "two", Mismatch: config.MismatchADD},
			},
			want: []mismatchRoute{
				{match: []string{"x-one=one", "x-two=two"}},
				{match: []string{"x-one=one"}, add: []string{"X-Two=two" + appendAction}},
				{match: []string{"x-two=two"}, add: []string{"X-One=one" + appendAction}},
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
				{match: []string{"x-one=one", "x-two=two", "x-three=three"}},
				{
					match: []string{"x-one=one", "x-two=two"},
					add:   []string{"X-Three=three" + appendAction},
				},
				{
					match: []string{"x-one=one", "x-three=three"},
					add:   []string{"X-Two=two" + appendAction},
				},
				{
					match: []string{"x-two=two", "x-three=three"},
					add:   []string{"X-One=one" + appendAction},
				},
				{
					match: []string{"x-one=one"},
					add:   []string{"X-Two=two" + appendAction, "X-Three=three" + appendAction},
				},
				{
					match: []string{"x-two=two"},
					add:   []string{"X-One=one" + appendAction, "X-Three=three" + appendAction},
				},
				{
					match: []string{"x-three=three"},
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
				{match: []string{"x-one=one", "x-rep=rep"}},
				{match: []string{"x-one=one"}, add: []string{"X-Rep=rep" + overwriteAction}},
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
				{match: []string{"x-required=yes", "x-one=one", "x-del=del"}},
				{match: []string{"x-required=yes", "x-one=one"}, remove: []string{"X-Del"}},
				{match: []string{"x-required=yes", "x-del=del"}, add: []string{"X-One=one" + appendAction}},
				{
					match:  []string{"x-required=yes"},
					add:    []string{"X-One=one" + appendAction},
					remove: []string{"X-Del"},
				},
			},
		},
		"one DELETE": {
			matches: []config.HeaderMatch{
				{Name: "X-Del", Value: "del", Mismatch: config.MismatchDELETE},
			},
			want: []mismatchRoute{
				{match: []string{"x-del=del"}},
				{remove: []string{"X-Del"}},
			},
		},
		// The route that replaces X-Rep also takes requests whose X-Del
		// holds the value, so it must match on X-Del and keep it.
		"DELETE with REPLACE": {
			matches: []config.HeaderMatch{
				{Name: "X-Del", Value: "del", Mismatch: config.MismatchDELETE},
				{Name: "X-Rep", Value: "rep", Mismatch: config.MismatchREPLACE},
			},
			want: []mismatchRoute{
				{match: []string{"x-del=del", "x-rep=rep"}},
				{match: []string{"x-del=del"}, add: []string{"X-Rep=rep" + overwriteAction}},
				{add: []string{"X-Rep=rep" + overwriteAction}, remove: []string{"X-Del"}},
			},
		},
		"DELETE with LOG": {
			matches: []config.HeaderMatch{
				{Name: "X-Del", Value: "del", Mismatch: config.MismatchDELETE},
				{Name: "X-Log", Value: "expected", Mismatch: config.MismatchLOG},
			},
			want: []mismatchRoute{
				{match: []string{"x-del=del", "x-log=expected"}},
				{match: []string{"x-del=del"}},
				{match: []string{"x-log=expected"}, remove: []string{"X-Del"}},
				{remove: []string{"X-Del"}},
			},
		},
		"two DELETE": {
			matches: []config.HeaderMatch{
				{Name: "X-One", Value: "one", Mismatch: config.MismatchDELETE},
				{Name: "X-Two", Value: "two", Mismatch: config.MismatchDELETE},
			},
			want: []mismatchRoute{
				{match: []string{"x-one=one", "x-two=two"}},
				{match: []string{"x-one=one"}, remove: []string{"X-Two"}},
				{match: []string{"x-two=two"}, remove: []string{"X-One"}},
				{remove: []string{"X-One", "X-Two"}},
			},
		},
		"LOG with REPLACE": {
			matches: []config.HeaderMatch{
				{Name: "X-Log", Value: "expected", Mismatch: config.MismatchLOG},
				{Name: "X-Rep", Value: "rep", Mismatch: config.MismatchREPLACE},
			},
			want: []mismatchRoute{
				{match: []string{"x-log=expected", "x-rep=rep"}},
				{match: []string{"x-log=expected"}, add: []string{"X-Rep=rep" + overwriteAction}},
				{add: []string{"X-Rep=rep" + overwriteAction}},
			},
		},
		"LOG with ADD": {
			matches: []config.HeaderMatch{
				{Name: "X-Log", Value: "expected", Mismatch: config.MismatchLOG},
				{Name: "X-Add", Value: "add", Mismatch: config.MismatchADD},
			},
			want: []mismatchRoute{
				{match: []string{"x-log=expected", "x-add=add"}},
				{match: []string{"x-log=expected"}, add: []string{"X-Add=add" + appendAction}},
				{match: []string{"x-add=add"}},
				{add: []string{"X-Add=add" + appendAction}},
			},
		},
		"REPLACE without ADD": {
			matches: []config.HeaderMatch{
				{Name: "X-Rep", Value: "rep", Mismatch: config.MismatchREPLACE},
			},
			want: []mismatchRoute{
				{match: []string{"x-rep=rep"}},
				{add: []string{"X-Rep=rep" + overwriteAction}},
			},
		},
		"required header without a value": {
			matches: []config.HeaderMatch{
				{Name: "X-Required"},
			},
			want: []mismatchRoute{
				{match: []string{"X-Required present"}},
			},
		},
		"LOG without a value": {
			matches: []config.HeaderMatch{
				{Name: "X-Log", Mismatch: config.MismatchLOG},
			},
			want: []mismatchRoute{
				{match: []string{"X-Log present"}},
				{},
			},
		},
		"ADD without a value": {
			matches: []config.HeaderMatch{
				{Name: "X-One", Mismatch: config.MismatchADD},
			},
			want: []mismatchRoute{
				{match: []string{"X-One present"}},
				{add: []string{"X-One=" + absentAction}},
			},
		},
		"REPLACE without a value": {
			matches: []config.HeaderMatch{
				{Name: "X-Rep", Mismatch: config.MismatchREPLACE},
			},
			want: []mismatchRoute{
				{match: []string{"X-Rep present"}},
				{add: []string{"X-Rep=" + absentAction}},
			},
		},
		// The route that adds X-One also takes requests that hold
		// X-Rep, so it must not overwrite X-Rep.
		"REPLACE without a value with ADD": {
			matches: []config.HeaderMatch{
				{Name: "X-One", Value: "one", Mismatch: config.MismatchADD},
				{Name: "X-Rep", Mismatch: config.MismatchREPLACE},
			},
			want: []mismatchRoute{
				{match: []string{"X-Rep present", "x-one=one"}},
				{match: []string{"x-one=one"}, add: []string{"X-Rep=" + absentAction}},
				{add: []string{"X-One=one" + appendAction, "X-Rep=" + absentAction}},
			},
		},
		"DELETE without a value": {
			matches: []config.HeaderMatch{
				{Name: "X-Del", Mismatch: config.MismatchDELETE},
			},
			want: []mismatchRoute{
				{},
			},
		},
		// The route that replaces X-Rep also takes requests that hold
		// X-Del, so it must not remove X-Del.
		"DELETE without a value with REPLACE": {
			matches: []config.HeaderMatch{
				{Name: "X-Del", Mismatch: config.MismatchDELETE},
				{Name: "X-Rep", Value: "rep", Mismatch: config.MismatchREPLACE},
			},
			want: []mismatchRoute{
				{match: []string{"x-rep=rep"}},
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
										StringMatch  *struct{} `yaml:"string_match"`
										Name         string    `yaml:"name"`
										PresentMatch bool      `yaml:"present_match"`
									} `yaml:"headers"`
									FilterState []struct {
										Key         string `yaml:"key"`
										StringMatch struct {
											Exact string `yaml:"exact"`
										} `yaml:"string_match"`
									} `yaml:"filter_state"`
								} `yaml:"match"`
								RequestHeadersToAdd []struct {
									Header struct {
										Key   string `yaml:"key"`
										Value string `yaml:"value"`
									} `yaml:"header"`
									AppendAction   string `yaml:"append_action"`
									KeepEmptyValue bool   `yaml:"keep_empty_value"`
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
			// Envoy requires exactly one specifier in a matcher.
			require.True(t, h.PresentMatch, "matcher on %s", h.Name)
			require.Nil(t, h.StringMatch, "matcher on %s", h.Name)

			mr.match = append(mr.match, h.Name+" present")
		}

		for _, fs := range r.Match.FilterState {
			name, found := strings.CutPrefix(fs.Key, headerValueKeyPrefix)
			require.True(t, found, "filter state key %s", fs.Key)

			// A string matcher must hold a pattern.
			require.NotEmpty(t, fs.StringMatch.Exact, "matcher on %s", fs.Key)

			mr.match = append(mr.match, name+"="+fs.StringMatch.Exact)
		}

		for _, h := range r.RequestHeadersToAdd {
			entry := fmt.Sprintf("%s=%s %s", h.Header.Key, h.Header.Value, h.AppendAction)
			if h.KeepEmptyValue {
				entry += " keep_empty_value"
			}

			mr.add = append(mr.add, entry)
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

// ruleRoute describes one forwarding route of an HTTP rule, or of a
// set of HTTP rules that one request can match.
type ruleRoute struct {
	// match lists the matchers of the route. A matcher on the path is
	// ":path~pattern", and it comes first. A route without one matches
	// every path. A matcher on the presence of a header is "name
	// present". A matcher on a header with a pattern is "name~pattern".
	// A matcher on the joined values of a header is "name=value". Its
	// name is the lowercase name in the filter state key of the
	// matcher. The matchers on the joined values come last.
	match []string
	// log lists the header names of the log_headers value in the route
	// metadata.
	log []string
	// add lists the request_headers_to_add entries of the route as
	// "name=value".
	add []string
	// remove lists the request_headers_to_remove entries of the route.
	remove []string
}

// TestHTTPRuleRouteSets checks the routes of a virtual host whose HTTP
// rules can match one request. Cilium applies the mismatch actions of
// every rule that a request matches. Envoy applies the header changes
// of the first route that matches. The virtual host must therefore
// hold routes that match the rules together and apply the actions of
// all of them. These routes must come before the routes of fewer rules.
func TestHTTPRuleRouteSets(t *testing.T) {
	t.Parallel()

	addA := config.HeaderMatch{Name: "X-A", Value: "one", Mismatch: config.MismatchADD}
	addB := config.HeaderMatch{Name: "X-B", Value: "two", Mismatch: config.MismatchADD}
	replaceC := config.HeaderMatch{Name: "X-C", Value: "three", Mismatch: config.MismatchREPLACE}

	tests := map[string]struct {
		rules []config.ResolvedHTTPRule
		want  []ruleRoute
	}{
		"rule without a path and rule with a path": {
			rules: []config.ResolvedHTTPRule{
				{HeaderMatches: []config.HeaderMatch{addB}},
				{Path: "/a/.*", HeaderMatches: []config.HeaderMatch{addA}},
			},
			want: []ruleRoute{
				// The requests that match both rules.
				{match: []string{":path~/a/.*", "x-b=two", "x-a=one"}},
				{match: []string{":path~/a/.*", "x-b=two"}, add: []string{"X-A=one"}},
				{match: []string{":path~/a/.*", "x-a=one"}, add: []string{"X-B=two"}},
				{match: []string{":path~/a/.*"}, add: []string{"X-B=two", "X-A=one"}},
				// The requests that match only the first rule.
				{match: []string{"x-b=two"}},
				{add: []string{"X-B=two"}},
				// The second rule matches no request that the first
				// rule does not match. Its routes take no request.
				{match: []string{":path~/a/.*", "x-a=one"}},
				{match: []string{":path~/a/.*"}, add: []string{"X-A=one"}},
			},
		},
		"rule without a mismatch action comes last": {
			rules: []config.ResolvedHTTPRule{
				{Method: "GET"},
				{Path: "/a", HeaderMatches: []config.HeaderMatch{addA}},
				{Path: "/b"},
			},
			want: []ruleRoute{
				{match: []string{":path~/a", "x-a=one"}},
				{match: []string{":path~/a"}, add: []string{"X-A=one"}},
				{match: []string{":method~^GET$"}},
				{match: []string{":path~/b"}},
			},
		},
		"rules that share no request": {
			rules: []config.ResolvedHTTPRule{
				{Path: "/a", HeaderMatches: []config.HeaderMatch{addA}},
				{Path: "/b", HeaderMatches: []config.HeaderMatch{addA}},
			},
			want: []ruleRoute{
				{match: []string{":path~/a", "x-a=one"}},
				{match: []string{":path~/a"}, add: []string{"X-A=one"}},
				{match: []string{":path~/b", "x-a=one"}},
				{match: []string{":path~/b"}, add: []string{"X-A=one"}},
			},
		},
		"every condition of both rules": {
			rules: []config.ResolvedHTTPRule{
				{
					Method:  "GET",
					Headers: []string{"X-Req"},
					HeaderMatches: []config.HeaderMatch{
						{Name: "X-Log", Value: "log", Mismatch: config.MismatchLOG},
					},
				},
				{
					Path: "/a",
					Host: `api\.example\.com`,
					HeaderMatches: []config.HeaderMatch{
						{Name: "X-Token", Value: "secret"},
						{Name: "X-Del", Value: "del", Mismatch: config.MismatchDELETE},
						replaceC,
					},
				},
			},
			want: []ruleRoute{
				{
					match: []string{
						":path~/a",
						":method~^GET$", "X-Req present", `:authority~^api\.example\.com(:[0-9]+)?$`,
						"x-token=secret", "x-log=log", "x-del=del", "x-c=three",
					},
				},
				{
					match: []string{
						":path~/a",
						":method~^GET$", "X-Req present", `:authority~^api\.example\.com(:[0-9]+)?$`,
						"x-token=secret", "x-log=log", "x-del=del",
					},
					add: []string{"X-C=three"},
				},
				{
					match: []string{
						":path~/a",
						":method~^GET$", "X-Req present", `:authority~^api\.example\.com(:[0-9]+)?$`,
						"x-token=secret", "x-log=log",
					},
					add:    []string{"X-C=three"},
					remove: []string{"X-Del"},
				},
				{
					match: []string{
						":path~/a",
						":method~^GET$", "X-Req present", `:authority~^api\.example\.com(:[0-9]+)?$`,
						"x-token=secret", "x-del=del",
					},
					add: []string{"X-C=three"},
					log: []string{"X-Log"},
				},
				{
					match: []string{
						":path~/a",
						":method~^GET$", "X-Req present", `:authority~^api\.example\.com(:[0-9]+)?$`,
						"x-token=secret",
					},
					add:    []string{"X-C=three"},
					remove: []string{"X-Del"},
					log:    []string{"X-Log"},
				},
				{match: []string{":method~^GET$", "X-Req present", "x-log=log"}},
				{match: []string{":method~^GET$", "X-Req present"}, log: []string{"X-Log"}},
				{
					match: []string{
						":path~/a",
						`:authority~^api\.example\.com(:[0-9]+)?$`, "x-token=secret", "x-del=del", "x-c=three",
					},
				},
				{
					match: []string{
						":path~/a",
						`:authority~^api\.example\.com(:[0-9]+)?$`,
						"x-token=secret",
						"x-del=del",
					},
					add: []string{"X-C=three"},
				},
				{
					match:  []string{":path~/a", `:authority~^api\.example\.com(:[0-9]+)?$`, "x-token=secret"},
					add:    []string{"X-C=three"},
					remove: []string{"X-Del"},
				},
			},
		},
		"three rules": {
			rules: []config.ResolvedHTTPRule{
				{HeaderMatches: []config.HeaderMatch{replaceC}},
				{Method: "GET", HeaderMatches: []config.HeaderMatch{
					{Name: "X-D", Value: "four", Mismatch: config.MismatchREPLACE},
				}},
				{Path: "/a", HeaderMatches: []config.HeaderMatch{
					{Name: "X-E", Value: "five", Mismatch: config.MismatchREPLACE},
				}},
			},
			want: []ruleRoute{
				{match: []string{":path~/a", ":method~^GET$", "x-c=three", "x-d=four", "x-e=five"}},
				{
					match: []string{":path~/a", ":method~^GET$"},
					add:   []string{"X-C=three", "X-D=four", "X-E=five"},
				},
				{match: []string{":method~^GET$", "x-c=three", "x-d=four"}},
				{match: []string{":method~^GET$"}, add: []string{"X-C=three", "X-D=four"}},
				{match: []string{":path~/a", "x-c=three", "x-e=five"}},
				{match: []string{":path~/a"}, add: []string{"X-C=three", "X-E=five"}},
				{match: []string{":path~/a", ":method~^GET$", "x-d=four", "x-e=five"}},
				{match: []string{":path~/a", ":method~^GET$"}, add: []string{"X-D=four", "X-E=five"}},
				{match: []string{"x-c=three"}},
				{add: []string{"X-C=three"}},
				{match: []string{":method~^GET$", "x-d=four"}},
				{match: []string{":method~^GET$"}, add: []string{"X-D=four"}},
				{match: []string{":path~/a", "x-e=five"}},
				{match: []string{":path~/a"}, add: []string{"X-E=five"}},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rules := []config.ResolvedRule{{Domain: "api.example.com", HTTPRules: tt.rules}}

			assert.Equal(t, tt.want, ruleRoutes(t, envoy.BuildHTTPForwardListener(rules, false, nil, false)))
		})
	}
}

// ruleRoutes returns the forwarding routes of the only virtual host of
// listener, in the order of the route table. The route table holds
// each forwarding route twice, first for gRPC requests and then for
// all requests. The function requires that both routes of a pair are
// equal, and it returns one entry for the pair. It also requires that
// the last route of the virtual host denies every other request.
func ruleRoutes(t *testing.T, listener envoy.Listener) []ruleRoute {
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
								Metadata struct {
									FilterMetadata map[string]map[string]string `yaml:"filter_metadata"`
								} `yaml:"metadata"`
								Match struct {
									Grpc      *struct{} `yaml:"grpc"`
									SafeRegex *struct {
										Regex string `yaml:"regex"`
									} `yaml:"safe_regex"`
									Prefix  string `yaml:"prefix"`
									Headers []struct {
										StringMatch *struct {
											SafeRegex struct {
												Regex string `yaml:"regex"`
											} `yaml:"safe_regex"`
										} `yaml:"string_match"`
										Name         string `yaml:"name"`
										PresentMatch bool   `yaml:"present_match"`
									} `yaml:"headers"`
									FilterState []struct {
										Key         string `yaml:"key"`
										StringMatch struct {
											Exact string `yaml:"exact"`
										} `yaml:"string_match"`
									} `yaml:"filter_state"`
								} `yaml:"match"`
								RequestHeadersToAdd []struct {
									Header struct {
										Key   string `yaml:"key"`
										Value string `yaml:"value"`
									} `yaml:"header"`
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

	routes := vhosts[0].Routes
	require.NotEmpty(t, routes)

	last := routes[len(routes)-1]
	require.Nil(t, last.Route, "the last route must deny")
	require.Equal(t, "/", last.Match.Prefix)
	require.Empty(t, last.Match.Headers)

	var (
		grpc, plain []ruleRoute
		grpcNext    = true
	)

	for i := range len(routes) - 1 {
		r := &routes[i]

		require.NotNil(t, r.Route, "only the last route denies")

		var rr ruleRoute

		// Envoy requires exactly one path specifier in a route match.
		if r.Match.SafeRegex != nil {
			require.Empty(t, r.Match.Prefix)

			rr.match = append(rr.match, ":path~"+r.Match.SafeRegex.Regex)
		} else {
			require.Equal(t, "/", r.Match.Prefix)
		}

		for _, h := range r.Match.Headers {
			if h.PresentMatch {
				require.Nil(t, h.StringMatch, "matcher on %s", h.Name)

				rr.match = append(rr.match, h.Name+" present")

				continue
			}

			require.NotNil(t, h.StringMatch, "matcher on %s", h.Name)

			rr.match = append(rr.match, h.Name+"~"+h.StringMatch.SafeRegex.Regex)
		}

		for _, fs := range r.Match.FilterState {
			name, found := strings.CutPrefix(fs.Key, headerValueKeyPrefix)
			require.True(t, found, "filter state key %s", fs.Key)

			rr.match = append(rr.match, name+"="+fs.StringMatch.Exact)
		}

		for _, h := range r.RequestHeadersToAdd {
			rr.add = append(rr.add, h.Header.Key+"="+h.Header.Value)
		}

		rr.remove = append(rr.remove, r.RequestHeadersToRemove...)

		require.LessOrEqual(t, len(r.Metadata.FilterMetadata), 1)

		logHeaders := r.Metadata.FilterMetadata["terrarium.header_mismatch"]["log_headers"]
		if logHeaders != "" {
			rr.log = append(rr.log, strings.Split(logHeaders, ",")...)
		}

		require.Equal(t, grpcNext, r.Match.Grpc != nil, "gRPC and plain routes must alternate")

		if grpcNext {
			grpc = append(grpc, rr)
		} else {
			plain = append(plain, rr)
		}

		grpcNext = !grpcNext
	}

	require.Equal(t, grpc, plain)

	return plain
}
