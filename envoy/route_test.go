package envoy_test

import (
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
		"ADD mismatch generates request_headers_to_add with ADD_IF_ABSENT": {
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
				"append_action: ADD_IF_ABSENT",
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
				"append_action: ADD_IF_ABSENT",
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
