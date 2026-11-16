package config_test

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
)

func TestResolvedHTTPRuleMismatchActions(t *testing.T) {
	t.Parallel()

	var (
		plain       = config.HeaderMatch{Name: "X-Token", Value: "secret"}
		log         = config.HeaderMatch{Name: "X-Log", Mismatch: config.MismatchLOG}
		add         = config.HeaderMatch{Name: "X-Add", Value: "one", Mismatch: config.MismatchADD}
		replace     = config.HeaderMatch{Name: "X-Rep", Mismatch: config.MismatchREPLACE}
		deleteValue = config.HeaderMatch{Name: "X-Del", Value: "bad", Mismatch: config.MismatchDELETE}
		deleteAny   = config.HeaderMatch{Name: "X-Del", Mismatch: config.MismatchDELETE}
	)

	tests := map[string]struct {
		matches []config.HeaderMatch
		want    []config.HeaderMatch
	}{
		"no entries": {},
		"entry without mismatch": {
			matches: []config.HeaderMatch{plain},
		},
		"DELETE without value changes no request": {
			matches: []config.HeaderMatch{deleteAny},
		},
		"every action in the order of the rule": {
			matches: []config.HeaderMatch{replace, plain, log, deleteAny, deleteValue, add},
			want:    []config.HeaderMatch{replace, log, deleteValue, add},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rule := config.ResolvedHTTPRule{HeaderMatches: tt.matches}

			assert.Equal(t, tt.want, rule.MismatchActions())
		})
	}
}

// logRule returns an HTTP rule with a LOG mismatch action. The rule
// logs the header "X-Log-" and n, so two rules with different n do not
// read a header that the other one changes.
func logRule(n int, rule config.ResolvedHTTPRule) config.ResolvedHTTPRule {
	rule.HeaderMatches = append(rule.HeaderMatches, config.HeaderMatch{
		Name:     "X-Log-" + strconv.Itoa(n),
		Value:    "value",
		Mismatch: config.MismatchLOG,
	})

	return rule
}

func TestMismatchRuleSets(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		rules []config.ResolvedHTTPRule
		want  [][]int
	}{
		"no rules": {},
		"rules without a mismatch action": {
			rules: []config.ResolvedHTTPRule{
				{Path: "/a"},
				{HeaderMatches: []config.HeaderMatch{{Name: "X-Token", Value: "secret"}}},
				{HeaderMatches: []config.HeaderMatch{{Name: "X-Del", Mismatch: config.MismatchDELETE}}},
			},
		},
		"one rule": {
			rules: []config.ResolvedHTTPRule{{Path: "/plain"}, logRule(0, config.ResolvedHTTPRule{})},
			want:  [][]int{{1}},
		},
		"rule without a path and rule with a path": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{}),
				logRule(1, config.ResolvedHTTPRule{Path: "/a/.*"}),
			},
			want: [][]int{{0, 1}, {0}, {1}},
		},
		"same path": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Path: "/a/.*", Method: "GET"}),
				logRule(1, config.ResolvedHTTPRule{Path: "/a/.*"}),
			},
			want: [][]int{{0, 1}, {0}, {1}},
		},
		"different literal paths": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Path: "/a"}),
				logRule(1, config.ResolvedHTTPRule{Path: "/ab"}),
			},
			want: [][]int{{0}, {1}},
		},
		"different literal starts of two path patterns": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Path: "/a/.*"}),
				logRule(1, config.ResolvedHTTPRule{Path: "/b/.*"}),
			},
			want: [][]int{{0}, {1}},
		},
		"literal path that a pattern cannot match": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Path: "/a"}),
				logRule(1, config.ResolvedHTTPRule{Path: "/a/.*"}),
			},
			want: [][]int{{0}, {1}},
		},
		// The two rules can match the request "/a/b". An Envoy route
		// cannot match two path patterns, so the rules stay apart.
		"different paths that share a request": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Path: "/a/.*"}),
				logRule(1, config.ResolvedHTTPRule{Path: "/a/b"}),
			},
			want: [][]int{{0}, {1}},
		},
		"different methods": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Method: "GET"}),
				logRule(1, config.ResolvedHTTPRule{Method: "POST"}),
			},
			want: [][]int{{0}, {1}},
		},
		"method pattern that holds the other method": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Method: "GET|POST"}),
				logRule(1, config.ResolvedHTTPRule{Method: "POST"}),
			},
			want: [][]int{{0, 1}, {0}, {1}},
		},
		"different hosts": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Host: `a\.example\.com`}),
				logRule(1, config.ResolvedHTTPRule{Host: `^b\.example\.com$`}),
			},
			want: [][]int{{0}, {1}},
		},
		// Envoy accepts only a port after the host, so the host
		// "example.com" excludes the host "example.com.au".
		"host that starts with the other host": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Host: `example\.com`}),
				logRule(1, config.ResolvedHTTPRule{Host: `example\.com\.au`}),
			},
			want: [][]int{{0}, {1}},
		},
		"host pattern that matches the other host": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Host: `example\.com.*`}),
				logRule(1, config.ResolvedHTTPRule{Host: `example\.com\.au`}),
			},
			want: [][]int{{0, 1}, {0}, {1}},
		},
		"host patterns with different subdomains": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Host: `.*\.a\.example\.com`}),
				logRule(1, config.ResolvedHTTPRule{Host: `.*\.b\.example\.com`}),
			},
			want: [][]int{{0}, {1}},
		},
		"host patterns that share a host": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Host: `.*\.example\.com`}),
				logRule(1, config.ResolvedHTTPRule{Host: `api\..*`}),
			},
			want: [][]int{{0, 1}, {0}, {1}},
		},
		"path patterns that start with a class": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Path: "/v[12]/a/.*"}),
				logRule(1, config.ResolvedHTTPRule{Path: "/v[12]/b/.*"}),
			},
			want: [][]int{{0}, {1}},
		},
		"path patterns with different ends": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Path: `.*\.json`}),
				logRule(1, config.ResolvedHTTPRule{Path: `.*\.xml`}),
			},
			want: [][]int{{0}, {1}},
		},
		"path pattern with an alternative that matches the other path": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Path: "/(a|b)/.*", Method: "GET"}),
				logRule(1, config.ResolvedHTTPRule{Path: "/(a|b)/.*", Host: `b\.example\.com`}),
				logRule(2, config.ResolvedHTTPRule{Path: "/(c|d)/.*", Method: "G.*"}),
			},
			want: [][]int{{0, 1}, {0}, {1}, {2}},
		},
		"methods without regard to case": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Method: "(?i)get"}),
				logRule(1, config.ResolvedHTTPRule{Method: "GET"}),
			},
			want: [][]int{{0, 1}, {0}, {1}},
		},
		"different values of a required header": {
			rules: []config.ResolvedHTTPRule{
				logRule(
					0,
					config.ResolvedHTTPRule{HeaderMatches: []config.HeaderMatch{{Name: "X-Tenant", Value: "a"}}},
				),
				logRule(
					1,
					config.ResolvedHTTPRule{HeaderMatches: []config.HeaderMatch{{Name: "x-tenant", Value: "b"}}},
				),
			},
			want: [][]int{{0}, {1}},
		},
		"same value of a required header": {
			rules: []config.ResolvedHTTPRule{
				logRule(
					0,
					config.ResolvedHTTPRule{HeaderMatches: []config.HeaderMatch{{Name: "X-Tenant", Value: "a"}}},
				),
				logRule(
					1,
					config.ResolvedHTTPRule{HeaderMatches: []config.HeaderMatch{{Name: "X-Tenant", Value: "a"}}},
				),
			},
			want: [][]int{{0, 1}, {0}, {1}},
		},
		"required value and a header that must be present": {
			rules: []config.ResolvedHTTPRule{
				logRule(
					0,
					config.ResolvedHTTPRule{HeaderMatches: []config.HeaderMatch{{Name: "X-Tenant", Value: "a"}}},
				),
				logRule(1, config.ResolvedHTTPRule{HeaderMatches: []config.HeaderMatch{{Name: "X-Tenant"}}}),
			},
			want: [][]int{{0, 1}, {0}, {1}},
		},
		// A rule that changes the header can make a request match the
		// other value, so the values prove nothing.
		"different values of a header that a rule changes": {
			rules: []config.ResolvedHTTPRule{
				logRule(
					0,
					config.ResolvedHTTPRule{HeaderMatches: []config.HeaderMatch{{Name: "X-Tenant", Value: "a"}}},
				),
				logRule(
					1,
					config.ResolvedHTTPRule{HeaderMatches: []config.HeaderMatch{{Name: "X-Tenant", Value: "b"}}},
				),
				{
					Method: "POST",
					HeaderMatches: []config.HeaderMatch{
						{Name: "X-Tenant", Value: "a", Mismatch: config.MismatchREPLACE},
					},
				},
			},
			want: [][]int{{0, 1, 2}, {0, 1}, {0, 2}, {1, 2}, {0}, {1}, {2}},
		},
		// The two methods share no text, but their programs have too
		// many pairs of states to compare.
		"methods too large to compare": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Method: "(.*/){240}a"}),
				logRule(1, config.ResolvedHTTPRule{Method: "(.*/){240}b"}),
			},
			want: [][]int{{0, 1}, {0}, {1}},
		},
		"path and method of different rules": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{Method: "GET"}),
				logRule(1, config.ResolvedHTTPRule{Path: "/a"}),
			},
			want: [][]int{{0, 1}, {0}, {1}},
		},
		"rule without a mismatch action between two rules": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{}),
				{Path: "/plain"},
				logRule(1, config.ResolvedHTTPRule{Method: "GET"}),
			},
			want: [][]int{{0, 2}, {0}, {2}},
		},
		"three rules": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{}),
				logRule(1, config.ResolvedHTTPRule{Method: "GET"}),
				logRule(2, config.ResolvedHTTPRule{Path: "/a"}),
			},
			want: [][]int{{0, 1, 2}, {0, 1}, {0, 2}, {1, 2}, {0}, {1}, {2}},
		},
		// The first rule shares requests with each of the other two
		// rules, but no request matches all three.
		"two rules that share no request and a third rule": {
			rules: []config.ResolvedHTTPRule{
				logRule(0, config.ResolvedHTTPRule{}),
				logRule(1, config.ResolvedHTTPRule{Path: "/a"}),
				logRule(2, config.ResolvedHTTPRule{Path: "/b"}),
			},
			want: [][]int{{0, 1}, {0, 2}, {0}, {1}, {2}},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, config.MismatchRuleSets(tt.rules))
		})
	}
}

// TestValidateMismatchAcrossRules checks the HTTP rules that have a
// mismatch action and can match one request. Cilium applies the
// actions of every rule that a request matches, one rule after the
// other. Validation rejects the rules for which the Envoy routes cannot
// give that result.
func TestValidateMismatchAcrossRules(t *testing.T) {
	t.Parallel()

	var (
		addA     = config.HeaderMatch{Name: "X-A", Value: "one", Mismatch: config.MismatchADD}
		addB     = config.HeaderMatch{Name: "X-B", Value: "two", Mismatch: config.MismatchADD}
		replaceA = config.HeaderMatch{Name: "X-A", Value: "one", Mismatch: config.MismatchREPLACE}
		logA     = config.HeaderMatch{Name: "X-A", Value: "one", Mismatch: config.MismatchLOG}
		tokenA   = config.HeaderMatch{Name: "Authorization", Value: "tokA", Mismatch: config.MismatchREPLACE}
		tokenB   = config.HeaderMatch{Name: "Authorization", Value: "tokB", Mismatch: config.MismatchREPLACE}
	)

	// Each two of the paths share no text, but the comparison of each
	// two of them spends much work.
	largePathRules := func(n int) []config.HTTPRule {
		rules := make([]config.HTTPRule, 0, n)
		for i := range n {
			rules = append(rules, config.HTTPRule{
				Path:          fmt.Sprintf("(.*/){200}x%02d", i),
				HeaderMatches: []config.HeaderMatch{addA},
			})
		}

		return rules
	}

	logRules := func(n int) []config.HTTPRule {
		rules := make([]config.HTTPRule, 0, n)
		for i := range n {
			rules = append(rules, config.HTTPRule(logRule(i, config.ResolvedHTTPRule{})))
		}

		return rules
	}

	// The rules of one group differ by path, by method, or by host, so
	// no request matches two rules of one group. Each request can match
	// one rule of each group, so the sets of two or more rules grow
	// with n^3.
	groupRules := func(n int) []config.HTTPRule {
		rules := make([]config.HTTPRule, 0, 3*n)
		for i := range n {
			rules = append(rules,
				config.HTTPRule(logRule(3*i, config.ResolvedHTTPRule{Path: "/p" + strconv.Itoa(i)})),
				config.HTTPRule(logRule(3*i+1, config.ResolvedHTTPRule{Method: "M" + strconv.Itoa(i)})),
				config.HTTPRule(logRule(3*i+2, config.ResolvedHTTPRule{Host: "h" + strconv.Itoa(i)})),
			)
		}

		return rules
	}

	tests := map[string]struct {
		err   error
		want  string
		rules []config.HTTPRule
	}{
		// 48 pairs count 4 each and 64 triples count 8 each, 704 in
		// total.
		"704 route combinations of shared rules accepted": {
			rules: groupRules(4),
		},
		// 75 pairs count 4 each and 125 triples count 8 each, 1300 in
		// total.
		"1300 route combinations of shared rules rejected": {
			rules: groupRules(5),
			err:   config.ErrHTTPRuleMismatchRoutesTooMany,
			want:  `port 443 domain "api.example.com" has more than 1024`,
		},
		"route combinations of rules that share no request accepted": {
			rules: []config.HTTPRule{
				{Path: "/a", HeaderMatches: addHeaderMatches(8)},
				{Path: "/b", HeaderMatches: addHeaderMatches(8)},
				{Path: "/c", HeaderMatches: addHeaderMatches(8)},
				{Path: "/d", HeaderMatches: addHeaderMatches(8)},
				{Path: "/e", HeaderMatches: addHeaderMatches(8)},
			},
		},
		"actions on different headers accepted": {
			rules: []config.HTTPRule{
				{Path: "/a/.*", HeaderMatches: []config.HeaderMatch{addA}},
				{HeaderMatches: []config.HeaderMatch{addB}},
			},
		},
		"same header in rules that share no request accepted": {
			rules: []config.HTTPRule{
				{Path: "/a", HeaderMatches: []config.HeaderMatch{addA}},
				{Path: "/b", HeaderMatches: []config.HeaderMatch{addA}},
			},
		},
		"different paths that share no request accepted": {
			rules: []config.HTTPRule{
				{Path: "/a/.*", HeaderMatches: []config.HeaderMatch{addA}},
				{Path: "/b/.*", HeaderMatches: []config.HeaderMatch{addB}},
			},
		},
		"path patterns that start with a class accepted": {
			rules: []config.HTTPRule{
				{Path: "/v[12]/a/.*", HeaderMatches: []config.HeaderMatch{tokenA}},
				{Path: "/v[12]/b/.*", HeaderMatches: []config.HeaderMatch{tokenB}},
			},
		},
		"path patterns with different ends accepted": {
			rules: []config.HTTPRule{
				{Path: `.*\.json`, HeaderMatches: []config.HeaderMatch{addA}},
				{Path: `.*\.xml`, HeaderMatches: []config.HeaderMatch{addB}},
			},
		},
		"path pattern with a class that matches the other path rejected": {
			rules: []config.HTTPRule{
				{Path: "/v[12]/.*", HeaderMatches: []config.HeaderMatch{tokenA}},
				{Path: "/v1/a", HeaderMatches: []config.HeaderMatch{tokenB}},
			},
			err:  config.ErrHTTPRuleMismatchPaths,
			want: `port 443 domain "api.example.com" http rules {path "/v1/a"} and {path "/v[12]/.*"}`,
		},
		"host patterns with different subdomains accepted": {
			rules: []config.HTTPRule{
				{Host: `.*\.a\.example\.com`, HeaderMatches: []config.HeaderMatch{tokenA}},
				{Host: `.*\.b\.example\.com`, HeaderMatches: []config.HeaderMatch{tokenB}},
			},
		},
		"host patterns that share a host rejected": {
			rules: []config.HTTPRule{
				{Host: `.*\.example\.com`, HeaderMatches: []config.HeaderMatch{tokenA}},
				{Host: `api\..*`, HeaderMatches: []config.HeaderMatch{tokenB}},
			},
			err: config.ErrHeaderMatchMismatchAcrossRules,
		},
		"different values of a required header accepted": {
			rules: []config.HTTPRule{
				{HeaderMatches: []config.HeaderMatch{{Name: "X-Tenant", Value: "a"}, tokenA}},
				{HeaderMatches: []config.HeaderMatch{{Name: "X-Tenant", Value: "b"}, tokenB}},
			},
		},
		"same value of a required header rejected": {
			rules: []config.HTTPRule{
				{HeaderMatches: []config.HeaderMatch{{Name: "X-Tenant", Value: "a"}, tokenA}},
				{Method: "GET", HeaderMatches: []config.HeaderMatch{{Name: "X-Tenant", Value: "a"}, tokenB}},
			},
			err: config.ErrHeaderMatchMismatchAcrossRules,
		},
		"different values of a required header that a rule changes rejected": {
			rules: []config.HTTPRule{
				{HeaderMatches: []config.HeaderMatch{{Name: "X-Tenant", Value: "a"}, tokenA}},
				{HeaderMatches: []config.HeaderMatch{{Name: "X-Tenant", Value: "b"}, tokenB}},
				{
					Path: "/c",
					HeaderMatches: []config.HeaderMatch{
						{Name: "X-Tenant", Value: "a", Mismatch: config.MismatchREPLACE},
					},
				},
			},
			err: config.ErrHeaderMatchMismatchAcrossRules,
		},
		"different paths with different methods accepted": {
			rules: []config.HTTPRule{
				{Path: "/a/.*", Method: "GET", HeaderMatches: []config.HeaderMatch{addA}},
				{Path: "/a/b", Method: "POST", HeaderMatches: []config.HeaderMatch{addB}},
			},
		},
		// The two paths share no text, but their programs have too many
		// pairs of states to compare.
		"paths too large to compare rejected": {
			rules: []config.HTTPRule{
				{Path: "(.*/){240}a", HeaderMatches: []config.HeaderMatch{addA}},
				{Path: "(.*/){240}b", HeaderMatches: []config.HeaderMatch{addB}},
			},
			err:  config.ErrHTTPRuleMismatchPaths,
			want: `port 443 domain "api.example.com" http rules {path "(.*/){240}a"} and {path "(.*/){240}b"}`,
		},
		// Each two of the paths share no text. The comparisons of three
		// paths fit the work that the comparisons of one rule list
		// share.
		"large paths within the comparison work accepted": {
			rules: largePathRules(3),
		},
		// The comparisons of the first pairs of paths spend the work
		// that the comparisons of one rule list share. The later pairs
		// count as pairs that can match one request.
		// The literal prefixes of the paths prove that no two of them
		// share a text, so the comparisons spend no work.
		"large paths with different literal prefixes accepted": {
			rules: func() []config.HTTPRule {
				rules := largePathRules(40)
				for i := range rules {
					rules[i].Path = fmt.Sprintf("/x%02d/", i) + rules[i].Path
				}

				return rules
			}(),
		},
		"many literal paths with one REPLACE action accepted": {
			rules: func() []config.HTTPRule {
				rules := make([]config.HTTPRule, 0, 1000)
				for i := range 1000 {
					rules = append(rules, config.HTTPRule{
						Path:          fmt.Sprintf("/repos/my-org/service/api/v1/resources/item%04d", i),
						HeaderMatches: []config.HeaderMatch{tokenA},
					})
				}

				return rules
			}(),
		},
		// A literal prefix that ignores case proves nothing, so the
		// walk over the states finds the request "/A".
		"literal paths that match one request without regard to case rejected": {
			rules: []config.HTTPRule{
				{Path: "(?i)/a", HeaderMatches: []config.HeaderMatch{addA}},
				{Path: "/A", HeaderMatches: []config.HeaderMatch{addB}},
			},
			err:  config.ErrHTTPRuleMismatchPaths,
			want: `http rules {path "(?i)/a"} and {path "/A"}`,
		},
		"large paths past the comparison work rejected": {
			rules: largePathRules(40),
			err:   config.ErrHTTPRuleMismatchPaths,
			want:  `port 443 domain "api.example.com" http rules {path "(.*/){200}x00"} and {path "(.*/){200}x`,
		},
		"different paths that share a request rejected": {
			rules: []config.HTTPRule{
				{Path: "/a/.*", HeaderMatches: []config.HeaderMatch{addA}},
				{Path: "/a/b", Method: "GET", HeaderMatches: []config.HeaderMatch{addB}},
			},
			err:  config.ErrHTTPRuleMismatchPaths,
			want: `port 443 domain "api.example.com" http rules {path "/a/.*"} and {path "/a/b", method "GET"}`,
		},
		"different paths and a rule without a mismatch action accepted": {
			rules: []config.HTTPRule{
				{Path: "/a/.*", HeaderMatches: []config.HeaderMatch{addA}},
				{Path: "/a/b"},
			},
		},
		"ADD to a header that the other rule adds rejected": {
			rules: []config.HTTPRule{
				{Path: "/a/.*", HeaderMatches: []config.HeaderMatch{addA}},
				{HeaderMatches: []config.HeaderMatch{{Name: "x-a", Value: "two", Mismatch: config.MismatchADD}}},
			},
			err: config.ErrHeaderMatchMismatchAcrossRules,
			want: `port 443 domain "api.example.com" http rule {} changes "x-a" with mismatch "ADD",` +
				` and http rule {path "/a/.*"} reads it`,
		},
		"REPLACE of a header that the other rule logs rejected": {
			rules: []config.HTTPRule{
				{Method: "GET", HeaderMatches: []config.HeaderMatch{replaceA}},
				{Host: "api", HeaderMatches: []config.HeaderMatch{logA}},
			},
			err: config.ErrHeaderMatchMismatchAcrossRules,
			want: `port 443 domain "api.example.com" http rule {method "GET"} changes "X-A" with mismatch "REPLACE",` +
				` and http rule {host "api"} reads it`,
		},
		"DELETE of a header that the other rule requires rejected": {
			rules: []config.HTTPRule{
				{HeaderMatches: []config.HeaderMatch{{Name: "X-A", Value: "bad", Mismatch: config.MismatchDELETE}}},
				{Method: "GET", Headers: []string{"x-a"}, HeaderMatches: []config.HeaderMatch{addB}},
			},
			err: config.ErrHeaderMatchMismatchAcrossRules,
		},
		"ADD to a header that the other rule compares rejected": {
			rules: []config.HTTPRule{
				{HeaderMatches: []config.HeaderMatch{addA}},
				{Method: "GET", HeaderMatches: []config.HeaderMatch{{Name: "X-A", Value: "one"}, addB}},
			},
			err: config.ErrHeaderMatchMismatchAcrossRules,
		},
		"ADD to a header that a rule without a mismatch action compares accepted": {
			rules: []config.HTTPRule{
				{HeaderMatches: []config.HeaderMatch{addA}},
				{Method: "GET", HeaderMatches: []config.HeaderMatch{{Name: "X-A", Value: "one"}}},
			},
		},
		"ADD to a header of a DELETE without value accepted": {
			rules: []config.HTTPRule{
				{HeaderMatches: []config.HeaderMatch{addA}},
				{
					Method:        "GET",
					HeaderMatches: []config.HeaderMatch{{Name: "X-A", Mismatch: config.MismatchDELETE}, addB},
				},
			},
		},
		"LOG of a header that the other rule logs accepted": {
			rules: []config.HTTPRule{
				{HeaderMatches: []config.HeaderMatch{logA}},
				{
					Method:        "GET",
					HeaderMatches: []config.HeaderMatch{{Name: "X-A", Value: "two", Mismatch: config.MismatchLOG}},
				},
			},
		},
		"same REPLACE in both rules accepted": {
			rules: []config.HTTPRule{
				{HeaderMatches: []config.HeaderMatch{replaceA}},
				{Method: "GET", HeaderMatches: []config.HeaderMatch{replaceA, addB}},
			},
		},
		"REPLACE with another value in the other rule rejected": {
			rules: []config.HTTPRule{
				{HeaderMatches: []config.HeaderMatch{replaceA}},
				{
					Method:        "GET",
					HeaderMatches: []config.HeaderMatch{{Name: "X-A", Value: "two", Mismatch: config.MismatchREPLACE}},
				},
			},
			err: config.ErrHeaderMatchMismatchAcrossRules,
		},
		"same REPLACE and a LOG of the header in the other rule rejected": {
			rules: []config.HTTPRule{
				{HeaderMatches: []config.HeaderMatch{replaceA}},
				{Method: "GET", HeaderMatches: []config.HeaderMatch{logA, replaceA}},
			},
			err: config.ErrHeaderMatchMismatchAcrossRules,
		},
		"four rules that one request can match accepted": {
			rules: logRules(4),
		},
		"five rules that one request can match rejected": {
			rules: logRules(5),
			err:   config.ErrHTTPRuleMismatchTooMany,
			want:  `port 443 domain "api.example.com" has 5`,
		},
		"five rules of which four can match one request accepted": {
			rules: []config.HTTPRule{
				config.HTTPRule(logRule(0, config.ResolvedHTTPRule{})),
				config.HTTPRule(logRule(1, config.ResolvedHTTPRule{Method: "GET"})),
				config.HTTPRule(logRule(2, config.ResolvedHTTPRule{Host: "api"})),
				config.HTTPRule(logRule(3, config.ResolvedHTTPRule{Path: "/a"})),
				config.HTTPRule(logRule(4, config.ResolvedHTTPRule{Path: "/b"})),
			},
		},
		"eight ADD, DELETE, and LOG entries in two rules accepted": {
			rules: []config.HTTPRule{
				{HeaderMatches: addHeaderMatches(7)},
				config.HTTPRule(logRule(0, config.ResolvedHTTPRule{Method: "GET"})),
			},
		},
		"nine ADD, DELETE, and LOG entries in two rules rejected": {
			rules: []config.HTTPRule{
				{HeaderMatches: addHeaderMatches(8)},
				config.HTTPRule(logRule(0, config.ResolvedHTTPRule{Method: "GET"})),
			},
			err:  config.ErrHeaderMatchMismatchTooMany,
			want: `port 443 domain "api.example.com" has 9 in 2 http rules`,
		},
		"nine ADD, DELETE, and LOG entries in rules that share no request accepted": {
			rules: []config.HTTPRule{
				{Method: "POST", HeaderMatches: addHeaderMatches(8)},
				config.HTTPRule(logRule(0, config.ResolvedHTTPRule{Method: "GET"})),
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.Config{
				Egress: egressRules(config.EgressRule{
					ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
					ToPorts: []config.PortRule{{
						Ports: []config.Port{{Port: "443"}},
						Rules: &config.L7Rules{HTTP: tt.rules},
					}},
				}),
			}

			err := cfg.Validate(t.Context())
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				assert.ErrorContains(t, err, tt.want)

				return
			}

			require.NoError(t, err)
		})
	}
}

// TestValidateMismatchRulesOfOneVirtualHost checks that validation
// compares the HTTP rules that reach one Envoy virtual host, which
// serves one domain on one port. The rules of two egress rules for one
// domain and one port reach one virtual host.
func TestValidateMismatchRulesOfOneVirtualHost(t *testing.T) {
	t.Parallel()

	egress := func(domain, port string, rule config.HTTPRule) config.EgressRule {
		return config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: domain}},
			ToPorts: []config.PortRule{{
				Ports: []config.Port{{Port: port}},
				Rules: &config.L7Rules{HTTP: []config.HTTPRule{rule}},
			}},
		}
	}

	var (
		addA = config.HTTPRule{HeaderMatches: []config.HeaderMatch{
			{Name: "X-A", Value: "one", Mismatch: config.MismatchADD},
		}}
		replaceA = config.HTTPRule{Method: "GET", HeaderMatches: []config.HeaderMatch{
			{Name: "X-A", Value: "two", Mismatch: config.MismatchREPLACE},
		}}
		// apartAddZ and readsD require different values of the header
		// "a", but sharedAddZ and readsD read the headers "a=b" and "a".
		apartAddZ = config.HTTPRule{HeaderMatches: []config.HeaderMatch{
			{Name: "a", Value: "b=c"},
			{Name: "z", Value: "1", Mismatch: config.MismatchADD},
		}}
		sharedAddZ = config.HTTPRule{HeaderMatches: []config.HeaderMatch{
			{Name: "a=b", Value: "c"},
			{Name: "z", Value: "1", Mismatch: config.MismatchADD},
		}}
		readsD = config.HTTPRule{HeaderMatches: []config.HeaderMatch{
			{Name: "a", Value: "d"},
			{Name: "z", Value: "1", Mismatch: config.MismatchLOG},
		}}
	)

	tests := map[string]struct {
		err    error
		want   string
		egress []config.EgressRule
	}{
		"two egress rules for one domain and one port rejected": {
			egress: []config.EgressRule{
				egress("api.example.com", "8443", addA),
				egress("api.example.com", "8443", replaceA),
			},
			err:  config.ErrHeaderMatchMismatchAcrossRules,
			want: `port 8443 domain "api.example.com"`,
		},
		"two egress rules for one domain and port 80 rejected": {
			egress: []config.EgressRule{
				egress("api.example.com", "80", addA),
				egress("api.example.com", "80", replaceA),
			},
			err:  config.ErrHeaderMatchMismatchAcrossRules,
			want: `port 80 domain "api.example.com"`,
		},
		"two domains accepted": {
			egress: []config.EgressRule{
				egress("api.example.com", "443", addA),
				egress("www.example.com", "443", replaceA),
			},
		},
		"port range rejected at its first port": {
			egress: []config.EgressRule{{
				ToFQDNs: []config.FQDNSelector{{MatchName: "api.example.com"}},
				ToPorts: []config.PortRule{{
					Ports: []config.Port{{Port: "8000", EndPort: 8099}},
					Rules: &config.L7Rules{HTTP: []config.HTTPRule{addA, replaceA}},
				}},
			}},
			err:  config.ErrHeaderMatchMismatchAcrossRules,
			want: `port 8000 domain "api.example.com"`,
		},
		"two ports accepted": {
			egress: []config.EgressRule{
				egress("api.example.com", "443", addA),
				egress("api.example.com", "8443", replaceA),
			},
		},
		// The rules of the two domains join to the same text, but only
		// the rules of b.example.com can match one request.
		"rule lists that join to the same text rejected at the second domain": {
			egress: []config.EgressRule{
				egress("a.example.com", "443", apartAddZ),
				egress("a.example.com", "443", readsD),
				egress("b.example.com", "443", sharedAddZ),
				egress("b.example.com", "443", readsD),
			},
			err:  config.ErrHeaderMatchMismatchAcrossRules,
			want: `port 443 domain "b.example.com"`,
		},
		"rule lists that join to the same text rejected at the first domain": {
			egress: []config.EgressRule{
				egress("a.example.com", "443", sharedAddZ),
				egress("a.example.com", "443", readsD),
				egress("b.example.com", "443", apartAddZ),
				egress("b.example.com", "443", readsD),
			},
			err:  config.ErrHeaderMatchMismatchAcrossRules,
			want: `port 443 domain "a.example.com"`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := &config.Config{Egress: egressRules(tt.egress...)}

			err := cfg.Validate(t.Context())
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				assert.ErrorContains(t, err, tt.want)

				return
			}

			require.NoError(t, err)
		})
	}
}

// TestMismatchRuleSetsMemo checks that the rule sets of one rule list
// are computed once, however many domains and ports hold the list.
func TestMismatchRuleSetsMemo(t *testing.T) {
	t.Parallel()

	// The comparisons of the paths spend much of the work that the
	// comparisons of one rule list share.
	costly := make([]config.HTTPRule, 0, 4)
	for i := range 4 {
		costly = append(costly, config.HTTPRule(logRule(i, config.ResolvedHTTPRule{
			Path: fmt.Sprintf("(.*/){200}x%02d", i),
		})))
	}

	domains := make([]config.FQDNSelector, 0, 20)
	for i := range 20 {
		domains = append(domains, config.FQDNSelector{MatchName: fmt.Sprintf("api%02d.example.com", i)})
	}

	cfg := &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: domains,
			ToPorts: []config.PortRule{{
				Ports: []config.Port{{Port: "443"}, {Port: "8000", EndPort: 8099}},
				Rules: &config.L7Rules{HTTP: costly},
			}},
		}),
	}

	require.NoError(t, cfg.Validate(t.Context()))

	var shared [][]config.ResolvedHTTPRule

	for port := 8000; port <= 8099; port++ {
		for _, r := range cfg.ResolveRulesForPort(t.Context(), port) {
			shared = append(shared, r.HTTPRules)
		}
	}

	require.Len(t, shared, 2000)

	plain := []config.ResolvedHTTPRule{logRule(0, config.ResolvedHTTPRule{Path: "/a"})}

	tests := map[string]struct {
		lists [][]config.ResolvedHTTPRule
		limit int
		want  int
	}{
		"one rule list of many domains and ports": {
			lists: shared,
			limit: config.MaxRuleSetCacheWeight,
			want:  1,
		},
		"two rule lists": {
			lists: [][]config.ResolvedHTTPRule{shared[0], plain, shared[1], plain},
			limit: config.MaxRuleSetCacheWeight,
			want:  2,
		},
		"two rule lists whose fields join to the same text": {
			lists: [][]config.ResolvedHTTPRule{
				{{HeaderMatches: []config.HeaderMatch{{Name: "a", Value: "b=c"}}}, plain[0]},
				{{HeaderMatches: []config.HeaderMatch{{Name: "a=b", Value: "c"}}}, plain[0]},
			},
			limit: config.MaxRuleSetCacheWeight,
			want:  2,
		},
		// Each entry removes the other one, because the two do not fit
		// the weight limit together.
		"two rule lists past the weight limit": {
			lists: [][]config.ResolvedHTTPRule{shared[0], plain, shared[1], plain},
			limit: 1,
			want:  4,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, config.RuleSetMisses(tt.lists, tt.limit))
		})
	}
}

// TestMismatchRuleSetsKey checks that the memo of [MismatchRuleSets]
// keeps two rule lists apart when the fields of their rules differ but
// join to the same text.
func TestMismatchRuleSetsKey(t *testing.T) {
	t.Parallel()

	logZ := config.HeaderMatch{Name: "z", Value: "1", Mismatch: config.MismatchLOG}
	readsD := config.ResolvedHTTPRule{HeaderMatches: []config.HeaderMatch{
		{Name: "a", Value: "d"},
		{Name: "y", Value: "1", Mismatch: config.MismatchLOG},
	}}

	// The header "a" holds "b=c" in one rule and "d" in the other, so
	// no request matches both rules.
	apart := []config.ResolvedHTTPRule{
		{HeaderMatches: []config.HeaderMatch{{Name: "a", Value: "b=c"}, logZ}},
		readsD,
	}
	// The rules read the headers "a=b" and "a", so one request can
	// match both rules.
	shared := []config.ResolvedHTTPRule{
		{HeaderMatches: []config.HeaderMatch{{Name: "a=b", Value: "c"}, logZ}},
		readsD,
	}

	wantApart := [][]int{{0}, {1}}
	wantShared := [][]int{{0, 1}, {0}, {1}}

	tests := map[string]struct {
		lists [][]config.ResolvedHTTPRule
		want  [][][]int
	}{
		"rules apart first": {
			lists: [][]config.ResolvedHTTPRule{apart, shared},
			want:  [][][]int{wantApart, wantShared},
		},
		"shared rules first": {
			lists: [][]config.ResolvedHTTPRule{shared, apart},
			want:  [][][]int{wantShared, wantApart},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, config.MemoRuleSets(tt.lists))
		})
	}
}
