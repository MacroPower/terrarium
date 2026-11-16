package envoy_test

import (
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoy"
)

// chainAction is the action of a filter chain matcher, which names a
// filter chain.
type chainAction struct {
	TypedConfig struct {
		AtType string `yaml:"@type"`
		Value  string `yaml:"value"`
	} `yaml:"typed_config"`
}

// chainOnMatch is the result of one entry of a filter chain matcher.
type chainOnMatch struct {
	Action  *chainAction `yaml:"action"`
	Matcher *struct {
		MatcherList struct {
			Matchers []struct {
				Predicate struct {
					SinglePredicate struct {
						Input struct {
							TypedConfig struct {
								AtType string `yaml:"@type"`
							} `yaml:"typed_config"`
						} `yaml:"input"`
						ValueMatch struct {
							SafeRegex *struct {
								GoogleRE2 *struct{} `yaml:"google_re2"`
								Regex     string    `yaml:"regex"`
							} `yaml:"safe_regex"`
							Exact string `yaml:"exact"`
						} `yaml:"value_match"`
					} `yaml:"single_predicate"`
				} `yaml:"predicate"`
				OnMatch struct {
					Action *chainAction `yaml:"action"`
				} `yaml:"on_match"`
			} `yaml:"matchers"`
		} `yaml:"matcher_list"`
		OnNoMatch *struct {
			Action *chainAction `yaml:"action"`
		} `yaml:"on_no_match"`
	} `yaml:"matcher"`
}

// tlsListenerDoc holds the fields of the YAML of a TLS listener that
// select the filter chain of a connection.
type tlsListenerDoc struct {
	FilterChainMatcher *struct {
		MatcherTree struct {
			Input struct {
				TypedConfig struct {
					AtType string `yaml:"@type"`
				} `yaml:"typed_config"`
			} `yaml:"input"`
			ExactMatchMap struct {
				Map map[string]chainOnMatch `yaml:"map"`
			} `yaml:"exact_match_map"`
		} `yaml:"matcher_tree"`
		OnNoMatch *chainOnMatch `yaml:"on_no_match"`
	} `yaml:"filter_chain_matcher"`
	DefaultFilterChain *struct {
		Name string `yaml:"name"`
	} `yaml:"default_filter_chain"`
	FilterChains []struct {
		FilterChainMatch map[string]any `yaml:"filter_chain_match"`
		Name             string         `yaml:"name"`
		Filters          []struct {
			Name string `yaml:"name"`
		} `yaml:"filters"`
	} `yaml:"filter_chains"`
}

// tlsChainSelection describes how a TLS listener selects the filter
// chain of a TLS connection.
type tlsChainSelection struct {
	// Routes lists the server name entries of the matcher in the order
	// in which Envoy checks them. An entry is "exact <name> > <chain>"
	// or "regex <regex> > <chain>".
	Routes []string
	// Fallback is the name of the chain of a TLS connection that no
	// entry of Routes matches. It is empty when such a connection uses
	// the default filter chain.
	Fallback string
	// Chains lists the names of the filter chains of the listener.
	Chains []string
}

// readTLSChainSelection returns the chain selection of listener. It
// also checks the parts of the listener that Envoy requires of a
// listener with a filter chain matcher.
func readTLSChainSelection(t *testing.T, listener envoy.Listener) tlsChainSelection {
	t.Helper()

	const (
		transportInput  = "type.googleapis.com/envoy.extensions.matching.common_inputs.network.v3.TransportProtocolInput"
		serverNameInput = "type.googleapis.com/envoy.extensions.matching.common_inputs.network.v3.ServerNameInput"
		stringValue     = "type.googleapis.com/google.protobuf.StringValue"
	)

	var doc tlsListenerDoc

	require.NoError(t, yaml.Unmarshal([]byte(marshalYAML(t, listener)), &doc))

	// The default filter chain handles each connection that the
	// matcher gives no chain.
	require.NotNil(t, doc.DefaultFilterChain)

	var sel tlsChainSelection

	chains := make(map[string]bool)

	for _, c := range doc.FilterChains {
		// Envoy selects a chain of a listener with a matcher only by
		// its name, so each chain has its own name and no match.
		require.NotEmpty(t, c.Name)
		require.False(t, chains[c.Name], "duplicate chain name %q", c.Name)
		assert.Nil(t, c.FilterChainMatch, "chain %q", c.Name)

		// A network filter denies a server name only after the other
		// filters of its chain started to resolve the name. No chain
		// has such a filter.
		for _, f := range c.Filters {
			assert.NotEqual(t, "envoy.filters.network.rbac", f.Name, "chain %q", c.Name)
		}

		chains[c.Name] = true
		sel.Chains = append(sel.Chains, c.Name)
	}

	if doc.FilterChainMatcher == nil {
		require.Empty(t, sel.Chains, "chains without a matcher receive no connection")

		return sel
	}

	action := func(a *chainAction) string {
		require.NotNil(t, a)
		assert.Equal(t, stringValue, a.TypedConfig.AtType)
		assert.True(t, chains[a.TypedConfig.Value], "action names no chain: %q", a.TypedConfig.Value)

		return a.TypedConfig.Value
	}

	// A connection that is not TLS gets no chain.
	tree := doc.FilterChainMatcher.MatcherTree
	assert.Equal(t, transportInput, tree.Input.TypedConfig.AtType)
	assert.Nil(t, doc.FilterChainMatcher.OnNoMatch)
	require.Len(t, tree.ExactMatchMap.Map, 1)
	require.Contains(t, tree.ExactMatchMap.Map, "tls")

	onTLS := tree.ExactMatchMap.Map["tls"]
	if onTLS.Matcher == nil {
		sel.Fallback = action(onTLS.Action)

		return sel
	}

	require.Nil(t, onTLS.Action)
	require.NotEmpty(t, onTLS.Matcher.MatcherList.Matchers)

	for _, m := range onTLS.Matcher.MatcherList.Matchers {
		p := m.Predicate.SinglePredicate
		assert.Equal(t, serverNameInput, p.Input.TypedConfig.AtType)

		chain := action(m.OnMatch.Action)

		if p.ValueMatch.SafeRegex != nil {
			assert.Empty(t, p.ValueMatch.Exact)
			assert.NotNil(t, p.ValueMatch.SafeRegex.GoogleRE2, "Envoy requires the regex engine")

			sel.Routes = append(sel.Routes, "regex "+p.ValueMatch.SafeRegex.Regex+" > "+chain)

			continue
		}

		require.NotEmpty(t, p.ValueMatch.Exact)

		sel.Routes = append(sel.Routes, "exact "+p.ValueMatch.Exact+" > "+chain)
	}

	if onTLS.Matcher.OnNoMatch != nil {
		sel.Fallback = action(onTLS.Matcher.OnNoMatch.Action)
	}

	return sel
}

// TestTLSListeners_FilterChainMatcher checks that a TLS listener
// selects the filter chain of each connection with a filter chain
// matcher that applies the exact meaning of each domain to the SNI.
// A connection with an SNI that the policy does not allow then gets
// the default filter chain. That chain resolves no name and connects
// to no upstream. A chain that checks the SNI in a network filter
// resolves the name and connects to the upstream before the filter
// denies the connection.
func TestTLSListeners_FilterChainMatcher(t *testing.T) {
	t.Parallel()

	restricted := []config.ResolvedHTTPRule{{Method: "GET"}}

	const (
		oneLabel  = `^[-a-zA-Z0-9_]+\.example\.com$`
		anyLabels = `^[-a-zA-Z0-9_]+(\.[-a-zA-Z0-9_]+)*\.example\.com$`
	)

	tests := map[string]struct {
		rules    []config.ResolvedRule
		certsDir string
		open     bool
		want     tlsChainSelection
	}{
		"no rules": {
			want: tlsChainSelection{},
		},
		"open without rules": {
			open: true,
			want: tlsChainSelection{
				Fallback: "passthrough_open",
				Chains:   []string{"passthrough_open"},
			},
		},
		"exact names": {
			rules: []config.ResolvedRule{{Domain: "a.example.com"}, {Domain: "b.example.com"}},
			want: tlsChainSelection{
				Routes: []string{
					"exact a.example.com > passthrough",
					"exact b.example.com > passthrough",
				},
				Chains: []string{"passthrough"},
			},
		},
		"single-label wildcard": {
			rules: []config.ResolvedRule{{Domain: "*.example.com"}},
			want: tlsChainSelection{
				Routes: []string{"regex " + oneLabel + " > passthrough"},
				Chains: []string{"passthrough"},
			},
		},
		"multi-label wildcard": {
			rules: []config.ResolvedRule{{Domain: "**.example.com"}},
			want: tlsChainSelection{
				Routes: []string{"regex " + anyLabels + " > passthrough"},
				Chains: []string{"passthrough"},
			},
		},
		"wildcard inside a label": {
			rules: []config.ResolvedRule{{Domain: "*.ci*.io"}},
			want: tlsChainSelection{
				Routes: []string{`regex ^[-a-zA-Z0-9_]+\.ci[-a-zA-Z0-9_]*\.io$ > passthrough`},
				Chains: []string{"passthrough"},
			},
		},
		"exact name before wildcard": {
			rules: []config.ResolvedRule{{Domain: "*.example.com"}, {Domain: "api.example.com"}},
			want: tlsChainSelection{
				Routes: []string{
					"exact api.example.com > passthrough",
					"regex " + oneLabel + " > passthrough",
				},
				Chains: []string{"passthrough"},
			},
		},
		"longer wildcard suffix first": {
			rules: []config.ResolvedRule{
				{Domain: "**.com"},
				{Domain: "*.example.com", HTTPRules: restricted},
				{Domain: "*.api.example.com"},
			},
			certsDir: "/certs",
			want: tlsChainSelection{
				Routes: []string{
					`regex ^[-a-zA-Z0-9_]+\.api\.example\.com$ > passthrough`,
					"regex " + oneLabel + " > mitm_*.example.com",
					`regex ^[-a-zA-Z0-9_]+(\.[-a-zA-Z0-9_]+)*\.com$ > passthrough`,
				},
				Chains: []string{"passthrough", "mitm_*.example.com"},
			},
		},
		"single-label and multi-label wildcards of one suffix": {
			rules: []config.ResolvedRule{{Domain: "*.example.com"}, {Domain: "**.example.com"}},
			want: tlsChainSelection{
				Routes: []string{
					"regex " + oneLabel + " > passthrough",
					"regex " + anyLabels + " > passthrough",
				},
				Chains: []string{"passthrough"},
			},
		},
		"passthrough before MITM for one suffix": {
			rules: []config.ResolvedRule{
				{Domain: "*.example.com", HTTPRules: restricted},
				{Domain: "**.example.com"},
			},
			certsDir: "/certs",
			want: tlsChainSelection{
				Routes: []string{
					"regex " + anyLabels + " > passthrough",
					"regex " + oneLabel + " > mitm_*.example.com",
				},
				Chains: []string{"passthrough", "mitm_*.example.com"},
			},
		},
		"MITM chains": {
			rules: []config.ResolvedRule{
				{Domain: "**.example.com", HTTPRules: restricted},
				{Domain: "api.example.org", HTTPRules: restricted},
				{Domain: "plain.example.org"},
			},
			certsDir: "/certs",
			want: tlsChainSelection{
				Routes: []string{
					"exact plain.example.org > passthrough",
					"exact api.example.org > mitm_api.example.org",
					"regex " + anyLabels + " > mitm_*.example.com",
				},
				Chains: []string{"passthrough", "mitm_*.example.com", "mitm_api.example.org"},
			},
		},
		"restricted rule without certificates": {
			rules: []config.ResolvedRule{{Domain: "*.example.com", HTTPRules: restricted}},
			want: tlsChainSelection{
				Routes: []string{"regex " + oneLabel + " > passthrough"},
				Chains: []string{"passthrough"},
			},
		},
		"one route for a repeated domain": {
			rules: []config.ResolvedRule{{Domain: "*.example.com"}, {Domain: "*.example.com"}},
			want: tlsChainSelection{
				Routes: []string{"regex " + oneLabel + " > passthrough"},
				Chains: []string{"passthrough"},
			},
		},
		"deeper name on an open port uses the open chain": {
			rules: []config.ResolvedRule{{Domain: "*.example.com"}},
			open:  true,
			want: tlsChainSelection{
				Routes:   []string{"regex " + oneLabel + " > passthrough"},
				Fallback: "passthrough_open",
				Chains:   []string{"passthrough", "passthrough_open"},
			},
		},
		"bare wildcard opens the port": {
			rules: []config.ResolvedRule{{Domain: "*"}, {Domain: "example.com"}},
			want: tlsChainSelection{
				Routes:   []string{"exact example.com > passthrough"},
				Fallback: "passthrough_open",
				Chains:   []string{"passthrough", "passthrough_open"},
			},
		},
		"bare wildcard alone": {
			rules: []config.ResolvedRule{{Domain: "*"}},
			want: tlsChainSelection{
				Fallback: "passthrough_open",
				Chains:   []string{"passthrough_open"},
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			listeners := map[string]envoy.Listener{
				"container": envoy.BuildTLSListener(
					"tls_passthrough", 15443, 443, "tls_passthrough",
					tt.rules, tt.open, nil, nil, tt.certsDir, false,
				),
				"proxy internal": envoy.BuildInternalTLSListener(
					443, tt.rules, tt.open, nil, nil, tt.certsDir, nil,
				),
			}

			for kind, l := range listeners {
				assert.Equal(t, tt.want, readTLSChainSelection(t, l), kind)
			}
		})
	}
}
