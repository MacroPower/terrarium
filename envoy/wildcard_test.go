package envoy_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.jacobcolvin.com/terrarium/envoy"
)

func TestWildcardToSNIRegex(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		pattern string
		matches []string
		rejects []string
	}{
		"single-star prefix": {
			pattern: "*.example.com",
			matches: []string{"sub.example.com"},
			rejects: []string{"a.b.example.com", "example.com"},
		},
		"double-star prefix": {
			pattern: "**.example.com",
			matches: []string{"sub.example.com", "a.b.example.com", "a.b.c.example.com"},
			rejects: []string{"example.com"},
		},
		"mid-label wildcard": {
			pattern: "api.*.example.com",
			matches: []string{"api.foo.example.com", "api.bar.example.com"},
			rejects: []string{"api.foo.bar.example.com", "notapi.foo.example.com", "api.example.com"},
		},
		"intra-label wildcard": {
			pattern: "*.ci*.io",
			matches: []string{"sub.cilium.io", "sub.ci.io", "sub.circus.io"},
			rejects: []string{"cilium.io", "ci.io"},
		},
		"multiple wildcards": {
			pattern: "*.*.cilium.io",
			matches: []string{"a.b.cilium.io"},
			rejects: []string{"a.cilium.io", "cilium.io", "a.b.c.cilium.io"},
		},
		"double-star with wildcard suffix": {
			pattern: "**.ci*.io",
			matches: []string{"a.cilium.io", "a.b.cilium.io", "x.ci.io"},
			rejects: []string{"cilium.io", "ci.io"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			re := regexp.MustCompile(envoy.WildcardToSNIRegex(tt.pattern))
			for _, m := range tt.matches {
				assert.True(t, re.MatchString(m), "expected %q to match %q", tt.pattern, m)
			}

			for _, r := range tt.rejects {
				assert.False(t, re.MatchString(r), "expected %q to reject %q", tt.pattern, r)
			}
		})
	}
}

func TestWildcardToHostRegex(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		pattern string
		matches []string
		rejects []string
	}{
		"single-star with port": {
			pattern: "*.example.com",
			matches: []string{"sub.example.com", "sub.example.com:80", "sub.example.com:443"},
			rejects: []string{"a.b.example.com", "a.b.example.com:80", "example.com"},
		},
		"double-star with port": {
			pattern: "**.example.com",
			matches: []string{"sub.example.com", "a.b.example.com:8080"},
			rejects: []string{"example.com", "example.com:80"},
		},
		"mid-label wildcard with port": {
			pattern: "api.*.example.com",
			matches: []string{"api.foo.example.com", "api.foo.example.com:443"},
			rejects: []string{"api.foo.bar.example.com", "notapi.foo.example.com"},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			re := regexp.MustCompile(envoy.WildcardToHostRegex(tt.pattern))
			for _, m := range tt.matches {
				assert.True(t, re.MatchString(m), "expected %q to match %q", tt.pattern, m)
			}

			for _, r := range tt.rejects {
				assert.False(t, re.MatchString(r), "expected %q to reject %q", tt.pattern, r)
			}
		})
	}
}

func TestWildcardServerName(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		domain string
		want   string
	}{
		"exact domain": {
			domain: "example.com",
			want:   "example.com",
		},
		"single-star prefix": {
			domain: "*.example.com",
			want:   "*.example.com",
		},
		"double-star prefix": {
			domain: "**.example.com",
			want:   "*.example.com",
		},
		"mid-position wildcard": {
			domain: "api.*.example.com",
			want:   "*.example.com",
		},
		"intra-label wildcard": {
			domain: "*.ci*.io",
			want:   "*.io",
		},
		"multiple wildcards": {
			domain: "*.*.cilium.io",
			want:   "*.cilium.io",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, envoy.WildcardServerName(tt.domain))
		})
	}
}

func TestIsWildcardDomain(t *testing.T) {
	t.Parallel()

	assert.True(t, envoy.IsWildcardDomain("*.example.com"))
	assert.True(t, envoy.IsWildcardDomain("**.example.com"))
	assert.True(t, envoy.IsWildcardDomain("api.*.example.com"))
	assert.True(t, envoy.IsWildcardDomain("*.ci*.io"))
	assert.False(t, envoy.IsWildcardDomain("example.com"))
	assert.False(t, envoy.IsWildcardDomain("sub.example.com"))
}
