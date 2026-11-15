package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/module"
)

// The go.mod and go.sum of the ci module after Renovate changed the
// gqlparser requirement from v2.5.34 to v2.5.35 and left go.sum
// unchanged, reduced to two requirements.
const (
	renovatedMod = `module dagger/ci

go 1.26.1

require (
	github.com/Khan/genqlient v0.8.1
	github.com/vektah/gqlparser/v2 v2.5.35
)
`

	renovatedSum = `github.com/Khan/genqlient v0.8.1 h1:wtOCc8N9rNynRLXN3k3CnfzheCUNKBcvXmVv5zt6WCs=
github.com/Khan/genqlient v0.8.1/go.mod h1:R2G6DzjBvCbhjsEajfRjbWdVglSH/73kSivC9TLWVjU=
github.com/vektah/gqlparser/v2 v2.5.34 h1:MEea5P0qhdcqfBL45ghKE+qr9laidVHTMHjav5h7ckk=
github.com/vektah/gqlparser/v2 v2.5.34/go.mod h1:mFdHLGCio7OGX1fby9ZjTW6FN+qxgmbnBcRIeeScE5s=
`

	// tidiedSum is the go.sum that `go mod tidy` writes for renovatedMod.
	tidiedSum = `github.com/Khan/genqlient v0.8.1 h1:wtOCc8N9rNynRLXN3k3CnfzheCUNKBcvXmVv5zt6WCs=
github.com/Khan/genqlient v0.8.1/go.mod h1:R2G6DzjBvCbhjsEajfRjbWdVglSH/73kSivC9TLWVjU=
github.com/vektah/gqlparser/v2 v2.5.35 h1:LEr/wXnTKkOqNn+4tNClYclksXN2781VoBFzzFW51Dk=
github.com/vektah/gqlparser/v2 v2.5.35/go.mod h1:cAJ9qwVgPaUkWv6Gn8vn0mqOE0Ui5Pn56wNy5396XWo=
`
)

// mustRequirements returns the requirements of the go.mod text in mod.
func mustRequirements(t *testing.T, mod string) []requirement {
	t.Helper()

	reqs, err := requirements("go.mod", []byte(mod))
	require.NoError(t, err)

	return reqs
}

// mustParseSums returns the lines of the go.sum text in sum.
func mustParseSums(t *testing.T, sum string) []sumLine {
	t.Helper()

	lines, err := parseSums("go.sum", []byte(sum))
	require.NoError(t, err)

	return lines
}

func TestRequirements(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mod  string
		want []requirement
	}{
		"no requirement": {
			mod:  "module example.com/m\n\ngo 1.26.0\n",
			want: []requirement{},
		},
		"direct and indirect requirements": {
			mod: `module example.com/m

require example.com/a v1.0.0

require (
	example.com/b v1.2.0 // indirect
	example.com/c/v2 v2.0.1 // indirect
)
`,
			want: []requirement{
				{path: "example.com/a", sum: module.Version{Path: "example.com/a", Version: "v1.0.0"}},
				{path: "example.com/b", sum: module.Version{Path: "example.com/b", Version: "v1.2.0"}},
				{path: "example.com/c/v2", sum: module.Version{Path: "example.com/c/v2", Version: "v2.0.1"}},
			},
		},
		"replacement of every version": {
			mod: `module example.com/m

require example.com/a v1.0.0

replace example.com/a => example.com/a v1.5.0
`,
			want: []requirement{
				{path: "example.com/a", sum: module.Version{Path: "example.com/a", Version: "v1.5.0"}},
			},
		},
		"replacement by another module": {
			mod: `module example.com/m

require example.com/a v1.0.0

replace example.com/a => example.com/fork v0.3.0
`,
			want: []requirement{
				{path: "example.com/a", sum: module.Version{Path: "example.com/fork", Version: "v0.3.0"}},
			},
		},
		"replacement of the required version wins": {
			mod: `module example.com/m

require example.com/a v1.0.0

replace (
	example.com/a => example.com/a v1.5.0
	example.com/a v1.0.0 => example.com/a v1.0.1
)
`,
			want: []requirement{
				{path: "example.com/a", sum: module.Version{Path: "example.com/a", Version: "v1.0.1"}},
			},
		},
		"replacement of another version": {
			mod: `module example.com/m

require example.com/a v1.0.0

replace example.com/a v0.9.0 => example.com/a v0.9.1
`,
			want: []requirement{
				{path: "example.com/a", sum: module.Version{Path: "example.com/a", Version: "v1.0.0"}},
			},
		},
		"replacement by a directory": {
			mod: `module example.com/m

require (
	example.com/a v1.0.0
	example.com/b v1.0.0
)

replace example.com/a => ../a
`,
			want: []requirement{
				{path: "example.com/b", sum: module.Version{Path: "example.com/b", Version: "v1.0.0"}},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := requirements("go.mod", []byte(tc.mod))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRequirementsRejectsFile(t *testing.T) {
	t.Parallel()

	_, err := requirements("ci/go.mod", []byte("module example.com/m\n\nrequire example.com/a\n"))
	require.ErrorIs(t, err, ErrModFile)
	require.ErrorContains(t, err, "ci/go.mod:3")
}

func TestParseSums(t *testing.T) {
	t.Parallel()

	t.Run("lines", func(t *testing.T) {
		t.Parallel()

		got, err := parseSums(
			"go.sum",
			[]byte("example.com/a v1.0.0 h1:AAAA=\r\n\nexample.com/a v1.0.0/go.mod h1:BBBB=\n"),
		)
		require.NoError(t, err)

		want := []sumLine{
			{
				mod:  module.Version{Path: "example.com/a", Version: "v1.0.0"},
				text: "example.com/a v1.0.0 h1:AAAA=",
			},
			{
				mod:   module.Version{Path: "example.com/a", Version: "v1.0.0"},
				goMod: true,
				text:  "example.com/a v1.0.0/go.mod h1:BBBB=",
			},
		}

		assert.Equal(t, want, got)
	})

	t.Run("empty file", func(t *testing.T) {
		t.Parallel()

		got, err := parseSums("go.sum", nil)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t, renovatedSum, string(formatSums(mustParseSums(t, renovatedSum))))
	})

	t.Run("malformed line", func(t *testing.T) {
		t.Parallel()

		_, err := parseSums("ci/go.sum", []byte("example.com/a v1.0.0 h1:AAAA=\nexample.com/a v1.0.0/go.mod\n"))
		require.ErrorIs(t, err, ErrSumFile)
		require.ErrorContains(t, err, "ci/go.sum:2: a line has 2 fields, want 3")
	})
}

func TestProblems(t *testing.T) {
	t.Parallel()

	const mod = `module example.com/m

require (
	example.com/a v1.1.0
	example.com/b v1.0.0 // indirect
)
`

	tests := map[string]struct {
		mod  string
		sum  string
		want []string
	}{
		"go.sum of go mod tidy": {
			mod: renovatedMod,
			sum: tidiedSum,
		},
		"go.sum of the version before a Renovate update": {
			mod: renovatedMod,
			sum: renovatedSum,
			want: []string{
				"no hash of github.com/vektah/gqlparser/v2 v2.5.35",
				"no go.mod hash of github.com/vektah/gqlparser/v2 v2.5.35",
				"a hash of github.com/vektah/gqlparser/v2 v2.5.34, and go.mod does not select that version",
			},
		},
		"no go.sum": {
			mod: mod,
			want: []string{
				"no hash of example.com/a v1.1.0",
				"no go.mod hash of example.com/a v1.1.0",
				"no hash of example.com/b v1.0.0",
				"no go.mod hash of example.com/b v1.0.0",
			},
		},
		"no requirement and no go.sum": {
			mod: "module example.com/m\n",
		},
		"hash of the files is missing": {
			mod: mod,
			sum: `example.com/a v1.1.0/go.mod h1:BBBB=
example.com/b v1.0.0 h1:CCCC=
example.com/b v1.0.0/go.mod h1:DDDD=
`,
			want: []string{"no hash of example.com/a v1.1.0"},
		},
		"hash of the go.mod file is missing": {
			mod: mod,
			sum: `example.com/a v1.1.0 h1:AAAA=
example.com/a v1.1.0/go.mod h1:BBBB=
example.com/b v1.0.0 h1:CCCC=
`,
			want: []string{"no go.mod hash of example.com/b v1.0.0"},
		},
		"hash of the files of another version": {
			mod: mod,
			sum: `example.com/a v1.0.0 h1:EEEE=
example.com/a v1.1.0 h1:AAAA=
example.com/a v1.1.0/go.mod h1:BBBB=
example.com/b v1.0.0 h1:CCCC=
example.com/b v1.0.0/go.mod h1:DDDD=
`,
			want: []string{"a hash of example.com/a v1.0.0, and go.mod does not select that version"},
		},
		// The go command keeps the go.mod hash of a version that a
		// dependency requires.
		"go.mod hash of another version": {
			mod: mod,
			sum: `example.com/a v1.0.0/go.mod h1:FFFF=
example.com/a v1.1.0 h1:AAAA=
example.com/a v1.1.0/go.mod h1:BBBB=
example.com/b v1.0.0 h1:CCCC=
example.com/b v1.0.0/go.mod h1:DDDD=
`,
		},
		// `go mod tidy` keeps the hashes of a module that provides a
		// package to the tests of a dependency.
		"hashes of a module that go.mod does not require": {
			mod: mod,
			sum: `example.com/a v1.1.0 h1:AAAA=
example.com/a v1.1.0/go.mod h1:BBBB=
example.com/b v1.0.0 h1:CCCC=
example.com/b v1.0.0/go.mod h1:DDDD=
example.com/test v0.1.0 h1:GGGG=
example.com/test v0.1.0/go.mod h1:HHHH=
`,
		},
		"hashes of the replacement": {
			mod: mod + "\nreplace example.com/a => example.com/a v1.5.0\n",
			sum: `example.com/a v1.5.0 h1:AAAA=
example.com/a v1.5.0/go.mod h1:BBBB=
example.com/b v1.0.0 h1:CCCC=
example.com/b v1.0.0/go.mod h1:DDDD=
`,
		},
		"hashes of the replaced version": {
			mod: mod + "\nreplace example.com/a => example.com/a v1.5.0\n",
			sum: `example.com/a v1.1.0 h1:AAAA=
example.com/a v1.1.0/go.mod h1:BBBB=
example.com/b v1.0.0 h1:CCCC=
example.com/b v1.0.0/go.mod h1:DDDD=
`,
			want: []string{
				"no hash of example.com/a v1.5.0",
				"no go.mod hash of example.com/a v1.5.0",
				"a hash of example.com/a v1.1.0, and go.mod does not select that version",
			},
		},
		// One module replaces another module and is also a requirement
		// at another version, so go.sum holds both versions.
		"replacement is also a requirement": {
			mod: mod + "\nreplace example.com/a => example.com/b v0.9.0\n",
			sum: `example.com/b v0.9.0 h1:AAAA=
example.com/b v0.9.0/go.mod h1:BBBB=
example.com/b v1.0.0 h1:CCCC=
example.com/b v1.0.0/go.mod h1:DDDD=
`,
		},
		"hashes of a module that another module replaces": {
			mod: mod + "\nreplace example.com/a => example.com/fork v0.3.0\n",
			sum: `example.com/a v1.1.0 h1:AAAA=
example.com/a v1.1.0/go.mod h1:BBBB=
example.com/b v1.0.0 h1:CCCC=
example.com/b v1.0.0/go.mod h1:DDDD=
example.com/fork v0.3.0 h1:EEEE=
example.com/fork v0.3.0/go.mod h1:FFFF=
`,
			want: []string{"a hash of example.com/a v1.1.0, and go.mod does not select that version"},
		},
		"replacement by a directory": {
			mod: mod + "\nreplace example.com/a => ../a\n",
			sum: `example.com/b v1.0.0 h1:CCCC=
example.com/b v1.0.0/go.mod h1:DDDD=
`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := problems(mustRequirements(t, tc.mod), mustParseSums(t, tc.sum))
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTrim(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mod  string
		sum  string
		want string
	}{
		"go.sum of go mod tidy": {
			mod:  renovatedMod,
			sum:  tidiedSum,
			want: tidiedSum,
		},
		"go.sum of the version before a Renovate update": {
			mod: renovatedMod,
			sum: renovatedSum,
			want: `github.com/Khan/genqlient v0.8.1 h1:wtOCc8N9rNynRLXN3k3CnfzheCUNKBcvXmVv5zt6WCs=
github.com/Khan/genqlient v0.8.1/go.mod h1:R2G6DzjBvCbhjsEajfRjbWdVglSH/73kSivC9TLWVjU=
`,
		},
		"module that go.mod does not require": {
			mod: "module example.com/m\n\nrequire example.com/a v1.1.0\n",
			sum: `example.com/a v1.0.0/go.mod h1:FFFF=
example.com/a v1.1.0 h1:AAAA=
example.com/test v0.1.0 h1:GGGG=
example.com/test v0.1.0/go.mod h1:HHHH=
`,
			want: `example.com/a v1.1.0 h1:AAAA=
example.com/test v0.1.0 h1:GGGG=
example.com/test v0.1.0/go.mod h1:HHHH=
`,
		},
		// The build uses no version of a module that another module
		// replaces.
		"replacement by another module": {
			mod: "module example.com/m\n\nrequire example.com/a v1.1.0\n\nreplace example.com/a => example.com/fork v0.3.0\n",
			sum: `example.com/a v1.1.0 h1:AAAA=
example.com/a v1.1.0/go.mod h1:BBBB=
example.com/fork v0.2.0 h1:IIII=
example.com/fork v0.3.0 h1:JJJJ=
`,
			want: `example.com/fork v0.3.0 h1:JJJJ=
`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := trim(mustRequirements(t, tc.mod), mustParseSums(t, tc.sum))
			assert.Equal(t, tc.want, string(formatSums(got)))
		})
	}
}
