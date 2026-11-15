package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.jacobcolvin.com/terrarium/envoybin"
)

func TestRunRejectsArguments(t *testing.T) {
	t.Parallel()

	// No platform has this name, so the host is always a different
	// platform.
	const otherPlatform = "testos-testarch"

	tests := map[string]struct {
		err  error
		msg  string
		args []string
	}{
		"no command": {
			err: ErrUsage,
		},
		"unknown command": {
			args: []string{"install"},
			err:  ErrUsage,
		},
		"update with two files": {
			args: []string{cmdUpdate, "a.go", "b.go"},
			err:  ErrUsage,
		},
		"verify with two platforms": {
			args: []string{cmdVerify, otherPlatform, otherPlatform},
			err:  ErrUsage,
		},
		"verify for a platform that is not the host": {
			args: []string{cmdVerify, otherPlatform},
			err:  ErrHost,
			msg:  "want " + otherPlatform + ", host is " + envoybin.HostPlatform().String(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer

			err := run(t.Context(), tc.args, &out)
			require.ErrorIs(t, err, tc.err)
			require.ErrorContains(t, err, tc.msg)
			assert.Empty(t, out.String())
		})
	}
}

// TestRunUpdateSource checks which source file the update command reads.
// Neither file exists, so the command stops before the first download.
func TestRunUpdateSource(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing.go")

	tests := map[string]struct {
		// want is the path of the source file in the error.
		want string
		args []string
	}{
		"file argument": {
			args: []string{cmdUpdate, missing},
			want: missing,
		},
		// The test runs in the directory of this package, which has no
		// file at the default path.
		"default path": {
			args: []string{cmdUpdate},
			want: manifestSource,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer

			err := run(t.Context(), tc.args, &out)
			require.ErrorIs(t, err, ErrManifestSource)
			require.ErrorIs(t, err, os.ErrNotExist)
			require.ErrorContains(t, err, tc.want)
			assert.Empty(t, out.String())
		})
	}
}

func TestGithubToken(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		env  map[string]string
		want string
	}{
		"no variable": {},
		"GH_TOKEN": {
			env:  map[string]string{"GH_TOKEN": "gh"},
			want: "gh",
		},
		"GITHUB_TOKEN": {
			env:  map[string]string{"GITHUB_TOKEN": "github"},
			want: "github",
		},
		"GH_TOKEN takes precedence": {
			env:  map[string]string{"GH_TOKEN": "gh", "GITHUB_TOKEN": "github"},
			want: "gh",
		},
		"empty GH_TOKEN": {
			env:  map[string]string{"GH_TOKEN": "", "GITHUB_TOKEN": "github"},
			want: "github",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := githubToken(func(key string) string { return tc.env[key] })
			assert.Equal(t, tc.want, got)
		})
	}
}
