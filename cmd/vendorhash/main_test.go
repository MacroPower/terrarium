package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// repoHash is the output of `nix-hash --type sha256 --sri` for the
	// vendor tree of the module in testdata/repo. The flake of that
	// repository holds it.
	repoHash = "sha256-Saiub9Fa4ougHAdfKhM1jfyK3/P+bkoVL0fD2KXYVIc="

	// staleHash is a hash of another tree.
	staleHash = "sha256-pQpattmS9VmO3ZIQUFn66az8GSmB4IvYhTTCFn6SUmo="
)

// copyRepo copies the repository in testdata/repo to a new temporary
// directory and returns the path of the copy.
func copyRepo(t *testing.T) string {
	t.Helper()

	root := t.TempDir()
	require.NoError(t, os.CopyFS(root, os.DirFS(filepath.Join("testdata", "repo"))))

	return root
}

// editFlake replaces each occurrence of old in the flake of the
// repository at root with text. It returns the path and the text of the
// changed flake.
func editFlake(t *testing.T, root, old, text string) (string, string) {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(flakeSource))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), old)

	edited := strings.ReplaceAll(string(data), old, text)
	require.NoError(t, os.WriteFile(path, []byte(edited), 0o644))

	return path, edited
}

// flakeText returns the text of the flake at path, or the empty string
// when no file exists at path.
func flakeText(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}

	require.NoError(t, err)

	return string(data)
}

func TestRunRejectsArguments(t *testing.T) {
	t.Parallel()

	tests := map[string][]string{
		"no command":              nil,
		"unknown command":         {"verify"},
		"check with an argument":  {cmdCheck, flakeSource},
		"update with an argument": {cmdUpdate, flakeSource},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer

			err := run(t.Context(), args, copyRepo(t), &out)
			require.ErrorIs(t, err, ErrUsage)
			assert.Empty(t, out.String())
		})
	}
}

func TestRunCheck(t *testing.T) {
	t.Parallel()

	t.Run("hash of the vendor tree", func(t *testing.T) {
		t.Parallel()

		root := copyRepo(t)
		path, flake := editFlake(t, root, repoHash, repoHash)

		var out bytes.Buffer

		require.NoError(t, run(t.Context(), []string{cmdCheck}, root, &out))
		assert.Equal(t, path+": vendorHash "+repoHash+" matches the vendor tree\n", out.String())

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, flake, string(data))

		// The command creates the vendor tree outside the repository.
		assert.NoDirExists(t, filepath.Join(root, "vendor"))
	})

	t.Run("stale hash", func(t *testing.T) {
		t.Parallel()

		root := copyRepo(t)
		path, flake := editFlake(t, root, repoHash, staleHash)

		var out bytes.Buffer

		err := run(t.Context(), []string{cmdCheck}, root, &out)
		require.ErrorIs(t, err, ErrStale)
		require.ErrorContains(t, err, path+" holds "+staleHash+", and the vendor tree hashes to "+repoHash)
		require.ErrorContains(t, err, "go run ./cmd/vendorhash "+cmdUpdate)
		assert.Empty(t, out.String())

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, flake, string(data))
	})
}

func TestRunUpdate(t *testing.T) {
	t.Parallel()

	t.Run("stale hash", func(t *testing.T) {
		t.Parallel()

		root := copyRepo(t)
		path, flake := editFlake(t, root, repoHash, staleHash)
		require.NoError(t, os.Chmod(path, 0o600))

		var out bytes.Buffer

		require.NoError(t, run(t.Context(), []string{cmdUpdate}, root, &out))
		assert.Equal(t, path+": vendorHash changed from "+staleHash+" to "+repoHash+"\n", out.String())

		// The command changes only the hash.
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, strings.ReplaceAll(flake, staleHash, repoHash), string(data))

		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, fs.FileMode(0o600), info.Mode().Perm())

		out.Reset()

		require.NoError(t, run(t.Context(), []string{cmdCheck}, root, &out))
		assert.Contains(t, out.String(), "matches the vendor tree")
	})

	t.Run("hash of the vendor tree", func(t *testing.T) {
		t.Parallel()

		root := copyRepo(t)
		path, flake := editFlake(t, root, repoHash, repoHash)

		// The command must not write a flake that holds the hash, and
		// it cannot write this one.
		require.NoError(t, os.Chmod(path, 0o400))

		var out bytes.Buffer

		require.NoError(t, run(t.Context(), []string{cmdUpdate}, root, &out))
		assert.Equal(t, path+": vendorHash "+repoHash+" matches the vendor tree\n", out.String())

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, flake, string(data))
	})
}

// TestRunRejectsRepository checks that both commands fail for a
// repository whose flake or module they cannot use, and that the update
// command leaves the flake unchanged.
func TestRunRejectsRepository(t *testing.T) {
	t.Parallel()

	const attr = `vendorHash = "` + repoHash + `";`

	tests := map[string]struct {
		// setup changes the repository at root.
		setup func(t *testing.T, root string)
		err   error
		msg   string
	}{
		"flake is missing": {
			setup: func(t *testing.T, root string) {
				t.Helper()

				require.NoError(t, os.Remove(filepath.Join(root, filepath.FromSlash(flakeSource))))
			},
			err: ErrFlakeSource,
			msg: "no such file or directory",
		},
		"flake without a vendorHash": {
			setup: func(t *testing.T, root string) {
				t.Helper()

				editFlake(t, root, attr, "")
			},
			err: ErrFlakeSource,
			msg: "assigns a string to vendorHash 0 times, want 1",
		},
		"flake with a null vendorHash": {
			setup: func(t *testing.T, root string) {
				t.Helper()

				editFlake(t, root, attr, "vendorHash = null;")
			},
			err: ErrFlakeSource,
			msg: "assigns a string to vendorHash 0 times, want 1",
		},
		"flake with two vendorHash strings": {
			setup: func(t *testing.T, root string) {
				t.Helper()

				editFlake(t, root, attr, attr+"\n"+attr)
			},
			err: ErrFlakeSource,
			msg: "assigns a string to vendorHash 2 times, want 1",
		},
		"module is missing": {
			setup: func(t *testing.T, root string) {
				t.Helper()

				require.NoError(t, os.Remove(filepath.Join(root, "go.mod")))
			},
			err: ErrVendor,
			msg: "go mod vendor: exit status 1: go: ",
		},
		"module without dependencies": {
			setup: func(t *testing.T, root string) {
				t.Helper()

				require.NoError(t, os.Remove(filepath.Join(root, "repo.go")))
				require.NoError(t, os.WriteFile(
					filepath.Join(root, "go.mod"), []byte("module example.test/repo\n\ngo 1.21\n"), 0o644,
				))
			},
			err: ErrVendor,
			msg: "has no dependencies",
		},
	}

	for name, tc := range tests {
		for _, cmd := range []string{cmdCheck, cmdUpdate} {
			t.Run(name+"/"+cmd, func(t *testing.T) {
				t.Parallel()

				root := copyRepo(t)
				tc.setup(t, root)

				path := filepath.Join(root, filepath.FromSlash(flakeSource))

				before := flakeText(t, path)

				var out bytes.Buffer

				err := run(t.Context(), []string{cmd}, root, &out)
				require.ErrorIs(t, err, tc.err)
				require.ErrorContains(t, err, tc.msg)
				assert.Empty(t, out.String())

				assert.Equal(t, before, flakeText(t, path))
			})
		}
	}
}
