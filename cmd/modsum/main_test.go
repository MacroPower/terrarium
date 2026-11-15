package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeRepo creates a repository in a new temporary directory whose
// modules in [moduleDirs] hold the go.mod text in goMod and the go.sum
// text in goSum. It writes no go.sum for an empty goSum. It returns the
// root of the repository.
func writeRepo(t *testing.T, goMod, goSum string) string {
	t.Helper()

	root := t.TempDir()

	for _, dir := range moduleDirs {
		dir = filepath.Join(root, filepath.FromSlash(dir))
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644))

		if goSum != "" {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "go.sum"), []byte(goSum), 0o644))
		}
	}

	return root
}

func TestRunRejectsArguments(t *testing.T) {
	t.Parallel()

	tests := map[string][]string{
		"no command":              nil,
		"unknown command":         {"tidy"},
		"check with an argument":  {cmdCheck, "ci"},
		"update with an argument": {cmdUpdate, "ci"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer

			err := run(t.Context(), args, writeRepo(t, renovatedMod, renovatedSum), os.Environ(), &out)
			require.ErrorIs(t, err, ErrUsage)
			assert.Empty(t, out.String())
		})
	}
}

func TestRunCheck(t *testing.T) {
	t.Parallel()

	t.Run("go.sum of go mod tidy", func(t *testing.T) {
		t.Parallel()

		root := writeRepo(t, renovatedMod, tidiedSum)

		var out bytes.Buffer

		require.NoError(t, run(t.Context(), []string{cmdCheck}, root, nil, &out))

		ci := filepath.Join(root, "ci")
		tests := filepath.Join(root, "ci", "tests")

		assert.Equal(t,
			filepath.Join(ci, "go.sum")+": holds each hash that "+filepath.Join(ci, "go.mod")+" requires\n"+
				filepath.Join(tests, "go.sum")+": holds each hash that "+filepath.Join(tests, "go.mod")+" requires\n",
			out.String(),
		)
	})

	// Renovate changed a requirement in go.mod and left go.sum
	// unchanged.
	t.Run("go.sum of the version before a Renovate update", func(t *testing.T) {
		t.Parallel()

		root := writeRepo(t, renovatedMod, renovatedSum)

		var out bytes.Buffer

		err := run(t.Context(), []string{cmdCheck}, root, nil, &out)
		require.ErrorIs(t, err, ErrStale)
		assert.Empty(t, out.String())

		for _, dir := range moduleDirs {
			dir = filepath.Join(root, filepath.FromSlash(dir))

			require.ErrorContains(t, err,
				filepath.Join(dir, "go.sum")+" does not match "+filepath.Join(dir, "go.mod")+
					" (run `go run ./cmd/modsum "+cmdUpdate+"`):\n"+
					"\tit holds no hash of github.com/vektah/gqlparser/v2 v2.5.35\n"+
					"\tit holds no go.mod hash of github.com/vektah/gqlparser/v2 v2.5.35\n"+
					"\tit holds a hash of github.com/vektah/gqlparser/v2 v2.5.34, and go.mod does not select that version",
			)

			// The command changes no file.
			assert.Equal(t, renovatedSum, readText(t, filepath.Join(dir, "go.sum")))
			assert.Equal(t, renovatedMod, readText(t, filepath.Join(dir, "go.mod")))
		}
	})

	t.Run("one stale module", func(t *testing.T) {
		t.Parallel()

		root := writeRepo(t, renovatedMod, tidiedSum)
		stale := filepath.Join(root, "ci", "tests", "go.sum")
		require.NoError(t, os.WriteFile(stale, []byte(renovatedSum), 0o644))

		var out bytes.Buffer

		err := run(t.Context(), []string{cmdCheck}, root, nil, &out)
		require.ErrorIs(t, err, ErrStale)
		require.ErrorContains(t, err, stale+" does not match")
		assert.NotContains(t, err.Error(), filepath.Join(root, "ci", "go.sum")+" does not match")

		// The command reports the module that passes.
		assert.Contains(t, out.String(), filepath.Join(root, "ci", "go.sum")+": holds each hash")
	})

	t.Run("no go.sum", func(t *testing.T) {
		t.Parallel()

		var out bytes.Buffer

		err := run(t.Context(), []string{cmdCheck}, writeRepo(t, renovatedMod, ""), nil, &out)
		require.ErrorIs(t, err, ErrStale)
		require.ErrorContains(t, err, "it holds no hash of github.com/Khan/genqlient v0.8.1")
	})

	t.Run("no requirement and no go.sum", func(t *testing.T) {
		t.Parallel()

		var out bytes.Buffer

		require.NoError(t, run(t.Context(), []string{cmdCheck}, writeRepo(t, "module dagger/ci\n", ""), nil, &out))
	})
}

// TestRunRejectsRepository checks that both commands fail for a
// repository whose files they cannot use, and that the update command
// leaves those files unchanged.
func TestRunRejectsRepository(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		goMod string
		goSum string
		err   error
		msg   string
	}{
		"go.mod is missing": {
			err: ErrModFile,
		},
		"go.mod is malformed": {
			goMod: "module dagger/ci\n\nrequire example.com/a\n",
			err:   ErrModFile,
			msg:   "go.mod:3",
		},
		"go.sum is malformed": {
			goMod: "module dagger/ci\n",
			goSum: "example.com/a v1.0.0\n",
			err:   ErrSumFile,
			msg:   "go.sum:1: a line has 2 fields, want 3",
		},
	}

	for name, tc := range tests {
		for _, command := range []string{cmdCheck, cmdUpdate} {
			t.Run(name+"/"+command, func(t *testing.T) {
				t.Parallel()

				root := writeRepo(t, tc.goMod, tc.goSum)
				if tc.goMod == "" {
					for _, dir := range moduleDirs {
						require.NoError(t, os.Remove(filepath.Join(root, filepath.FromSlash(dir), "go.mod")))
					}
				}

				var out bytes.Buffer

				err := run(t.Context(), []string{command}, root, newProxy(t), &out)
				require.ErrorIs(t, err, tc.err)
				require.ErrorContains(t, err, tc.msg)
				assert.Empty(t, out.String())

				for _, dir := range moduleDirs {
					dir = filepath.Join(root, filepath.FromSlash(dir))
					assert.Equal(t, tc.goMod, readText(t, filepath.Join(dir, "go.mod")))
					assert.Equal(t, tc.goSum, readText(t, filepath.Join(dir, "go.sum")))
				}
			})
		}
	}
}

// TestRunUpdate checks that the update command writes the go.mod and the
// go.sum that `go mod tidy` writes in a copy of the module that holds
// every package. The modules of the repository import a package that
// they do not hold, so `go mod tidy` cannot load their packages.
func TestRunUpdate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// The arguments of [repo.edit].
		old, text string

		// Whether the go command changes go.mod.
		goModChanges bool
	}{
		"requirement changes to a later version": {
			old:  "example.com/a v1.0.0",
			text: "example.com/a v1.2.0",
		},
		"requirement changes to an earlier version": {
			old:  "example.com/b v1.0.0",
			text: "example.com/b v0.9.0",
		},
		// The later version of the module requires a later version of
		// another requirement, so the go command raises that
		// requirement in go.mod.
		"later version needs a later version of another requirement": {
			old:          "example.com/a v1.0.0",
			text:         "example.com/a v1.1.0",
			goModChanges: true,
		},
		"replacement by a later version": {
			old:  "\nrequire (",
			text: "\nreplace example.com/a => example.com/a v1.2.0\n\nrequire (",
		},
		"replacement by another module": {
			old:  "\nrequire (",
			text: "\nreplace example.com/a => example.com/fork v1.0.0\n\nrequire (",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRepo(t)
			_, oldSum := r.files("ci")

			wantMod, wantSum := r.edit(tc.old, tc.text)
			require.NotEqual(t, wantSum, oldSum, "the change to go.mod does not change go.sum")

			var out bytes.Buffer

			err := run(t.Context(), []string{cmdCheck}, r.root, r.env, &out)
			require.ErrorIs(t, err, ErrStale)

			out.Reset()

			require.NoError(t, run(t.Context(), []string{cmdUpdate}, r.root, r.env, &out))

			for _, dir := range moduleDirs {
				goMod, goSum := r.files(dir)
				assert.Equal(t, wantMod, goMod)
				assert.Equal(t, wantSum, goSum)

				sumPath := filepath.Join(r.dir(dir), "go.sum")
				modPath := filepath.Join(r.dir(dir), "go.mod")

				assert.Contains(t, out.String(), sumPath+": changed to the hashes that "+modPath+" requires\n")

				if tc.goModChanges {
					assert.Contains(t, out.String(), modPath+": the go command changed the requirements\n")
				} else {
					assert.NotContains(t, out.String(), modPath+": the go command")
				}
			}

			out.Reset()

			require.NoError(t, run(t.Context(), []string{cmdCheck}, r.root, r.env, &out))

			// A second update changes nothing.
			out.Reset()

			require.NoError(t, run(t.Context(), []string{cmdUpdate}, r.root, r.env, &out))
			assert.NotContains(t, out.String(), "changed")

			for _, dir := range moduleDirs {
				goMod, goSum := r.files(dir)
				assert.Equal(t, wantMod, goMod)
				assert.Equal(t, wantSum, goSum)
			}
		})
	}
}

// TestRunUpdateKeepsGoModHash checks that the update command keeps the
// go.mod hash of a version that go.mod does not select. A dependency
// before Go 1.17 requires that version, so the go command reads its
// go.mod file.
func TestRunUpdateKeepsGoModHash(t *testing.T) {
	t.Parallel()

	const line = "example.com/b v0.9.0/go.mod h1:"

	r := newRepo(t)

	_, goSum := r.files("ci")
	require.Contains(t, goSum, line)
	require.NotContains(t, goSum, "example.com/b v0.9.0 h1:")

	_, wantSum := r.edit("example.com/a v1.0.0", "example.com/a v1.2.0")
	require.Contains(t, wantSum, line)

	var out bytes.Buffer

	require.NoError(t, run(t.Context(), []string{cmdUpdate}, r.root, r.env, &out))

	_, goSum = r.files("ci")
	assert.Equal(t, wantSum, goSum)
}

func TestRunUpdateOfTidyModule(t *testing.T) {
	t.Parallel()

	r := newRepo(t)
	wantMod, wantSum := r.files("ci")

	var out bytes.Buffer

	require.NoError(t, run(t.Context(), []string{cmdUpdate}, r.root, r.env, &out))

	for _, dir := range moduleDirs {
		goMod, goSum := r.files(dir)
		assert.Equal(t, wantMod, goMod)
		assert.Equal(t, wantSum, goSum)

		assert.Contains(
			t,
			out.String(),
			filepath.Join(
				r.dir(dir),
				"go.sum",
			)+": holds each hash that "+filepath.Join(
				r.dir(dir),
				"go.mod",
			)+" requires\n",
		)
	}
}

func TestRunUpdateCreatesGoSum(t *testing.T) {
	t.Parallel()

	r := newRepo(t)
	wantMod, wantSum := r.files("ci")

	for _, dir := range moduleDirs {
		require.NoError(t, os.Remove(filepath.Join(r.dir(dir), "go.sum")))
	}

	var out bytes.Buffer

	require.NoError(t, run(t.Context(), []string{cmdUpdate}, r.root, r.env, &out))

	for _, dir := range moduleDirs {
		goMod, goSum := r.files(dir)
		assert.Equal(t, wantMod, goMod)
		assert.Equal(t, wantSum, goSum)
	}
}

// TestRunUpdateRestoresFiles checks that the update command leaves go.mod
// and go.sum unchanged when the go command cannot download a module.
func TestRunUpdateRestoresFiles(t *testing.T) {
	t.Parallel()

	r := newRepo(t)
	_, wantSum := r.files("ci")

	// The proxy does not serve this version, and `go mod tidy` fails
	// for it too, so the test changes only the modules of the
	// repository.
	var wantMod string

	for _, dir := range moduleDirs {
		path := filepath.Join(r.dir(dir), "go.mod")

		wantMod = strings.Replace(readText(t, path), "example.com/a v1.0.0", "example.com/a v1.9.0", 1)
		require.Contains(t, wantMod, "example.com/a v1.9.0")
		require.NoError(t, os.WriteFile(path, []byte(wantMod), 0o644))
	}

	var out bytes.Buffer

	err := run(t.Context(), []string{cmdUpdate}, r.root, r.env, &out)
	require.ErrorIs(t, err, ErrDownload)
	require.ErrorContains(t, err, "example.com/a@v1.9.0")
	assert.Empty(t, out.String())

	for _, dir := range moduleDirs {
		goMod, goSum := r.files(dir)
		assert.Equal(t, wantMod, goMod)
		assert.Equal(t, wantSum, goSum)
	}
}

func TestFileStateRestore(t *testing.T) {
	t.Parallel()

	t.Run("changed file", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "go.sum")
		require.NoError(t, os.WriteFile(path, []byte(tidiedSum), 0o600))

		state, err := readState(path)
		require.NoError(t, err)

		require.NoError(t, os.WriteFile(path, []byte(renovatedSum), 0o600))
		require.NoError(t, state.restore())
		assert.Equal(t, tidiedSum, readText(t, path))

		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	})

	t.Run("new file", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "go.sum")

		state, err := readState(path)
		require.NoError(t, err)

		require.NoError(t, os.WriteFile(path, []byte(renovatedSum), 0o600))
		require.NoError(t, state.restore())
		assert.NoFileExists(t, path)
	})

	t.Run("unchanged file", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "go.sum")
		require.NoError(t, os.WriteFile(path, []byte(tidiedSum), 0o400))

		state, err := readState(path)
		require.NoError(t, err)

		require.NoError(t, state.restore())
		assert.Equal(t, tidiedSum, readText(t, path))
	})
}
