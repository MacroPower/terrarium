package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/mod/module"
)

// proxyModule is one module version that a test module proxy serves.
type proxyModule struct {
	mod module.Version

	// The version of the go directive. The go command reads the go.mod
	// file of each dependency of a module before Go 1.17.
	goVersion string

	// The module path of the go.mod file, when it is not the path of
	// mod. A module that replaces another module declares the path of
	// that module.
	declares string

	// The modules that the go.mod file requires. The package of the
	// module imports each of them.
	requires []module.Version
}

// proxyModules holds the module versions that [newProxy] serves.
var proxyModules = []proxyModule{
	{mod: module.Version{Path: "example.com/a", Version: "v1.0.0"}},
	{
		mod:      module.Version{Path: "example.com/a", Version: "v1.1.0"},
		requires: []module.Version{{Path: "example.com/b", Version: "v1.1.0"}},
	},
	{mod: module.Version{Path: "example.com/a", Version: "v1.2.0"}},
	{mod: module.Version{Path: "example.com/b", Version: "v0.9.0"}},
	{mod: module.Version{Path: "example.com/b", Version: "v1.0.0"}},
	{mod: module.Version{Path: "example.com/b", Version: "v1.1.0"}},
	{
		mod:      module.Version{Path: "example.com/c", Version: "v1.0.0"},
		requires: []module.Version{{Path: "example.com/d", Version: "v1.0.0"}},
	},
	{mod: module.Version{Path: "example.com/d", Version: "v1.0.0"}},
	{
		mod:       module.Version{Path: "example.com/old", Version: "v1.0.0"},
		goVersion: "1.16",
		requires:  []module.Version{{Path: "example.com/b", Version: "v0.9.0"}},
	},
	{
		mod:      module.Version{Path: "example.com/fork", Version: "v1.0.0"},
		declares: "example.com/a",
	},
}

// newProxy creates a module proxy in a new temporary directory. The proxy
// serves [proxyModules] from files. The function returns the environment
// for a go command that downloads modules only from that proxy, into a
// module cache of its own.
func newProxy(t *testing.T) []string {
	t.Helper()

	root := t.TempDir()

	versions := map[string][]string{}

	for _, m := range proxyModules {
		dir := filepath.Join(root, filepath.FromSlash(m.mod.Path), "@v")
		require.NoError(t, os.MkdirAll(dir, 0o755))

		declares := m.declares
		if declares == "" {
			declares = m.mod.Path
		}

		goVersion := m.goVersion
		if goVersion == "" {
			goVersion = "1.21"
		}

		var goMod, source strings.Builder

		fmt.Fprintf(&goMod, "module %s\n\ngo %s\n", declares, goVersion)
		fmt.Fprintf(&source, "package %s\n", path.Base(declares))

		for _, r := range m.requires {
			fmt.Fprintf(&goMod, "\nrequire %s %s\n", r.Path, r.Version)
			fmt.Fprintf(&source, "\nimport _ %q\n", r.Path)
		}

		var archive bytes.Buffer

		prefix := m.mod.Path + "@" + m.mod.Version + "/"
		w := zip.NewWriter(&archive)

		for name, text := range map[string]string{"go.mod": goMod.String(), "lib.go": source.String()} {
			f, err := w.Create(prefix + name)
			require.NoError(t, err)

			_, err = f.Write([]byte(text))
			require.NoError(t, err)
		}

		require.NoError(t, w.Close())

		info := fmt.Sprintf(`{"Version":%q,"Time":"2024-01-01T00:00:00Z"}`, m.mod.Version)

		base := filepath.Join(dir, m.mod.Version)
		require.NoError(t, os.WriteFile(base+".mod", []byte(goMod.String()), 0o644))
		require.NoError(t, os.WriteFile(base+".zip", archive.Bytes(), 0o644))
		require.NoError(t, os.WriteFile(base+".info", []byte(info), 0o644))

		versions[dir] = append(versions[dir], m.mod.Version)
	}

	for dir, list := range versions {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "list"), []byte(strings.Join(list, "\n")+"\n"), 0o644))
	}

	// -modcacherw lets the test remove the module cache.
	return append(os.Environ(),
		"GOPROXY=file://"+filepath.ToSlash(root),
		"GOSUMDB=off",
		"GONOSUMDB=",
		"GONOPROXY=",
		"GOPRIVATE=",
		"GOFLAGS=-modcacherw",
		"GOMODCACHE="+t.TempDir(),
		"GOTOOLCHAIN=local",
		"GOWORK=off",
	)
}

// The files of the test module. Its go.mod requires modules of
// [proxyModules]. The module in [repo.ci] holds daggerSource, which
// imports a package that the module does not hold, as a Dagger module
// does before Dagger generates its code. The module in [repo.tidy] holds
// tidySource, which imports the same modules and no missing package, so
// `go mod tidy` works there.
const (
	baseMod = `module example.com/ci

go 1.26.0

require (
	example.com/a v1.0.0
	example.com/b v1.0.0
	example.com/c v1.0.0
	example.com/old v1.0.0
)
`

	tidySource = `package ci

import (
	_ "example.com/a"
	_ "example.com/b"
	_ "example.com/c"
	_ "example.com/old"
)
`

	daggerSource = `package ci

import (
	_ "example.com/a"
	_ "example.com/b"
	_ "example.com/c"
	_ "example.com/ci/internal/dagger"
	_ "example.com/old"
)
`
)

// repo is a repository in a temporary directory that holds one copy of
// the test module in each directory of [moduleDirs]. Create instances
// with [newRepo].
type repo struct {
	t *testing.T

	// The root of the repository.
	root string

	// The environment of [newProxy].
	env []string

	// The directory of a copy of the test module outside the
	// repository. `go mod tidy` there writes the go.mod and the go.sum
	// that the update command writes in the repository.
	tidy string
}

// newRepo creates a [repo] whose modules hold the go.mod and go.sum that
// `go mod tidy` writes for [baseMod].
func newRepo(t *testing.T) *repo {
	t.Helper()

	r := &repo{t: t, root: t.TempDir(), env: newProxy(t), tidy: t.TempDir()}

	require.NoError(t, os.WriteFile(filepath.Join(r.tidy, "go.mod"), []byte(baseMod), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(r.tidy, "ci.go"), []byte(tidySource), 0o644))

	goMod, goSum := r.goModTidy()

	for _, dir := range moduleDirs {
		dir = r.dir(dir)
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "go.sum"), []byte(goSum), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "ci.go"), []byte(daggerSource), 0o644))
	}

	return r
}

// dir returns the path of the module of the repository in dir, which is
// one of [moduleDirs].
func (r *repo) dir(dir string) string {
	return filepath.Join(r.root, filepath.FromSlash(dir))
}

// goModTidy runs `go mod tidy` in the module in [repo.tidy] and returns
// the text of its go.mod and go.sum.
func (r *repo) goModTidy() (string, string) {
	r.t.Helper()

	cmd := exec.CommandContext(r.t.Context(), "go", "mod", "tidy")
	cmd.Dir = r.tidy
	cmd.Env = r.env

	output, err := cmd.CombinedOutput()
	require.NoError(r.t, err, "go mod tidy: %s", output)

	return readText(r.t, filepath.Join(r.tidy, "go.mod")), readText(r.t, filepath.Join(r.tidy, "go.sum"))
}

// edit replaces old with text in the go.mod of each module of the
// repository and leaves go.sum unchanged, as Renovate does. It makes the
// same change in [repo.tidy] and returns the go.mod and go.sum that
// `go mod tidy` writes for the changed go.mod.
func (r *repo) edit(old, text string) (string, string) {
	r.t.Helper()

	dirs := []string{r.tidy}
	for _, dir := range moduleDirs {
		dirs = append(dirs, r.dir(dir))
	}

	for _, dir := range dirs {
		name := filepath.Join(dir, "go.mod")

		goMod := readText(r.t, name)
		require.Contains(r.t, goMod, old)
		require.NoError(r.t, os.WriteFile(name, []byte(strings.Replace(goMod, old, text, 1)), 0o644))
	}

	return r.goModTidy()
}

// files returns the text of go.mod and go.sum of the module of the
// repository in dir. The text of a missing file is empty.
func (r *repo) files(dir string) (string, string) {
	r.t.Helper()

	return readText(r.t, filepath.Join(r.dir(dir), "go.mod")), readText(r.t, filepath.Join(r.dir(dir), "go.sum"))
}

// readText returns the text of the file called name, or the empty string
// when no such file exists.
func readText(t *testing.T, name string) string {
	t.Helper()

	data, err := os.ReadFile(name)
	if os.IsNotExist(err) {
		return ""
	}

	require.NoError(t, err)

	return string(data)
}
