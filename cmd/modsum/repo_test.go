package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
)

// repoRoot is the path of the root of the repository, relative to the
// directory of this package.
var repoRoot = filepath.Join("..", "..")

// readRepoFile returns the text of the file at path, which is relative to
// the root of the repository.
func readRepoFile(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(path)))
	require.NoError(t, err)

	return string(data)
}

// quoteList returns items as the text of a list of strings in the
// Renovate configuration.
func quoteList(items []string) string {
	return `["` + strings.Join(items, `", "`) + `"]`
}

// moduleFiles returns the path of the file called name in each module
// of [moduleDirs], relative to the root of the repository.
func moduleFiles(names ...string) []string {
	var files []string

	for _, dir := range moduleDirs {
		for _, name := range names {
			files = append(files, dir+"/"+name)
		}
	}

	return files
}

// TestRepositoryPassesCheck checks that go.sum matches go.mod in each
// Dagger module of this repository.
func TestRepositoryPassesCheck(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer

	require.NoError(t, run(t.Context(), []string{cmdCheck}, repoRoot, nil, &out))
}

// TestModuleDirsHoldModulesOutsideWorkspace checks that [moduleDirs]
// names each Go module of this repository that is outside the workspace
// of go.work. The tidy check of the lint task covers the modules of the
// workspace and no other module.
func TestModuleDirsHoldModulesOutsideWorkspace(t *testing.T) {
	t.Parallel()

	work, err := modfile.ParseWork("go.work", []byte(readRepoFile(t, "go.work")), nil)
	require.NoError(t, err)

	workspace := map[string]bool{}
	for _, use := range work.Use {
		workspace[filepath.ToSlash(filepath.Clean(use.Path))] = true
	}

	var outside []string

	err = filepath.WalkDir(repoRoot, func(path string, entry fs.DirEntry, err error) error {
		// Other tests remove their files during the walk.
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}

		if err != nil {
			return err
		}

		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}

		if entry.IsDir() {
			// Directories that start with a period hold tools, caches,
			// and other checkouts. The go command ignores testdata.
			name := entry.Name()
			if rel != "." && (strings.HasPrefix(name, ".") || name == "testdata") {
				return filepath.SkipDir
			}

			return nil
		}

		dir := filepath.ToSlash(filepath.Dir(rel))
		if entry.Name() == "go.mod" && !workspace[dir] {
			outside = append(outside, dir)
		}

		return nil
	})
	require.NoError(t, err)

	assert.ElementsMatch(t, moduleDirs, outside)
}

// TestTasksRunCommands checks that the lint task runs the check command
// and that the format task runs the update command.
func TestTasksRunCommands(t *testing.T) {
	t.Parallel()

	tasks := readRepoFile(t, ".taskfiles/go/Taskfile.yaml")

	assert.Regexp(t, `(?m)^  mod-sum:\n(    .*\n)*    cmd: go run \./cmd/modsum `+cmdUpdate+`\n`, tasks)
	assert.Regexp(t, `(?m)^  mod-sum:check:\n(    .*\n)*    cmd: go run \./cmd/modsum `+cmdCheck+`\n`, tasks)

	// A task that reads the files of a module as sources runs again
	// after a change to one of them.
	for _, file := range moduleFiles("go.mod", "go.sum") {
		assert.Regexp(t, `(?m)^      - `+regexp.QuoteMeta(file)+`$`, tasks)
	}

	root := readRepoFile(t, "Taskfile.yaml")

	assert.Regexp(t, `(?m)^  format:\n(    .*\n)*      - task: go:mod-sum\n`, root)
	// Prettier moves a list that does not fit on the line of its key to
	// the next line.
	assert.Regexp(t, `(?m)^  lint:\n(    .*\n)*    deps:\s+\[[^\]]*\bgo:mod-sum:check\b[^\]]*\]\n`, root)
}

// TestRenovateRunsUpdate checks that Renovate runs the update command
// after it changes a dependency in the go.mod of a Dagger module. The
// Renovate configuration must name the command, and the Renovate workflow
// must permit it.
func TestRenovateRunsUpdate(t *testing.T) {
	t.Parallel()

	const command = "go run ./cmd/modsum " + cmdUpdate

	config := readRepoFile(t, ".github/renovate.json5")

	rule := regexp.MustCompile(
		`(?s)matchManagers: \["gomod"\],\s+matchFileNames: ` +
			regexp.QuoteMeta(quoteList(moduleFiles("go.mod"))) +
			`,\s+postUpgradeTasks: \{(.*?)\}`,
	).FindStringSubmatch(config)
	require.NotNil(t, rule, "the Renovate configuration has no post-upgrade task for the go.mod of each Dagger module")

	assert.Contains(t, rule[1], `commands: ["`+command+`"]`)

	// The go command can change go.mod, so the commit takes both files
	// of each module.
	assert.Contains(t, rule[1], `fileFilters: `+quoteList(moduleFiles("go.mod", "go.sum")))

	workflow := readRepoFile(t, ".github/workflows/renovate.yaml")

	match := regexp.MustCompile(`(?m)^\s+RENOVATE_ALLOWED_COMMANDS: '(.*)'$`).FindStringSubmatch(workflow)
	require.NotNil(t, match, "the Renovate workflow does not set RENOVATE_ALLOWED_COMMANDS")

	var allowed []string

	require.NoError(t, json.Unmarshal([]byte(match[1]), &allowed))

	// The patterns that permit the command.
	var permits []string

	for _, expr := range allowed {
		pattern, err := regexp.Compile(expr)
		require.NoError(t, err)

		if pattern.MatchString(command) {
			permits = append(permits, expr)
		}

		assert.False(t, pattern.MatchString(command+" && true"), "%q permits a longer command", expr)
	}

	assert.Len(t, permits, 1, "want one pattern of %q that permits %q", allowed, command)
}
