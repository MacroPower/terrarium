package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// moduleDir is the directory of this module, relative to the root of the
// repository.
const moduleDir = "cmd/vendorhash"

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

// TestFlakeHoldsVendorHash checks that the commands can read the flake of
// this repository, and that the flake vendors the root module as the
// commands do. The lint task compares the hash with the vendor tree, and
// the test does not. The tests run without internet access, and the
// module cache might not hold the dependencies of every platform, which
// the vendor tree holds.
func TestFlakeHoldsVendorHash(t *testing.T) {
	t.Parallel()

	f, err := readFlake(filepath.Join(repoRoot, filepath.FromSlash(flakeSource)))
	require.NoError(t, err)

	assert.Regexp(t, `^sha256-[0-9A-Za-z+/]{43}=$`, f.hash())

	// The go command vendors the root module only outside the workspace.
	assert.Contains(t, f.text, `env.GOWORK = "off";`)
}

// TestTasksRunCommands checks that the lint task runs the check command
// and that the format task runs the update command.
func TestTasksRunCommands(t *testing.T) {
	t.Parallel()

	tasks := readRepoFile(t, ".taskfiles/go/Taskfile.yaml")

	assert.Regexp(t, `(?m)^  vendor-hash:\n(    .*\n)*    cmd: go run \./cmd/vendorhash `+cmdUpdate+`\n`, tasks)
	assert.Regexp(t, `(?m)^  vendor-hash:check:\n(    .*\n)*    cmd: go run \./cmd/vendorhash `+cmdCheck+`\n`, tasks)

	// A task that reads the flake as a source runs again after a change
	// to the hash.
	assert.Regexp(t, `(?m)^      - `+regexp.QuoteMeta(flakeSource)+`$`, tasks)

	root := readRepoFile(t, "Taskfile.yaml")

	assert.Regexp(t, `(?m)^  format:\n(    .*\n)*      - task: go:vendor-hash\n`, root)
	// Prettier moves a list that does not fit on the line of its key to
	// the next line.
	assert.Regexp(t, `(?m)^  lint:\n(    .*\n)*    deps:\s+\[[^\]]*\bgo:vendor-hash:check\b[^\]]*\]\n`, root)
}

// TestTasksRunTestsWithoutCache checks that the test tasks run the tests
// of this module without the test cache. The tests in this file read
// files outside this module. The go command does not track those files,
// so it reuses the cached result of a test after a change to one of
// them.
func TestTasksRunTestsWithoutCache(t *testing.T) {
	t.Parallel()

	// The lines of a task after its name, which can include empty
	// lines.
	const body = `(?:(?:    .*)?\n)*`

	tasks := readRepoFile(t, ".taskfiles/go/Taskfile.yaml")

	match := regexp.MustCompile(`(?m)^ {2}UNCACHED_TEST_MODULES: (.*)$`).FindStringSubmatch(tasks)
	require.NotNil(t, match, "the Taskfile does not set UNCACHED_TEST_MODULES")

	assert.Contains(t, strings.Fields(match[1]), moduleDir)

	for _, task := range []string{"test", "test:integration"} {
		assert.Regexp(t,
			`(?m)^  `+task+`:\n`+body+`      - go test -count=1 .* \{\{\.UNCACHED_TEST_PKGS\}\}\n`,
			tasks,
			"the %s task does not run the modules of UNCACHED_TEST_MODULES with -count=1", task,
		)
	}

	// The coverage task writes one profile, so one command runs the
	// tests of every module.
	assert.Regexp(t,
		`(?m)^  test:cover:\n`+body+`      - go test -count=1 .* \{\{\.TEST_PKGS\}\}\n`,
		tasks,
		"the test:cover task does not run the tests with -count=1",
	)
}

// TestRenovateRunsUpdate checks that Renovate runs the update command
// after it changes a dependency in the root go.mod. The Renovate
// configuration must name the command, and the Renovate workflow must
// permit it.
func TestRenovateRunsUpdate(t *testing.T) {
	t.Parallel()

	const command = "go run ./cmd/vendorhash " + cmdUpdate

	config := readRepoFile(t, ".github/renovate.json5")

	rule := regexp.MustCompile(`(?s)matchManagers: \["gomod"\],\s+matchFileNames: \["go\.mod"\],\s+postUpgradeTasks: \{(.*?)\}`).
		FindStringSubmatch(config)
	require.NotNil(t, rule, "the Renovate configuration has no post-upgrade task for the root go.mod")

	assert.Contains(t, rule[1], `commands: ["`+command+`"]`)
	assert.Contains(t, rule[1], `fileFilters: ["`+flakeSource+`"]`)

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
