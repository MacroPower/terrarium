package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.Regexp(t, `(?m)^  lint:\n(    .*\n)*    deps: \[.*\bgo:vendor-hash:check\b.*\]\n`, root)
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
