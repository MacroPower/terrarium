package envoybin_test

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

// The test of the Renovate files is in this package because this package
// is in the module at the root of the repository. The envoymanifest
// command is a module of its own. The go command drops the cached result
// of a test only when a file that the test read inside its own module
// changes. A test in the module of the command therefore keeps its cached
// result after a change to a file under .github.

// Paths of the files that the Renovate test reads, and the values that
// the files must hold. The envoymanifest command defines the name of its
// update command and the default path of the source file.
const (
	// The paths of the Renovate files are relative to the directory of
	// this package.
	renovateConfigPath   = "../.github/renovate.json5"
	renovateWorkflowPath = "../.github/workflows/renovate.yaml"

	// updateCommand writes the hashes of the pinned version into the
	// manifest source file. Renovate runs it in the root of the
	// repository.
	updateCommand = "go run ./cmd/envoymanifest update"

	// manifestSource is the path of the Go source file that defines
	// [envoybin.DefaultManifest], relative to the root of the repository.
	manifestSource = "envoybin/manifest.go"
)

// TestRenovateRunsUpdate checks that Renovate runs the update command
// after it changes the version in the manifest source file. The Renovate
// configuration must name the command, and the Renovate workflow must
// permit it.
func TestRenovateRunsUpdate(t *testing.T) {
	t.Parallel()

	require.FileExists(t, filepath.Join("..", filepath.FromSlash(manifestSource)))

	data, err := os.ReadFile(filepath.FromSlash(renovateConfigPath))
	require.NoError(t, err)

	config := string(data)

	assert.Contains(t, config, `commands: ["`+updateCommand+`"]`)
	assert.Contains(t, config, `fileFilters: ["`+manifestSource+`"]`)

	// The custom manager must read the source file. A JSON5 string holds
	// each backslash of the pattern twice.
	assert.Contains(t, config, `"/^`+strings.ReplaceAll(manifestSource, ".", `\\.`)+`$/"`)

	data, err = os.ReadFile(filepath.FromSlash(renovateWorkflowPath))
	require.NoError(t, err)

	match := regexp.MustCompile(`(?m)^\s+RENOVATE_ALLOWED_COMMANDS: '(.*)'$`).FindSubmatch(data)
	require.NotNil(t, match, "the Renovate workflow does not set RENOVATE_ALLOWED_COMMANDS")

	var allowed []string

	require.NoError(t, json.Unmarshal(match[1], &allowed))

	// The patterns that permit the command.
	var permits []string

	for _, expr := range allowed {
		pattern, err := regexp.Compile(expr)
		require.NoError(t, err)

		if pattern.MatchString(updateCommand) {
			permits = append(permits, expr)
		}

		assert.False(t, pattern.MatchString(updateCommand+" && true"), "%q permits a longer command", expr)
	}

	assert.Len(t, permits, 1, "want one pattern of %q that permits %q", allowed, updateCommand)
}
