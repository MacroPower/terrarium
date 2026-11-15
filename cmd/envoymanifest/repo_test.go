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
	"go.jacobcolvin.com/terrarium/envoybin"
)

// readRepoFile returns the text of the file at path, which is relative to
// the root of the repository.
func readRepoFile(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(path)))
	require.NoError(t, err)

	return string(data)
}

// TestWorkflowCoversManifestPlatforms checks that the envoy workflow has
// one job for each platform of [envoybin.DefaultManifest]. A platform
// without a job gets no provenance check.
func TestWorkflowCoversManifestPlatforms(t *testing.T) {
	t.Parallel()

	workflow := readRepoFile(t, ".github/workflows/envoy.yaml")

	assert.Contains(t, workflow, `go run ./cmd/envoymanifest verify "$PLATFORM"`)

	matches := regexp.MustCompile(`(?m)^\s+- platform: (\S+)$`).FindAllStringSubmatch(workflow, -1)

	jobs := make([]string, 0, len(matches))
	for _, m := range matches {
		jobs = append(jobs, m[1])
	}

	var want []string

	for _, p := range platforms(envoybin.DefaultManifest()) {
		want = append(want, p.String())
	}

	assert.ElementsMatch(t, want, jobs)
}

// TestRenovateRunsUpdate checks that Renovate runs the update command
// after it changes the version in the manifest source file. The Renovate
// configuration must name the command, and the Renovate workflow must
// permit it.
func TestRenovateRunsUpdate(t *testing.T) {
	t.Parallel()

	const command = "go run ./cmd/envoymanifest " + cmdUpdate

	config := readRepoFile(t, ".github/renovate.json5")

	assert.Contains(t, config, `commands: ["`+command+`"]`)
	assert.Contains(t, config, `fileFilters: ["`+manifestSource+`"]`)

	// The custom manager must read the source file. A JSON5 string holds
	// each backslash of the pattern twice.
	assert.Contains(t, config, `"/^`+strings.ReplaceAll(manifestSource, ".", `\\.`)+`$/"`)

	workflow := readRepoFile(t, ".github/workflows/renovate.yaml")

	match := regexp.MustCompile(`(?m)^\s+RENOVATE_ALLOWED_COMMANDS: '(.*)'$`).FindStringSubmatch(workflow)
	require.NotNil(t, match, "the Renovate workflow does not set RENOVATE_ALLOWED_COMMANDS")

	var allowed []string

	require.NoError(t, json.Unmarshal([]byte(match[1]), &allowed))
	require.Len(t, allowed, 1)

	pattern, err := regexp.Compile(allowed[0])
	require.NoError(t, err)

	assert.True(t, pattern.MatchString(command), "%q does not permit %q", allowed[0], command)
	assert.False(t, pattern.MatchString(command+" && true"), "%q permits a longer command", allowed[0])
}
