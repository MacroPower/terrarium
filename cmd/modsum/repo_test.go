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
	"golang.org/x/mod/semver"
)

// otelPath is the path of the root module of OpenTelemetry for Go. The
// paths of its other modules start with this path and a slash.
const otelPath = "go.opentelemetry.io/otel"

// otelLogPath is the path of the OpenTelemetry log module.
const otelLogPath = otelPath + "/log"

// otelLimit is the first version of the OpenTelemetry modules in which
// otel/internal/global imports otel/log. A Dagger module does not compile
// when it selects this version or a later one of an OpenTelemetry module
// and a version of otel/log that imports otel/internal/global. v0.16.0
// of otel/log, which the Dagger code generator selects, has that import,
// and v1.47.0 does not.
const otelLimit = "v1.47.0"

// moduleDir is the directory of this module, relative to the root of the
// repository.
const moduleDir = "cmd/modsum"

var (
	// repoRoot is the path of the root of the repository, relative to
	// the directory of this package.
	repoRoot = filepath.Join("..", "..")

	// generatorReplaces holds the paths of the OpenTelemetry log
	// modules. The Dagger code generator writes a replace directive for
	// each of them into the go.mod of each Dagger module.
	generatorReplaces = []string{
		otelPath + "/exporters/otlp/otlplog/otlploggrpc",
		otelPath + "/exporters/otlp/otlplog/otlploghttp",
		otelLogPath,
		otelPath + "/sdk/log",
	}
)

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

// quoted returns each string that list holds in double quotes. The list
// argument is the text between the brackets of a list of strings in the
// Renovate configuration.
func quoted(list string) []string {
	var items []string

	for _, match := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(list, -1) {
		items = append(items, match[1])
	}

	return items
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

// TestRenovateKeepsOpenTelemetryVersions checks that Renovate proposes no
// OpenTelemetry version that a Dagger module cannot use. One package rule
// must disable the modules that the Dagger code generator replaces.
// Another rule must limit the other OpenTelemetry modules to the versions
// before [otelLimit]. Each go.mod must still give the reason for both
// rules.
func TestRenovateKeepsOpenTelemetryVersions(t *testing.T) {
	t.Parallel()

	config := readRepoFile(t, ".github/renovate.json5")

	// The matchers that open each rule for the go.mod of the Dagger
	// modules, and the list of package names after them.
	packages := `(?s)matchManagers: \["gomod"\],\s+matchFileNames: ` +
		regexp.QuoteMeta(quoteList(moduleFiles("go.mod"))) +
		`,\s+matchPackageNames: \[([^\]]*)\],\s+`

	disabled := regexp.MustCompile(packages + `enabled: false,`).FindStringSubmatch(config)
	require.NotNil(
		t,
		disabled,
		"the Renovate configuration has no rule that disables modules in the go.mod of each Dagger module",
	)

	assert.ElementsMatch(t, generatorReplaces, quoted(disabled[1]))

	limit := regexp.MustCompile(packages + `allowedVersions: "([^"]*)",`).FindStringSubmatch(config)
	require.NotNil(
		t,
		limit,
		"the Renovate configuration has no rule that limits versions in the go.mod of each Dagger module",
	)

	// A glob of Renovate matches a slash only with a path segment of two
	// asterisks, so the root module needs a pattern of its own.
	assert.ElementsMatch(t, []string{otelPath, otelPath + "/**"}, quoted(limit[1]))

	// The range has the syntax of npm, so it names the version without
	// the v of a Go version.
	assert.Equal(t, "<"+strings.TrimPrefix(otelLimit, "v"), limit[2])

	for _, file := range moduleFiles("go.mod") {
		mod, err := modfile.Parse(file, []byte(readRepoFile(t, file)), nil)
		require.NoError(t, err)

		replaced := map[string]string{}
		for _, rep := range mod.Replace {
			replaced[rep.Old.Path] = rep.New.Version
		}

		for _, path := range generatorReplaces {
			assert.Contains(t, replaced, path,
				"%s does not replace %s, so remove the module from the rule that disables it", file, path)
		}

		// The limit has a reason only for a version of the log module
		// that imports otel/internal/global.
		version, ok := replaced[otelLogPath]
		if ok {
			assert.Negative(t, semver.Compare(version, otelLimit),
				"%s replaces %s with %s, so remove the rule that limits the versions", file, otelLogPath, version)
		}
	}
}
