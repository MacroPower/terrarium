// Integration tests for the [Go] module. Individual tests are annotated
// with +check so `dagger check -m toolchains/go/tests` runs them all concurrently.
//
// Security invariant: no test in this module should use
// InsecureRootCapabilities or ExperimentalPrivilegedNesting.
// These options bypass container sandboxing and are only appropriate
// for interactive use (Dev terminal). Adding either to a test
// function requires explicit security review justification.

package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/tests/internal/dagger"

	"golang.org/x/sync/errgroup"
)

// Tests provides integration tests for the [Go] module. Create instances
// with [New].
type Tests struct{}

// All runs all tests in parallel.
func (m *Tests) All(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return m.TestSourceFiltering(ctx) })
	g.Go(func() error { return m.TestGenerateIdempotent(ctx) })
	g.Go(func() error { return m.TestCoverageProfile(ctx) })
	g.Go(func() error { return m.TestEnv(ctx) })
	g.Go(func() error { return m.TestBuild(ctx) })
	g.Go(func() error { return m.TestBinary(ctx) })
	g.Go(func() error { return m.TestDownload(ctx) })
	g.Go(func() error { return m.TestModules(ctx) })
	g.Go(func() error { return m.TestModulesInclude(ctx) })
	g.Go(func() error { return m.TestModulesExclude(ctx) })
	g.Go(func() error { return m.TestLintModule(ctx) })
	g.Go(func() error { return m.TestTidyModule(ctx) })
	g.Go(func() error { return m.TestVersionTags(ctx) })
	g.Go(func() error { return m.TestVariantTag(ctx) })
	g.Go(func() error { return m.TestFormatDigestChecksums(ctx) })
	g.Go(func() error { return m.TestDeduplicateDigests(ctx) })
	g.Go(func() error { return m.TestRegistryHost(ctx) })
	g.Go(func() error { return m.TestLintDeadcodeClean(ctx) })
	g.Go(func() error { return m.TestLintPrettierClean(ctx) })
	g.Go(func() error { return m.TestFormatIdempotent(ctx) })
	g.Go(func() error { return m.TestReleaseSummary(ctx) })
	g.Go(func() error { return m.TestBuildDist(ctx) })

	return g.Wait()
}

// TestSourceFiltering verifies that the +ignore annotation in [Go.New]
// excludes the expected directories from the source.
//
// +check
func (m *Tests) TestSourceFiltering(ctx context.Context) error {
	entries, err := dag.Go().Source().Entries(ctx)
	if err != nil {
		return fmt.Errorf("list source entries: %w", err)
	}

	excluded := []string{"dist", ".worktrees", ".tmp", ".git"}
	for _, dir := range excluded {
		for _, entry := range entries {
			if strings.TrimRight(entry, "/") == dir {
				return fmt.Errorf("source should exclude %q but it was present", dir)
			}
		}
	}

	// Verify essential files are present.
	required := []string{"go.mod", "toolchains"}
	for _, name := range required {
		found := false
		for _, entry := range entries {
			if strings.TrimRight(entry, "/") == name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("source should include %q but it was missing (entries: %v)", name, entries)
		}
	}

	return nil
}

// TestGenerateIdempotent verifies that running the generator on
// already-generated source produces an empty changeset. This exercises the
// full [Go.Generate] pipeline and confirms the source is clean.
//
// +check
func (m *Tests) TestGenerateIdempotent(ctx context.Context) error {
	changeset := dag.Go().Generate()

	empty, err := changeset.IsEmpty(ctx)
	if err != nil {
		return fmt.Errorf("check changeset: %w", err)
	}
	if !empty {
		modified, _ := changeset.ModifiedPaths(ctx)
		added, _ := changeset.AddedPaths(ctx)
		removed, _ := changeset.RemovedPaths(ctx)
		return fmt.Errorf("expected empty changeset on clean source, modified=%v added=%v removed=%v",
			modified, added, removed)
	}
	return nil
}

// TestCoverageProfile verifies that [Go.TestCoverage] returns a non-empty
// Go coverage profile containing the expected "mode:" header line.
//
// +check
func (m *Tests) TestCoverageProfile(ctx context.Context) error {
	contents, err := dag.Go().TestCoverage().Contents(ctx)
	if err != nil {
		return fmt.Errorf("read coverage profile: %w", err)
	}
	if len(contents) == 0 {
		return fmt.Errorf("coverage profile is empty")
	}
	if !strings.Contains(contents, "mode:") {
		return fmt.Errorf("coverage profile missing 'mode:' header (got %d bytes)", len(contents))
	}
	return nil
}

// TestEnv verifies that [Go.Env] returns a working Go container with
// the expected environment configuration.
//
// +check
func (m *Tests) TestEnv(ctx context.Context) error {
	// Verify the container can run go version.
	out, err := dag.Go().Env(dagger.GoEnvOpts{}).
		WithExec([]string{"go", "version"}).
		Stdout(ctx)
	if err != nil {
		return fmt.Errorf("go version: %w", err)
	}
	if !strings.Contains(out, "go1.") {
		return fmt.Errorf("expected go version output, got: %s", out)
	}

	// Verify source is mounted.
	_, err = dag.Go().Env(dagger.GoEnvOpts{}).
		WithExec([]string{"test", "-f", "go.mod"}).
		Sync(ctx)
	if err != nil {
		return fmt.Errorf("go.mod not found in env: %w", err)
	}

	return nil
}

// TestBuild verifies that [Go.Build] compiles packages to the output directory.
//
// +check
func (m *Tests) TestBuild(ctx context.Context) error {
	dir := dag.Go().Build(dagger.GoBuildOpts{
		Pkgs:   []string{"./cmd/terrarium"},
		OutDir: "./bin/",
	})

	entries, err := dir.Entries(ctx)
	if err != nil {
		return fmt.Errorf("list entries: %w", err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("build produced no output")
	}

	// Verify there's a bin directory or binary.
	hasBin := false
	for _, entry := range entries {
		if strings.Contains(entry, "bin") {
			hasBin = true
			break
		}
	}
	if !hasBin {
		return fmt.Errorf("expected bin directory in output, got: %v", entries)
	}

	return nil
}

// TestBinary verifies that [Go.Binary] compiles a single package and
// returns the binary file.
//
// +check
func (m *Tests) TestBinary(ctx context.Context) error {
	binary := dag.Go().Binary("./cmd/terrarium", dagger.GoBinaryOpts{
		NoSymbols: true,
		NoDwarf:   true,
	})

	size, err := binary.Size(ctx)
	if err != nil {
		return fmt.Errorf("binary size: %w", err)
	}
	if size == 0 {
		return fmt.Errorf("binary has zero size")
	}

	return nil
}

// TestDownload verifies that [Go.Download] warms the module cache.
//
// +check
func (m *Tests) TestDownload(ctx context.Context) error {
	// Download returns a *Go; force evaluation by invoking Env and syncing.
	_, err := dag.Go().Download().Env(dagger.GoEnvOpts{}).Sync(ctx)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Multi-module tests
// ---------------------------------------------------------------------------

// TestModules verifies that [Go.Modules] discovers at least the root module.
//
// +check
func (m *Tests) TestModules(ctx context.Context) error {
	mods, err := dag.Go().Modules(ctx)
	if err != nil {
		return fmt.Errorf("modules: %w", err)
	}
	if len(mods) == 0 {
		return fmt.Errorf("expected at least one module, got none")
	}

	hasRoot := false
	for _, mod := range mods {
		if mod == "." {
			hasRoot = true
			break
		}
	}
	if !hasRoot {
		return fmt.Errorf("expected root module '.' in %v", mods)
	}
	return nil
}

// TestModulesInclude verifies that include patterns filter module results.
//
// +check
func (m *Tests) TestModulesInclude(ctx context.Context) error {
	mods, err := dag.Go().Modules(ctx, dagger.GoModulesOpts{
		Include: []string{"."},
	})
	if err != nil {
		return fmt.Errorf("modules with include: %w", err)
	}
	if len(mods) != 1 || mods[0] != "." {
		return fmt.Errorf("expected only root module '.', got %v", mods)
	}
	return nil
}

// TestModulesExclude verifies that exclude patterns filter out modules.
//
// +check
func (m *Tests) TestModulesExclude(ctx context.Context) error {
	mods, err := dag.Go().Modules(ctx, dagger.GoModulesOpts{
		Exclude: []string{"toolchains/**"},
	})
	if err != nil {
		return fmt.Errorf("modules with exclude: %w", err)
	}
	for _, mod := range mods {
		if strings.HasPrefix(mod, "toolchains/") {
			return fmt.Errorf("expected toolchains to be excluded, but found %q in %v", mod, mods)
		}
	}
	return nil
}

// TestLintModule verifies that [Go.LintModule] succeeds on the root module.
//
// +check
func (m *Tests) TestLintModule(ctx context.Context) error {
	err := dag.Go().LintModule(ctx, ".")
	if err != nil {
		return fmt.Errorf("lint module '.': %w", err)
	}
	return nil
}

// TestTidyModule verifies that [Go.TidyModule] returns an empty changeset
// on clean source.
//
// +check
func (m *Tests) TestTidyModule(ctx context.Context) error {
	changeset := dag.Go().TidyModule(".")

	empty, err := changeset.IsEmpty(ctx)
	if err != nil {
		return fmt.Errorf("check tidy changeset: %w", err)
	}
	if !empty {
		modified, _ := changeset.ModifiedPaths(ctx)
		return fmt.Errorf("expected empty changeset on clean source, modified=%v", modified)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Publish & release tests
// ---------------------------------------------------------------------------

// TestVersionTags verifies that [Go.VersionTags] returns the expected
// set of image tags for various version strings.
//
// +check
func (m *Tests) TestVersionTags(ctx context.Context) error {
	cases := map[string]struct {
		tag  string
		want []string
	}{
		"semver": {
			tag:  "v1.2.3",
			want: []string{"latest", "v1.2.3", "v1", "v1.2"},
		},
		"pre-release": {
			tag:  "v0.5.1-rc.1",
			want: []string{"v0.5.1-rc.1"},
		},
		"two-component": {
			tag:  "v2.0",
			want: []string{"latest", "v2.0", "v2", "v2.0"},
		},
		"single-component": {
			tag:  "v1",
			want: []string{"latest", "v1", "v1"},
		},
		"four-component": {
			tag:  "v1.2.3.4",
			want: []string{"latest", "v1.2.3.4", "v1", "v1.2"},
		},
		"empty-string": {
			tag:  "",
			want: []string{"latest", "", "v"},
		},
		"no-v-prefix": {
			tag:  "1.2.3",
			want: []string{"latest", "1.2.3", "v1", "v1.2"},
		},
		"hyphen-in-first-component": {
			tag:  "v0-beta.1",
			want: []string{"v0-beta.1"},
		},
	}

	for name, tc := range cases {
		got, err := dag.Go().VersionTags(ctx, tc.tag)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if len(got) != len(tc.want) {
			return fmt.Errorf("%s: got %v, want %v", name, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				return fmt.Errorf("%s: index %d: got %q, want %q", name, i, got[i], tc.want[i])
			}
		}
	}

	return nil
}

// TestVariantTag verifies that [Go.VariantTag] applies variant suffixes
// correctly, using the defaultVariant parameter to determine which variant
// gets unmodified tags.
//
// +check
func (m *Tests) TestVariantTag(ctx context.Context) error {
	cases := map[string]struct {
		tag            string
		variant        string
		defaultVariant string
		want           string
	}{
		"default-variant-unchanged": {
			tag: "v1.2.3", variant: "scratch", defaultVariant: "scratch",
			want: "v1.2.3",
		},
		"non-default-versioned": {
			tag: "v1.2.3", variant: "debian", defaultVariant: "scratch",
			want: "v1.2.3-debian",
		},
		"non-default-latest": {
			tag: "latest", variant: "debian", defaultVariant: "scratch",
			want: "debian",
		},
		"default-latest": {
			tag: "latest", variant: "scratch", defaultVariant: "scratch",
			want: "latest",
		},
		"custom-default": {
			tag: "v1.0.0", variant: "alpine", defaultVariant: "alpine",
			want: "v1.0.0",
		},
		"custom-non-default": {
			tag: "v1.0.0", variant: "slim", defaultVariant: "alpine",
			want: "v1.0.0-slim",
		},
	}

	for name, tc := range cases {
		got, err := dag.Go().VariantTag(ctx, tc.tag, tc.variant, tc.defaultVariant)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if got != tc.want {
			return fmt.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}

	return nil
}

// TestFormatDigestChecksums verifies that [Go.FormatDigestChecksums]
// converts publish output to the checksums format, deduplicating by digest.
//
// +check
func (m *Tests) TestFormatDigestChecksums(ctx context.Context) error {
	refs := []string{
		"ghcr.io/test:v1@sha256:abc123",
		"ghcr.io/test:v2@sha256:abc123", // duplicate digest
		"ghcr.io/test:latest@sha256:def456",
	}

	result, err := dag.Go().FormatDigestChecksums(ctx, refs)
	if err != nil {
		return fmt.Errorf("format: %w", err)
	}

	lines := strings.Split(strings.TrimSpace(result), "\n")
	if len(lines) != 2 {
		return fmt.Errorf("expected 2 lines (deduplicated), got %d: %q", len(lines), result)
	}

	if lines[0] != "abc123  ghcr.io/test:v1" {
		return fmt.Errorf("line 0 = %q, want %q", lines[0], "abc123  ghcr.io/test:v1")
	}
	if lines[1] != "def456  ghcr.io/test:latest" {
		return fmt.Errorf("line 1 = %q, want %q", lines[1], "def456  ghcr.io/test:latest")
	}

	return nil
}

// TestDeduplicateDigests verifies that [Go.DeduplicateDigests] keeps
// only the first occurrence of each sha256 digest.
//
// +check
func (m *Tests) TestDeduplicateDigests(ctx context.Context) error {
	refs := []string{
		"ghcr.io/test:v1@sha256:abc123",
		"ghcr.io/test:latest@sha256:abc123",
		"ghcr.io/test:v1.0@sha256:def456",
	}

	result, err := dag.Go().DeduplicateDigests(ctx, refs)
	if err != nil {
		return fmt.Errorf("deduplicate: %w", err)
	}

	if len(result) != 2 {
		return fmt.Errorf("expected 2 unique refs, got %d: %v", len(result), result)
	}
	if result[0] != "ghcr.io/test:v1@sha256:abc123" {
		return fmt.Errorf("ref 0 = %q, want %q", result[0], "ghcr.io/test:v1@sha256:abc123")
	}
	if result[1] != "ghcr.io/test:v1.0@sha256:def456" {
		return fmt.Errorf("ref 1 = %q, want %q", result[1], "ghcr.io/test:v1.0@sha256:def456")
	}

	return nil
}

// TestRegistryHost verifies that [Go.RegistryHost] extracts the host
// (with optional port) from various registry address formats.
//
// +check
func (m *Tests) TestRegistryHost(ctx context.Context) error {
	cases := map[string]struct {
		registry string
		want     string
	}{
		"standard-registry": {
			registry: "ghcr.io/macropower/terrarium",
			want:     "ghcr.io",
		},
		"with-port": {
			registry: "localhost:5000/myimage",
			want:     "localhost:5000",
		},
		"host-only": {
			registry: "docker.io",
			want:     "docker.io",
		},
		"nested-path": {
			registry: "registry.example.com/org/team/image",
			want:     "registry.example.com",
		},
		"empty-string": {
			registry: "",
			want:     "",
		},
	}

	for name, tc := range cases {
		got, err := dag.Go().RegistryHost(ctx, tc.registry)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if got != tc.want {
			return fmt.Errorf("%s: got %q, want %q", name, got, tc.want)
		}
	}

	return nil
}

// TestReleaseSummary verifies that [ReleaseReport.Summary] returns a
// Markdown summary containing the expected sections and formatting.
//
// +check
func (m *Tests) TestReleaseSummary(ctx context.Context) error {
	report := dag.Go().NewReleaseReport(
		dag.Directory(),
		"v1.2.3",
		[]string{
			"ghcr.io/test:v1.2.3@sha256:abc123",
			"ghcr.io/test:latest@sha256:abc123",
		},
		1,
		4,
	)

	summary, err := report.Summary(ctx)
	if err != nil {
		return fmt.Errorf("summary: %w", err)
	}

	checks := map[string]string{
		"header":       "## Release Summary",
		"version":      "`v1.2.3`",
		"tag-count":    "**Tags published:** 4",
		"digest-count": "**Unique image digests:** 1",
		"table-header": "| Tag Reference | Digest |",
		"digest-row":   "ghcr.io/test:v1.2.3",
	}

	for name, want := range checks {
		if !strings.Contains(summary, want) {
			return fmt.Errorf("%s: summary missing %q:\n%s", name, want, summary)
		}
	}

	return nil
}

// TestLintDeadcodeClean verifies that the codebase has no unreachable
// functions. This exercises [Go.LintDeadcode].
//
// +check
func (m *Tests) TestLintDeadcodeClean(ctx context.Context) error {
	return dag.Go().LintDeadcode(ctx)
}

// TestLintPrettierClean verifies that [Go.LintPrettier] passes on
// already-formatted source.
//
// +check
func (m *Tests) TestLintPrettierClean(ctx context.Context) error {
	return dag.Go().LintPrettier(ctx)
}

// TestFormatIdempotent verifies that running [Go.Format] on clean source
// produces an empty changeset, confirming both golangci-lint --fix and
// prettier --write are idempotent.
//
// +check
func (m *Tests) TestFormatIdempotent(ctx context.Context) error {
	changeset := dag.Go().Format()

	empty, err := changeset.IsEmpty(ctx)
	if err != nil {
		return fmt.Errorf("check changeset: %w", err)
	}
	if !empty {
		modified, _ := changeset.ModifiedPaths(ctx)
		added, _ := changeset.AddedPaths(ctx)
		removed, _ := changeset.RemovedPaths(ctx)
		return fmt.Errorf("expected empty changeset on clean source, modified=%v added=%v removed=%v",
			modified, added, removed)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Benchmark tests
// ---------------------------------------------------------------------------

// TestBenchmarkReturnsResults verifies that [Go.Benchmark] returns
// non-empty results with expected stage names and positive durations.
//
// Not annotated with +check because benchmarks run the full pipeline
// with cache-busting, which would duplicate all CI work in the
// integration test suite. Run manually:
//
//	dagger call -m toolchains/go/tests test-benchmark-returns-results
func (m *Tests) TestBenchmarkReturnsResults(ctx context.Context) error {
	results, err := dag.Go().Benchmark(ctx)
	if err != nil {
		return fmt.Errorf("run benchmark: %w", err)
	}
	if len(results) == 0 {
		return fmt.Errorf("benchmark returned no results")
	}

	expectedStages := map[string]bool{
		"env":           false,
		"lint":          false,
		"test":          false,
		"lint-prettier": false,
	}

	for _, r := range results {
		name, err := r.Name(ctx)
		if err != nil {
			return fmt.Errorf("read result name: %w", err)
		}
		if _, ok := expectedStages[name]; ok {
			expectedStages[name] = true
		}

		dur, err := r.DurationSecs(ctx)
		if err != nil {
			return fmt.Errorf("read duration for %s: %w", name, err)
		}
		if dur < 0 {
			return fmt.Errorf("stage %s has negative duration: %f", name, dur)
		}

		ok, err := r.Ok(ctx)
		if err != nil {
			return fmt.Errorf("read ok for %s: %w", name, err)
		}
		if !ok {
			errMsg, _ := r.Error(ctx)
			return fmt.Errorf("stage %s failed: %s", name, errMsg)
		}
	}

	for stage, found := range expectedStages {
		if !found {
			return fmt.Errorf("expected stage %q not found in results", stage)
		}
	}

	return nil
}

// TestBenchmarkSummaryFormat verifies that [Go.BenchmarkSummary] returns
// a non-empty string containing the expected table header and stage names.
//
// Not annotated with +check because benchmarks run the full pipeline
// with cache-busting (see [Tests.TestBenchmarkReturnsResults]). Run manually:
//
//	dagger call -m toolchains/go/tests test-benchmark-summary-format
func (m *Tests) TestBenchmarkSummaryFormat(ctx context.Context) error {
	summary, err := dag.Go().BenchmarkSummary(ctx)
	if err != nil {
		return fmt.Errorf("run benchmark summary: %w", err)
	}
	if len(summary) == 0 {
		return fmt.Errorf("benchmark summary is empty")
	}

	if !strings.Contains(summary, "STAGE") || !strings.Contains(summary, "DURATION") {
		return fmt.Errorf("benchmark summary missing table header: %s", summary)
	}

	for _, stage := range []string{"env", "lint", "test", "lint-prettier"} {
		if !strings.Contains(summary, stage) {
			return fmt.Errorf("benchmark summary missing stage %q: %s", stage, summary)
		}
	}

	if !strings.Contains(summary, "TOTAL") {
		return fmt.Errorf("benchmark summary missing TOTAL row: %s", summary)
	}

	return nil
}

// ---------------------------------------------------------------------------
// GoReleaser tests
// ---------------------------------------------------------------------------

// TestBuildDist verifies that [Go.GoreleaserBuild] returns a dist directory
// containing expected entries (checksums and at least one platform archive).
//
// +check
func (m *Tests) TestBuildDist(ctx context.Context) error {
	entries, err := dag.Go().GoreleaserBuild("https://github.com/macropower/terrarium.git").Entries(ctx)
	if err != nil {
		return fmt.Errorf("list dist entries: %w", err)
	}

	hasChecksums := false
	hasArchive := false
	for _, entry := range entries {
		if strings.Contains(entry, "checksums") {
			hasChecksums = true
		}
		if strings.Contains(entry, "linux_amd64") || strings.Contains(entry, "linux_arm64") {
			hasArchive = true
		}
	}

	if !hasChecksums {
		return fmt.Errorf("dist missing checksums file (entries: %v)", entries)
	}
	if !hasArchive {
		return fmt.Errorf("dist missing platform archive (entries: %v)", entries)
	}
	return nil
}
