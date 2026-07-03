// CI functions specific to the terrarium repository. Most quality gates are
// Taskfile targets that call local tools (go, golangci-lint, prettier) provided
// by devbox. These functions run those same tasks inside the project's devbox
// environment via the devbox toolchain, so CI reproduces exactly what
// developers run locally: local skips the container for speed, CI keeps it for
// reproducibility.
//
// The release pipeline (build.go, publish.go) instead composes the goreleaser
// toolchain directly -- including its folded-in cosign signing and syft SBOM
// helpers -- because those tools are not on the devbox PATH. LintActions runs
// the zizmor toolchain and Security runs the security toolchain (Trivy) for the
// same reason. Renovate-config validation stays self-contained here (a pinned
// renovate-config-validator in a Node container) because it is the one check
// neither devbox nor a shared toolchain provides.
package main

import (
	"context"

	"dagger/ci/internal/dagger"
)

const (
	goreleaserVersion = "v2.16.0" // renovate: datasource=github-releases depName=goreleaser/goreleaser
	envoyVersion      = "v1.38.2" // renovate: datasource=github-releases depName=envoyproxy/envoy

	defaultRegistry = "ghcr.io/macropower/terrarium"

	terrariumCloneURL = "https://github.com/macropower/terrarium.git"

	// renovateConfig is the Renovate configuration file validated by
	// [Ci.LintRenovate], relative to the source root.
	renovateConfig = ".github/renovate.json5"

	// Docker Official Image, pulled from Docker's verified publisher
	// space on ECR Public to avoid Docker Hub pull rate limits.
	renovateImage   = "public.ecr.aws/docker/library/node:24-slim" // renovate: datasource=docker depName=public.ecr.aws/docker/library/node
	renovateVersion = "43.251.0"                                   // renovate: datasource=npm depName=renovate

	// zizmorConfig is the zizmor configuration file used by [Ci.LintActions],
	// relative to the source root.
	zizmorConfig = ".github/zizmor.yaml"

	// cacheNamespace prefixes this module's cache volumes.
	cacheNamespace = "go.jacobcolvin.com/terrarium/ci"

	// devboxHome is the home directory of the devbox image's non-root user,
	// under which the Go and golangci-lint caches are mounted.
	devboxHome = "/home/devbox"
	// devboxUser owns the mounted caches so the containerized tasks can
	// write to them.
	devboxUser = "devbox"
)

// Ci provides CI functions for the terrarium repository. Create instances with
// [New].
type Ci struct {
	// Project source directory.
	Source *dagger.Directory
	// Container image registry address (e.g. "ghcr.io/macropower/terrarium").
	Registry string
	// Directory containing only go.mod and go.sum, synced independently of
	// [Ci.Source] so that its content hash changes only when dependency files
	// change.
	GoMod *dagger.Directory // +private
	// Devbox toolchain instance the task-based checks run inside.
	Devbox *dagger.Devbox // +private
	// Goreleaser toolchain used to build, validate, and release the project,
	// including its folded-in cosign signing and syft SBOM helpers (see
	// build.go and publish.go).
	Goreleaser *dagger.Goreleaser // +private
	// Scanner is the security toolchain (Trivy) backing [Ci.Security]. Named
	// Scanner rather than Security to avoid colliding with that method.
	Scanner *dagger.Security // +private
	// Zizmor is the zizmor toolchain backing [Ci.LintActions].
	Zizmor *dagger.Zizmor // +private
}

// New creates an [Ci] module with the given project source directory.
func New(
	// Project source directory. Ignore patterns (e.g. .git, dist) belong in the
	// root dagger.json customizations, not here.
	// +defaultPath="/"
	source *dagger.Directory,
	// Go module files (go.mod and go.sum only). Synced separately from
	// source so that the go mod download layer is cached independently
	// of source code changes.
	// +defaultPath="/"
	// +ignore=["*", "!go.mod", "!go.sum"]
	goMod *dagger.Directory,
	// Container image registry address.
	// +optional
	registry string,
) *Ci {
	if registry == "" {
		registry = defaultRegistry
	}
	return &Ci{
		Source:   source,
		GoMod:    goMod,
		Registry: registry,
		Devbox: dag.Devbox(dagger.DevboxOpts{
			Source:         source,
			CacheNamespace: cacheNamespace,
		}),
		Goreleaser: dag.Goreleaser(dagger.GoreleaserOpts{
			Source:    source,
			Version:   goreleaserVersion,
			RemoteURL: terrariumCloneURL,
		}),
		Scanner: dag.Security(dagger.SecurityOpts{
			Source:         source,
			CacheNamespace: cacheNamespace + ":security",
		}),
		Zizmor: dag.Zizmor(dagger.ZizmorOpts{
			Source:     source,
			ConfigPath: zizmorConfig,
		}),
	}
}

// env returns the devbox environment container with the project source
// overlaid and the Go module, build, and golangci-lint caches mounted, ready
// to run `devbox run -- task <target>`. The caches persist across runs so the
// containerized tasks reuse work the way the local toolchain does.
func (m *Ci) env() *dagger.Container {
	owner := dagger.ContainerWithMountedCacheOpts{Owner: devboxUser}
	return m.Devbox.WithSource().
		WithMountedCache(devboxHome+"/go/pkg/mod", dag.CacheVolume(cacheNamespace+":gomod"), owner).
		WithEnvVariable("GOMODCACHE", devboxHome+"/go/pkg/mod").
		WithMountedCache(devboxHome+"/.cache/go-build", dag.CacheVolume(cacheNamespace+":gobuild"), owner).
		WithEnvVariable("GOCACHE", devboxHome+"/.cache/go-build").
		WithMountedCache(devboxHome+"/.cache/golangci-lint", dag.CacheVolume(cacheNamespace+":golangci-lint"), owner)
}

// runTask runs a Taskfile target inside the devbox environment, failing if it
// exits non-zero.
func (m *Ci) runTask(ctx context.Context, target string) error {
	_, err := m.env().
		WithExec([]string{"devbox", "run", "--", "task", target}).
		Sync(ctx)
	return err
}

// Lint runs the lint gate (golangci-lint, go mod tidy check, prettier) inside
// the devbox environment, mirroring `task lint`.
//
// +check
func (m *Ci) Lint(ctx context.Context) error {
	return m.runTask(ctx, "lint")
}

// Test runs the unit tests with the race detector inside the devbox
// environment, mirroring `task go:test`.
//
// +check
func (m *Ci) Test(ctx context.Context) error {
	return m.runTask(ctx, "go:test")
}

// TestIntegration runs the integration tests with the race detector inside the
// devbox environment, mirroring `task go:test:integration`.
//
// +check
func (m *Ci) TestIntegration(ctx context.Context) error {
	return m.runTask(ctx, "go:test:integration")
}

// TestCoverage runs all tests with coverage profiling inside the devbox
// environment (mirroring `task go:test:cover`) and returns the coverage profile
// file.
func (m *Ci) TestCoverage() *dagger.File {
	return m.env().
		WithExec([]string{"devbox", "run", "--", "task", "go:test:cover"}).
		File(".test/coverage.txt")
}

// LintReleaser validates the GoReleaser configuration. Delegates to the
// shared [Goreleaser] toolchain, which mounts the source over a minimal git
// repo (the terrarium remote URL is configured at construction) because the
// goreleaser config references a git remote for homebrew/nix repository
// resolution.
//
// +check
func (m *Ci) LintReleaser(ctx context.Context) error {
	return m.Goreleaser.Check(ctx)
}

// LintActions lints the GitHub Actions workflows for security issues by
// composing the zizmor toolchain directly. zizmor is not on the devbox PATH, so
// this gate does not run through devbox. It pins .github/zizmor.yaml as the
// config path rather than relying on zizmor's auto-discovery.
//
// +check
func (m *Ci) LintActions(ctx context.Context) error {
	return m.Zizmor.Lint(ctx)
}

// Security scans source dependencies for known vulnerabilities by composing the
// security toolchain (Trivy) directly. The scanned source is the `ci`
// toolchain's source, whose root dagger.json customization already excludes the
// build and cache directories.
//
// +check
func (m *Ci) Security(ctx context.Context) error {
	return m.Scanner.ScanSource(ctx)
}

// SecuritySourceSarif scans source dependencies for known vulnerabilities and
// returns the results as a SARIF file for upload to GitHub Code Scanning. Unlike
// [Ci.Security], it does not gate on findings: SARIF capture must produce the
// file even when vulnerabilities are present, so they can be published to the
// Security tab. It scans the same source as the gate.
func (m *Ci) SecuritySourceSarif() *dagger.File {
	return m.Scanner.ScanSourceSarif()
}

// LintRenovate validates the Renovate configuration with
// renovate-config-validator, installed at a pinned version in a Node container
// so the check is self-contained and Renovate can bump its own validator
// version. It is the one check that composes neither devbox nor a shared
// toolchain.
//
// +check
func (m *Ci) LintRenovate(ctx context.Context) error {
	_, err := dag.Container().
		From(renovateImage).
		WithMountedCache("/root/.npm", dag.CacheVolume(cacheNamespace+":npm")).
		WithExec([]string{"npm", "install", "-g", "renovate@" + renovateVersion}).
		WithMountedFile("/src/"+renovateConfig, m.Source.File(renovateConfig)).
		WithWorkdir("/src").
		WithExec([]string{"renovate-config-validator", renovateConfig}).
		Sync(ctx)
	return err
}

// Binary compiles the terrarium binary for the given platform.
func (m *Ci) Binary(
	// Target build platform.
	// +optional
	platform dagger.Platform,
) *dagger.File {
	return m.goBinary("terrarium", platform)
}

// TestRunner compiles the testrunner binary for the given platform.
// Used by e2e tests to run assertions inside terrarium containers.
func (m *Ci) TestRunner(
	// Target build platform.
	// +optional
	platform dagger.Platform,
) *dagger.File {
	return m.goBinary("testrunner", platform)
}

// goBinary cross-compiles ./cmd/<name> for the given platform on the goreleaser
// toolchain's Go build base. Terrarium is CGO-free, so CGO_ENABLED=0 produces a
// static binary. The go module and build caches are keyed on this module's
// cache namespace and persist across runs. GoMod is mounted before source so
// the module download layer caches independently of source changes.
func (m *Ci) goBinary(name string, platform dagger.Platform) *dagger.File {
	ctr := m.Goreleaser.GoreleaserBase().
		WithMountedCache("/go/pkg/mod", dag.CacheVolume(cacheNamespace+":gomod")).
		WithEnvVariable("GOMODCACHE", "/go/pkg/mod").
		WithMountedCache("/root/.cache/go-build", dag.CacheVolume(cacheNamespace+":gobuild")).
		WithEnvVariable("GOCACHE", "/root/.cache/go-build").
		WithWorkdir("/src").
		WithMountedDirectory("/src", m.GoMod).
		WithExec([]string{"go", "mod", "download"}).
		WithMountedDirectory("/src", m.Source).
		WithEnvVariable("CGO_ENABLED", "0")

	if platform != "" {
		goos, goarch := splitPlatform(string(platform))
		ctr = ctr.
			WithEnvVariable("GOOS", goos).
			WithEnvVariable("GOARCH", goarch)
	}

	return ctr.
		WithExec([]string{
			"go", "build", "-trimpath", "-ldflags", "-s -w",
			"-o", "/out/" + name, "./cmd/" + name,
		}).
		File("/out/" + name)
}

// splitPlatform splits a "goos/goarch[/variant]" platform string into its goos
// and goarch components, dropping any variant suffix.
func splitPlatform(platform string) (goos, goarch string) {
	for i := 0; i < len(platform); i++ {
		if platform[i] == '/' {
			goos = platform[:i]
			rest := platform[i+1:]
			goarch = rest
			for j := 0; j < len(rest); j++ {
				if rest[j] == '/' {
					goarch = rest[:j]
					break
				}
			}
			return goos, goarch
		}
	}
	return platform, ""
}
