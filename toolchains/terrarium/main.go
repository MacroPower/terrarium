// CI/CD functions specific to the terrarium project. Provides building,
// releasing, linting non-Go files, benchmarking, and container image
// publishing. Generic Go CI functions (testing, Go linting, Go formatting) are
// provided by the [Go] toolchain module; this module adds terrarium-specific
// logic and project-level tooling (prettier, zizmor, goreleaser, cosign,
// syft, deadcode).

package main

import (
	"dagger/terrarium/internal/dagger"
)

const (
	goreleaserVersion = "v2.13.3" // renovate: datasource=github-releases depName=goreleaser/goreleaser
	envoyVersion      = "v1.38.2" // renovate: datasource=github-releases depName=envoyproxy/envoy

	terrariumCacheNamespace = "go.jacobcolvin.com/terrarium/toolchains/terrarium"

	defaultRegistry = "ghcr.io/macropower/terrarium"

	terrariumCloneURL = "https://github.com/macropower/terrarium.git"
)

// Terrarium provides CI/CD functions for terrarium. Create instances with [New].
type Terrarium struct {
	// Project source directory.
	Source *dagger.Directory
	// Container image registry address (e.g. "ghcr.io/macropower/terrarium").
	Registry string
	// Directory containing only go.mod and go.sum, synced independently of
	// [Terrarium.Source] so that its content hash changes only when dependency
	// files change.
	GoMod *dagger.Directory // +private
	// Go toolchain module instance for delegation.
	Go *dagger.Go // +private
	// GoReleaser toolchain module instance for config validation.
	Goreleaser *dagger.Goreleaser // +private
	// Zizmor toolchain module instance for GitHub Actions linting.
	Zizmor *dagger.Zizmor // +private
	// Cosign toolchain module instance for container image signing.
	Cosign *dagger.Cosign // +private
	// Prettier toolchain module instance for non-Go formatting and linting.
	Prettier *dagger.Prettier // +private
	// Syft toolchain module instance for SBOM generation during releases.
	Syft *dagger.Syft // +private
}

// New creates a [Terrarium] module with the given project source directory.
func New(
	// Project source directory.
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
) *Terrarium {
	if registry == "" {
		registry = defaultRegistry
	}
	goToolchain := dag.Go(dagger.GoOpts{
		Source:         source,
		GoMod:          goMod,
		Cgo:            false,
		CacheNamespace: "go.jacobcolvin.com/terrarium/toolchains/go",
	})
	return &Terrarium{
		Source:   source,
		GoMod:    goMod,
		Registry: registry,
		Go:       goToolchain,
		Goreleaser: dag.Goreleaser(dagger.GoreleaserOpts{
			Source:    source,
			Base:      goToolchain.Base(),
			Version:   goreleaserVersion,
			RemoteURL: terrariumCloneURL,
		}),
		Zizmor: dag.Zizmor(dagger.ZizmorOpts{Source: source}),
		Cosign: dag.Cosign(),
		Prettier: dag.Prettier(dagger.PrettierOpts{
			Source:         source,
			CacheNamespace: terrariumCacheNamespace,
		}),
		Syft: dag.Syft(),
	}
}

// Binary compiles the terrarium binary for the given platform.
func (m *Terrarium) Binary(
	// Target build platform.
	// +optional
	platform dagger.Platform,
) *dagger.File {
	return m.Go.Binary("./cmd/terrarium", dagger.GoBinaryOpts{
		NoSymbols: true,
		NoDwarf:   true,
		Platform:  platform,
	})
}

// TestRunner compiles the testrunner binary for the given platform.
// Used by e2e tests to run assertions inside terrarium containers.
func (m *Terrarium) TestRunner(
	// Target build platform.
	// +optional
	platform dagger.Platform,
) *dagger.File {
	return m.Go.Binary("./cmd/testrunner", dagger.GoBinaryOpts{
		NoSymbols: true,
		NoDwarf:   true,
		Platform:  platform,
	})
}
