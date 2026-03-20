// CI/CD functions specific to the terrarium project. Provides building,
// releasing, linting non-Go files, benchmarking, and container image
// publishing. Generic Go CI functions (testing, Go linting, Go formatting) are
// provided by the [Go] toolchain module; this module adds terrarium-specific
// logic and project-level tooling (prettier, zizmor, goreleaser, cosign,
// syft, deadcode).

package main

import (
	"context"

	"dagger/terrarium/internal/dagger"
)

const (
	goreleaserVersion = "v2.13.3"  // renovate: datasource=github-releases depName=goreleaser/goreleaser
	prettierVersion   = "3.5.3"    // renovate: datasource=npm depName=prettier
	zizmorVersion     = "1.22.0"   // renovate: datasource=github-releases depName=zizmorcore/zizmor
	deadcodeVersion   = "v0.42.0"  // renovate: datasource=go depName=golang.org/x/tools
	cosignVersion     = "v3.0.4"   // renovate: datasource=github-releases depName=sigstore/cosign
	syftVersion       = "v1.41.1"  // renovate: datasource=github-releases depName=anchore/syft
	envoyVersion      = "v1.37.1"  // renovate: datasource=github-releases depName=envoyproxy/envoy

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
	return &Terrarium{
		Source:   source,
		GoMod:    goMod,
		Registry: registry,
		Go: dag.Go(dagger.GoOpts{
			Source: source,
			GoMod:  goMod,
			Cgo:    false,
		}),
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

// ---------------------------------------------------------------------------
// Base containers (private)
// ---------------------------------------------------------------------------

// prettierBase returns a Node container with prettier pre-installed.
// Callers must mount their source directory and set the workdir.
func (m *Terrarium) prettierBase() *dagger.Container {
	return dag.Container().
		From("node:lts-slim").
		WithMountedCache("/root/.npm", dag.CacheVolume(terrariumCacheNamespace+":npm")).
		WithExec([]string{"npm", "install", "-g", "prettier@" + prettierVersion})
}

// goreleaserCheckBase extends [Terrarium.goreleaserBase] with a minimal git
// repo for the given remoteURL. This is sufficient for goreleaser check,
// which only validates config syntax and does not require the full release
// toolset provided by [Terrarium.releaserBase].
func (m *Terrarium) goreleaserCheckBase(ctx context.Context, remoteURL string) (*dagger.Container, error) {
	ctr, err := m.goreleaserBase(ctx)
	if err != nil {
		return nil, err
	}
	ctr = ctr.WithMountedDirectory("/src", m.Source)
	return ensureGitRepo(ctr, remoteURL), nil
}

// ensureGitRepo initializes a git repository in the container's workdir if
// one does not already exist, and configures the given remote URL. This is
// needed by GoReleaser which inspects git state for changelog generation
// and homebrew/nix repository resolution.
func ensureGitRepo(ctr *dagger.Container, remoteURL string) *dagger.Container {
	return ctr.
		WithExec([]string{"sh", "-c",
			"git init -q /src 2>/dev/null || true && " +
				"cd /src && " +
				"git config user.email 'ci@dagger.io' && " +
				"git config user.name 'Dagger CI' && " +
				"(git remote get-url origin 2>/dev/null || git remote add origin " + remoteURL + ") && " +
				"git add -A && git diff-index --quiet HEAD -- 2>/dev/null || git commit -q --allow-empty -m 'init'"})
}

// defaultPrettierPatterns returns the default file patterns for prettier
// formatting and linting.
func defaultPrettierPatterns() []string {
	return []string{
		"*.yaml", "*.md", "*.json",
		"**/*.yaml", "**/*.md", "**/*.json",
	}
}
