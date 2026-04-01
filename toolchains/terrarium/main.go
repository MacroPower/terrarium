// CI/CD functions specific to the terrarium project. Provides building,
// releasing, benchmarking, and container image publishing. Generic Go CI
// functions (testing, linting, formatting, prettier, GoReleaser,
// publishing, signing) are provided by the [Go] toolchain module; this
// module adds terrarium-specific logic.

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"dagger/terrarium/internal/dagger"
)

const (
	envoyVersion = "v1.37.1" // renovate: datasource=github-releases depName=envoyproxy/envoy

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

// Variant identifies a container image variant. Each variant uses a different
// base image and set of pre-installed dependencies. See [VariantScratch] and
// [VariantDebian] for the available variants.
type Variant string

const (
	// VariantScratch builds an empty container with only the terrarium
	// binary. This is the default variant and produces the smallest image.
	VariantScratch Variant = "scratch"

	// VariantDebian builds a debian:13-slim container with ca-certificates
	// and the Envoy proxy pre-installed.
	VariantDebian Variant = "debian"
)

// allVariants lists every supported image variant in publishing order.
var allVariants = []Variant{VariantScratch, VariantDebian}

// BuildImages builds multi-arch runtime container images from a GoReleaser
// dist directory. If no dist is provided, a snapshot build is run. When
// variant is empty, all variants are built and returned as a flat slice.
func (m *Terrarium) BuildImages(
	ctx context.Context,
	// Version label for OCI metadata.
	// +default="snapshot"
	version string,
	// Pre-built GoReleaser dist directory. If not provided, runs a snapshot build.
	// +optional
	dist *dagger.Directory,
	// Image variant to build. One of "scratch", "debian".
	// When empty, all variants are built.
	// +optional
	variant string,
) ([]*dagger.Container, error) {
	if dist == nil {
		var err error
		dist, err = m.Go.GoreleaserBuild(terrariumCloneURL).Sync(ctx)
		if err != nil {
			return nil, err
		}
	}

	if variant != "" {
		created := time.Now().UTC().Format(time.RFC3339)
		return buildVariantImages(m.Go, dist, version, Variant(variant), created)
	}

	sets, err := buildAllVariantSets(m.Go, dist, version)
	if err != nil {
		return nil, err
	}

	var all []*dagger.Container
	for _, s := range sets {
		ctrs, err := s.Containers(ctx)
		if err != nil {
			return nil, err
		}
		for _, c := range ctrs {
			all = append(all, &c)
		}
	}
	return all, nil
}

// buildAllVariantSets builds multi-arch containers for every supported
// variant, returning variant sets grouped by variant for direct use with
// [Terrarium.Release] and [Terrarium.PublishImages].
func buildAllVariantSets(g *dagger.Go, dist *dagger.Directory, version string) ([]*dagger.GoVariantSet, error) {
	sets := make([]*dagger.GoVariantSet, len(allVariants))
	created := time.Now().UTC().Format(time.RFC3339)

	for i, v := range allVariants {
		ctrs, err := buildVariantImages(g, dist, version, v, created)
		if err != nil {
			return nil, fmt.Errorf("building %s images: %w", v, err)
		}
		sets[i] = g.NewVariantSet(string(v), ctrs)
	}

	return sets, nil
}

// buildVariantImages constructs multi-arch containers for a single variant,
// sharing the created timestamp across all platforms for consistency.
func buildVariantImages(g *dagger.Go, dist *dagger.Directory, version string, variant Variant, created string) ([]*dagger.Container, error) {
	platforms := []dagger.Platform{"linux/amd64", "linux/arm64"}
	containers := make([]*dagger.Container, len(platforms))

	for i, platform := range platforms {
		containers[i] = runtimeBase(platform, variant).
			WithLabel("org.opencontainers.image.version", version).
			WithLabel("org.opencontainers.image.created", created).
			WithAnnotation("org.opencontainers.image.version", version).
			WithAnnotation("org.opencontainers.image.created", created).
			WithFile("/usr/local/bin/terrarium", g.GoreleaserDistBinary(dist, "terrarium", platform)).
			WithEntrypoint([]string{"terrarium"})
	}

	return containers, nil
}

// runtimeBase returns a base container for the given platform and variant
// with OCI labels pre-configured. Dispatches to variant-specific helpers
// for base image and dependency installation.
func runtimeBase(platform dagger.Platform, variant Variant) *dagger.Container {
	var ctr *dagger.Container

	switch variant {
	case VariantDebian:
		ctr = runtimeBaseDebian(platform)
	default:
		ctr = runtimeBaseScratch(platform)
	}

	return withOCILabels(ctr)
}

// runtimeBaseScratch returns an empty container for the given platform.
// The resulting image contains only the terrarium binary added by the caller.
func runtimeBaseScratch(platform dagger.Platform) *dagger.Container {
	return dag.Container(dagger.ContainerOpts{Platform: platform})
}

// runtimeBaseDebian returns a debian:13-slim container with ca-certificates
// and the Envoy proxy binary pre-installed.
func runtimeBaseDebian(platform dagger.Platform) *dagger.Container {
	return dag.Container(dagger.ContainerOpts{Platform: platform}).
		From("debian:13-slim").
		WithExec([]string{"sh", "-c",
			"apt-get update && apt-get install -y ca-certificates curl && rm -rf /var/lib/apt/lists/*"}).
		WithExec([]string{"sh", "-c",
			"useradd -u 1000 -m -s /bin/sh dev && " +
				"useradd -u 1001 -M -s /usr/sbin/nologin envoy"}).
		WithFile("/usr/local/bin/envoy", envoyBinary(platform))
}

// envoyBinary extracts the Envoy proxy binary from the official multi-arch
// container image for the given platform.
func envoyBinary(platform dagger.Platform) *dagger.File {
	return dag.Container(dagger.ContainerOpts{Platform: platform}).
		From("envoyproxy/envoy:" + envoyVersion).
		File("/usr/local/bin/envoy")
}

// withOCILabels applies the static OCI labels and annotations shared by all
// image variants.
func withOCILabels(ctr *dagger.Container) *dagger.Container {
	return ctr.
		WithLabel("org.opencontainers.image.title", "terrarium").
		WithLabel("org.opencontainers.image.description", "Secure container environment with Envoy egress gateway").
		WithLabel("org.opencontainers.image.source", "https://github.com/macropower/terrarium").
		WithLabel("org.opencontainers.image.url", "https://github.com/macropower/terrarium").
		WithLabel("org.opencontainers.image.licenses", "Apache-2.0").
		WithAnnotation("org.opencontainers.image.title", "terrarium").
		WithAnnotation("org.opencontainers.image.source", "https://github.com/macropower/terrarium")
}

// ReleaseDryRun validates the full release pipeline without publishing.
// Builds snapshot binaries via GoReleaser, verifies each binary's architecture
// matches its target platform, and constructs multi-arch container images,
// catching cross-compilation failures, missing tool binaries, and image build
// errors that would surface only during a real release.
//
// For a fast GoReleaser config-only check, use the Go module's
// GoreleaserCheck function instead.
func (m *Terrarium) ReleaseDryRun(ctx context.Context) error {
	dist, err := m.Go.GoreleaserBuild(terrariumCloneURL).Sync(ctx)
	if err != nil {
		return err
	}

	binaries := []*dagger.GoPlatformBinary{
		m.Go.NewPlatformBinary("linux/amd64", m.Go.GoreleaserDistBinary(dist, "terrarium", "linux/amd64")),
		m.Go.NewPlatformBinary("linux/arm64", m.Go.GoreleaserDistBinary(dist, "terrarium", "linux/arm64")),
	}

	containers, err := m.BuildImages(ctx, "dry-run", dist, "")
	if err != nil {
		return err
	}

	return m.Go.ReleaseDryRun(ctx, binaries, dagger.GoReleaseDryRunOpts{
		Containers: containers,
	})
}

// ReleaseReport captures the results of a release operation including
// image digests, artifact checksums, and a human-readable summary.
// Create instances with [Terrarium.Release].
//
// Wraps [Go.ReleaseReport] to satisfy Dagger's requirement that exported
// return types belong to the declaring module.
type ReleaseReport struct {
	// Underlying report from the Go module.
	Report *dagger.GoReleaseReport // +private
	// Dist directory containing release artifacts.
	Dist *dagger.Directory
	// Tag is the version tag that was released (e.g. "v1.2.3").
	Tag string
}

// Summary returns a Markdown summary of the release suitable for
// $GITHUB_STEP_SUMMARY. Delegates to [Go.ReleaseReport.Summary].
func (r *ReleaseReport) Summary(ctx context.Context) (string, error) {
	return r.Report.Summary(ctx)
}

// ImageDigests returns the published image digest references.
// Delegates to [Go.ReleaseReport.ImageDigests].
func (r *ReleaseReport) ImageDigests(ctx context.Context) ([]string, error) {
	return r.Report.ImageDigests(ctx)
}

// UniqueDigestCount returns the number of unique image digests.
// Delegates to [Go.ReleaseReport.UniqueDigestCount].
func (r *ReleaseReport) UniqueDigestCount(ctx context.Context) (int, error) {
	return r.Report.UniqueDigestCount(ctx)
}

// TagCount returns the number of tags published.
// Delegates to [Go.ReleaseReport.TagCount].
func (r *ReleaseReport) TagCount(ctx context.Context) (int, error) {
	return r.Report.TagCount(ctx)
}

// PublishImages builds multi-arch container images for all variants
// (scratch, debian) and publishes them to the registry. Each variant
// gets its own set of tags via [Go.VariantTag].
//
// Stable releases are published with multiple tags per variant. For
// scratch (default): :latest, :vX.Y.Z, :vX, :vX.Y. For debian the
// variant name is appended: :debian, :vX.Y.Z-debian, etc.
// Pre-release versions are published with only their exact tag per variant.
//
// +cache="never"
func (m *Terrarium) PublishImages(
	ctx context.Context,
	// Base image tags to publish (e.g. ["latest", "v1.2.3", "v1", "v1.2"]).
	// Variant suffixes are applied automatically.
	tags []string,
	// Registry username for authentication.
	// +optional
	registryUsername string,
	// Registry password or token for authentication.
	// +optional
	registryPassword *dagger.Secret,
	// OIDC token request URL for keyless Sigstore signing. In GitHub Actions
	// this is the ACTIONS_ID_TOKEN_REQUEST_URL environment variable. When
	// provided along with oidcRequestToken, published images are signed
	// using Sigstore keyless verification (Fulcio + Rekor).
	// +optional
	oidcRequestURL string,
	// Bearer token for the OIDC token request. In GitHub Actions this is the
	// ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable.
	// +optional
	oidcRequestToken *dagger.Secret,
	// Pre-built GoReleaser dist directory. If not provided, runs a snapshot build.
	// +optional
	dist *dagger.Directory,
) (string, error) {
	// Use the first non-"latest" tag as the version label, or fall back to "snapshot".
	version := "snapshot"
	for _, t := range tags {
		if t != "latest" {
			version = t
			break
		}
	}

	if dist == nil {
		var err error
		dist, err = m.Go.GoreleaserBuild(terrariumCloneURL).Sync(ctx)
		if err != nil {
			return "", err
		}
	}

	sets, err := buildAllVariantSets(m.Go, dist, version)
	if err != nil {
		return "", err
	}

	allDigests, err := m.Go.PublishAndSign(ctx, sets, tags, m.Registry, string(VariantScratch), dagger.GoPublishAndSignOpts{
		RegistryUsername:  registryUsername,
		RegistryPassword: registryPassword,
		OidcRequestURL:   oidcRequestURL,
		OidcRequestToken: oidcRequestToken,
	})
	if err != nil {
		return "", err
	}

	unique, err := m.Go.DeduplicateDigests(ctx, allDigests)
	if err != nil {
		return "", fmt.Errorf("deduplicate digests: %w", err)
	}
	return fmt.Sprintf("published %d tags (%d unique digests)\n%s",
		len(tags)*len(sets), len(unique), strings.Join(allDigests, "\n")), nil
}

// Release runs GoReleaser for binaries/archives/signing, then builds and
// publishes container images using Dagger-native Container.Publish().
// GoReleaser's Docker support is skipped entirely to avoid Docker-in-Docker.
//
// Both binary archives and container images are signed using Sigstore keyless
// verification when OIDC request credentials are provided. Cosign's built-in
// GitHub Actions provider fetches fresh tokens on demand, avoiding expiry
// issues with pre-fetched tokens.
//
// Returns a [ReleaseReport] containing the dist/ directory (with
// checksums.txt and digests.txt for attestation), published image digests,
// and a Markdown summary suitable for $GITHUB_STEP_SUMMARY.
//
// +cache="never"
func (m *Terrarium) Release(
	ctx context.Context,
	// GitHub token for creating the release.
	githubToken *dagger.Secret,
	// Registry username for container image authentication.
	registryUsername string,
	// Registry password or token for container image authentication.
	registryPassword *dagger.Secret,
	// Version tag to release (e.g. "v1.2.3").
	tag string,
	// OIDC token request URL for keyless Sigstore signing. In GitHub Actions
	// this is the ACTIONS_ID_TOKEN_REQUEST_URL environment variable.
	// +optional
	oidcRequestURL string,
	// Bearer token for the OIDC token request. In GitHub Actions this is the
	// ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable.
	// +optional
	oidcRequestToken *dagger.Secret,
) (*ReleaseReport, error) {
	dist := m.Go.GoreleaserRelease(terrariumCloneURL, githubToken, dagger.GoGoreleaserReleaseOpts{
		OidcRequestURL:   oidcRequestURL,
		OidcRequestToken: oidcRequestToken,
	})

	sets, err := buildAllVariantSets(m.Go, dist, tag)
	if err != nil {
		return nil, fmt.Errorf("build runtime images: %w", err)
	}

	report := m.Go.Release(sets, tag, dist, m.Registry, string(VariantScratch), dagger.GoReleaseOpts{
		RegistryUsername:  registryUsername,
		RegistryPassword: registryPassword,
		OidcRequestURL:   oidcRequestURL,
		OidcRequestToken: oidcRequestToken,
	})

	return &ReleaseReport{
		Report: report,
		Dist:   report.Dist(),
		Tag:    tag,
	}, nil
}
