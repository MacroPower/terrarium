package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"dagger/terrarium/internal/dagger"
)

// Variant identifies a container image variant. Each variant uses a different
// base image and set of pre-installed dependencies. See [VariantScratch],
// [VariantDebian], and [VariantAlpine] for the available variants.
type Variant string

const (
	// VariantScratch builds an empty container with only the terrarium
	// binary. This is the default variant and produces the smallest image.
	VariantScratch Variant = "scratch"

	// VariantDebian builds a debian:13-slim container with ca-certificates
	// and the Envoy proxy pre-installed.
	VariantDebian Variant = "debian"

	// VariantAlpine builds an alpine container with ca-certificates and
	// the Envoy proxy pre-installed.
	VariantAlpine Variant = "alpine"
)

// allVariants lists every supported image variant in publishing order.
var allVariants = []Variant{VariantScratch, VariantDebian, VariantAlpine}

// variantSet groups multi-arch platform containers for a single image
// variant. Used internally by [buildAllImages] to keep variant metadata
// associated with its containers through the publish pipeline.
type variantSet struct {
	variant    Variant
	containers []*dagger.Container
}

// Build runs GoReleaser in snapshot mode, producing binaries for all
// platforms. Returns the dist/ directory. Source archives are skipped in
// snapshot mode since they are only needed for releases.
func (m *Terrarium) Build(ctx context.Context) (*dagger.Directory, error) {
	ctr, err := m.releaserBase(ctx)
	if err != nil {
		return nil, err
	}
	return ctr.
		WithExec([]string{
			"goreleaser", "release", "--snapshot", "--clean",
			"--skip=docker,homebrew,nix,sign,sbom",
			"--parallelism=0",
		}).
		Directory("/src/dist"), nil
}

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
	// Image variant to build. One of "scratch", "debian", "alpine".
	// When empty, all variants are built.
	// +optional
	variant string,
) ([]*dagger.Container, error) {
	if dist == nil {
		var err error
		dist, err = m.Build(ctx)
		if err != nil {
			return nil, err
		}
	}

	if variant != "" {
		return runtimeImages(ctx, dist, version, Variant(variant))
	}

	sets, err := buildAllImages(ctx, dist, version)
	if err != nil {
		return nil, err
	}

	var all []*dagger.Container
	for _, s := range sets {
		all = append(all, s.containers...)
	}
	return all, nil
}

// buildAllImages builds multi-arch containers for every supported variant,
// returning them grouped so callers can apply variant-specific tags.
func buildAllImages(_ context.Context, dist *dagger.Directory, version string) ([]variantSet, error) {
	sets := make([]variantSet, len(allVariants))
	created := time.Now().UTC().Format(time.RFC3339)

	for i, v := range allVariants {
		ctrs, err := buildVariantImages(dist, version, v, created)
		if err != nil {
			return nil, fmt.Errorf("building %s images: %w", v, err)
		}
		sets[i] = variantSet{variant: v, containers: ctrs}
	}

	return sets, nil
}

// runtimeImages builds a multi-arch set of runtime container images for a
// single variant from a pre-built GoReleaser dist/ directory.
func runtimeImages(_ context.Context, dist *dagger.Directory, version string, variant Variant) ([]*dagger.Container, error) {
	created := time.Now().UTC().Format(time.RFC3339)
	return buildVariantImages(dist, version, variant, created)
}

// buildVariantImages constructs multi-arch containers for a single variant,
// sharing the created timestamp across all platforms for consistency.
func buildVariantImages(dist *dagger.Directory, version string, variant Variant, created string) ([]*dagger.Container, error) {
	platforms := []dagger.Platform{"linux/amd64", "linux/arm64"}
	containers := make([]*dagger.Container, len(platforms))

	for i, platform := range platforms {
		// Map platform to GoReleaser dist binary path.
		dir := "terrarium_linux_amd64_v1"
		if platform == "linux/arm64" {
			dir = "terrarium_linux_arm64_v8.0"
		}

		containers[i] = runtimeBase(platform, variant).
			WithLabel("org.opencontainers.image.version", version).
			WithLabel("org.opencontainers.image.created", created).
			WithAnnotation("org.opencontainers.image.version", version).
			WithAnnotation("org.opencontainers.image.created", created).
			WithFile("/usr/local/bin/terrarium", dist.File(dir+"/terrarium")).
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
	case VariantAlpine:
		ctr = runtimeBaseAlpine(platform)
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

// runtimeBaseAlpine returns an alpine container with ca-certificates
// and the Envoy proxy binary pre-installed.
func runtimeBaseAlpine(platform dagger.Platform) *dagger.Container {
	return dag.Container(dagger.ContainerOpts{Platform: platform}).
		From("alpine:3.22").
		WithExec([]string{"apk", "add", "--no-cache", "ca-certificates", "curl"}).
		WithExec([]string{"sh", "-c",
			"adduser -u 1000 -D -s /bin/sh dev && " +
				"adduser -u 1001 -H -D -s /sbin/nologin envoy"}).
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

// verifyBinaryPlatform runs the `file` command on a built binary and asserts
// that the reported architecture matches the expected architecture for the
// given platform. Returns an error if the architecture string is absent from
// the output, indicating a cross-compilation mismatch.
func verifyBinaryPlatform(ctx context.Context, bin *dagger.File, platform dagger.Platform) error {
	name, err := bin.Name(ctx)
	if err != nil {
		return fmt.Errorf("get binary name: %w", err)
	}

	arch := filepath.Base(strings.SplitN(string(platform), "/", 2)[1])
	expected, ok := platformToFileArch[arch]
	if !ok {
		return fmt.Errorf("unknown platform architecture %q", arch)
	}

	mntPath := filepath.Join("/mnt", name)
	out, err := dag.Container().
		From("debian:13-slim").
		WithExec([]string{"sh", "-c", "apt-get update -qq && apt-get install -y -qq file"}).
		WithMountedFile(mntPath, bin).
		WithExec([]string{"file", mntPath}).
		Stdout(ctx)
	if err != nil {
		return fmt.Errorf("run file on binary %s: %w", name, err)
	}

	if !strings.Contains(out, expected) {
		return fmt.Errorf("binary %s: expected architecture %q (%s) not found in file output: %s", name, expected, arch, out)
	}

	return nil
}

// platformToFileArch maps a Go platform architecture name to the architecture
// string produced by the `file` command.
var platformToFileArch = map[string]string{
	"amd64": "x86-64",
	"arm64": "aarch64",
}

// goreleaserBase returns a container with Go, GoReleaser, and module caches.
// This is the common base shared by [Terrarium.releaserBase] and
// [Terrarium.goreleaserCheckBase]. Callers are responsible for mounting
// project source and initializing a git repo with their appropriate remote
// URL before use.
//
// The container is built on top of [Go.Base], reusing the pre-built Go image
// with module cache and go mod download already completed.
func (m *Terrarium) goreleaserBase(_ context.Context) (*dagger.Container, error) {
	return m.Go.Base().
		WithFile("/usr/local/bin/goreleaser",
			dag.Container().From("ghcr.io/goreleaser/goreleaser:"+goreleaserVersion).
				File("/usr/bin/goreleaser")), nil
}

// releaserBase extends [Terrarium.goreleaserBase] with cosign, syft, and
// project source mounted. Provides the release toolset for goreleaser release
// with signing and SBOM support.
func (m *Terrarium) releaserBase(ctx context.Context) (*dagger.Container, error) {
	ctr, err := m.goreleaserBase(ctx)
	if err != nil {
		return nil, err
	}
	ctr = ctr.
		WithFile("/usr/local/bin/cosign",
			dag.Container().From("gcr.io/projectsigstore/cosign:"+cosignVersion).
				File("/ko-app/cosign")).
		WithFile("/usr/local/bin/syft",
			dag.Container().From("ghcr.io/anchore/syft:"+syftVersion).
				File("/syft")).
		WithNewFile("/usr/local/bin/nix-hash", `#!/bin/sh
# nix-hash shim -- supports: nix-hash --type sha256 --flat --sri <file>
file=""
for arg in "$@"; do
  case "$arg" in --*) ;; *) file="$arg" ;; esac
done
printf 'sha256-%s\n' "$(openssl dgst -sha256 -binary "$file" | base64 -w0)"
`,
			dagger.ContainerWithNewFileOpts{Permissions: 0o755}).
		// Env vars used by GoReleaser ldflags and templates.
		WithEnvVariable("HOSTNAME", "dagger").
		WithEnvVariable("USER", "dagger").
		// Mount source after all tools so that source changes only invalidate
		// layers from here onward, preserving the tool installation layers above.
		WithMountedDirectory("/src", m.Source)
	ctr = ensureGitRepo(ctr, terrariumCloneURL)
	return ctr, nil
}
