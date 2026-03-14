package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"dagger/terrarium/internal/dagger"
)

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
// dist directory. If no dist is provided, a snapshot build is run.
func (m *Terrarium) BuildImages(
	ctx context.Context,
	// Version label for OCI metadata.
	// +default="snapshot"
	version string,
	// Pre-built GoReleaser dist directory. If not provided, runs a snapshot build.
	// +optional
	dist *dagger.Directory,
) ([]*dagger.Container, error) {
	if dist == nil {
		var err error
		dist, err = m.Build(ctx)
		if err != nil {
			return nil, err
		}
	}
	return runtimeImages(ctx, dist, version)
}

// runtimeImages builds a multi-arch set of runtime container images from a
// pre-built GoReleaser dist/ directory. Each image is based on debian:13-slim
// with OCI labels.
func runtimeImages(_ context.Context, dist *dagger.Directory, version string) ([]*dagger.Container, error) {
	platforms := []dagger.Platform{"linux/amd64", "linux/arm64"}
	variants := make([]*dagger.Container, len(platforms))
	created := time.Now().UTC().Format(time.RFC3339)

	for i, platform := range platforms {
		// Map platform to GoReleaser dist binary path.
		dir := "terrarium_linux_amd64_v1"
		if platform == "linux/arm64" {
			dir = "terrarium_linux_arm64_v8.0"
		}

		variants[i] = runtimeBase(platform).
			// OCI labels (container config) for metadata.
			WithLabel("org.opencontainers.image.version", version).
			WithLabel("org.opencontainers.image.created", created).
			// OCI annotations (manifest-level) for registry discoverability.
			WithAnnotation("org.opencontainers.image.version", version).
			WithAnnotation("org.opencontainers.image.created", created).
			WithFile("/usr/local/bin/terrarium", dist.File(dir+"/terrarium")).
			WithEntrypoint([]string{"terrarium"})
	}

	return variants, nil
}

// runtimeBase returns a debian:13-slim container for the given platform with
// OCI labels and TLS certificates pre-configured.
func runtimeBase(platform dagger.Platform) *dagger.Container {
	return dag.Container(dagger.ContainerOpts{Platform: platform}).
		From("debian:13-slim").
		// Static OCI labels (container config) for metadata.
		WithLabel("org.opencontainers.image.title", "terrarium").
		WithLabel("org.opencontainers.image.description", "Secure container environment with Envoy egress gateway").
		WithLabel("org.opencontainers.image.source", "https://github.com/macropower/terrarium").
		WithLabel("org.opencontainers.image.url", "https://github.com/macropower/terrarium").
		WithLabel("org.opencontainers.image.licenses", "Apache-2.0").
		// Static OCI annotations (manifest-level) for registry discoverability.
		WithAnnotation("org.opencontainers.image.title", "terrarium").
		WithAnnotation("org.opencontainers.image.source", "https://github.com/macropower/terrarium").
		// Install ca-certificates for TLS trust.
		WithExec([]string{"sh", "-c",
			"apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*"})
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
		// Env vars used by GoReleaser ldflags and templates.
		WithEnvVariable("HOSTNAME", "dagger").
		WithEnvVariable("USER", "dagger").
		// Mount source after all tools so that source changes only invalidate
		// layers from here onward, preserving the tool installation layers above.
		WithMountedDirectory("/src", m.Source)
	ctr = ensureGitRepo(ctr, terrariumCloneURL)
	return ctr, nil
}
