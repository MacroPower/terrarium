package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"dagger/go/internal/dagger"
)

const (
	defaultGoreleaserVersion = "v2.13.3" // renovate: datasource=github-releases depName=goreleaser/goreleaser
	defaultCosignVersion     = "v3.0.4"  // renovate: datasource=github-releases depName=sigstore/cosign
	defaultSyftVersion       = "v1.41.1" // renovate: datasource=github-releases depName=anchore/syft
)

// GoreleaserBase returns a container with Go, GoReleaser, and module caches.
// Source is mounted and a git repository is initialized with the given remote
// URL (needed by GoReleaser for changelog generation and repository
// resolution). Builds on [Go.Base], reusing the pre-built Go image with
// module cache and go mod download already completed.
func (m *Go) GoreleaserBase(
	// Git remote URL for GoReleaser repository resolution. When empty,
	// the git repo is initialized without a remote.
	// +optional
	remoteURL string,
	// GoReleaser version. Defaults to the version pinned in this module.
	// +optional
	version string,
) *dagger.Container {
	if version == "" {
		version = defaultGoreleaserVersion
	}
	ctr := m.Base.
		WithFile("/usr/local/bin/goreleaser",
			dag.Container().From("ghcr.io/goreleaser/goreleaser:"+version).
				File("/usr/bin/goreleaser")).
		WithMountedDirectory("/src", m.Source)
	return ensureGitRepo(ctr, remoteURL)
}

// GoreleaserReleaseBase extends [Go.GoreleaserBase] with cosign, syft, and a
// nix-hash shim. Provides the full release toolset for goreleaser release
// with signing and SBOM support.
func (m *Go) GoreleaserReleaseBase(
	// Git remote URL for GoReleaser repository resolution.
	remoteURL string,
	// GoReleaser version.
	// +optional
	goreleaserVersion string,
	// Cosign version.
	// +optional
	cosignVersion string,
	// Syft version.
	// +optional
	syftVersion string,
) *dagger.Container {
	if cosignVersion == "" {
		cosignVersion = defaultCosignVersion
	}
	if syftVersion == "" {
		syftVersion = defaultSyftVersion
	}
	return m.GoreleaserBase(remoteURL, goreleaserVersion).
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
		WithEnvVariable("USER", "dagger")
}

// GoreleaserRelease runs goreleaser release and returns the dist directory
// containing release artifacts (binaries, archives, checksums). Docker
// publishing is always skipped (use [Go.PublishAndSign] for container images
// via Dagger-native APIs). Signing is skipped when oidcRequestToken is nil.
//
// +cache="never"
func (m *Go) GoreleaserRelease(
	// Git remote URL for GoReleaser repository resolution.
	remoteURL string,
	// GitHub token for creating the release.
	githubToken *dagger.Secret,
	// OIDC token request URL for keyless Sigstore signing. In GitHub Actions
	// this is the ACTIONS_ID_TOKEN_REQUEST_URL environment variable.
	// +optional
	oidcRequestURL string,
	// Bearer token for the OIDC token request. In GitHub Actions this is the
	// ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable.
	// +optional
	oidcRequestToken *dagger.Secret,
	// GoReleaser version.
	// +optional
	goreleaserVersion string,
	// Cosign version.
	// +optional
	cosignVersion string,
	// Syft version.
	// +optional
	syftVersion string,
) *dagger.Directory {
	ctr := m.GoreleaserReleaseBase(remoteURL, goreleaserVersion, cosignVersion, syftVersion).
		WithSecretVariable("GITHUB_TOKEN", githubToken)

	// Docker publishing is always skipped because container images are
	// published via Dagger-native APIs (see PublishAndSign). Signing is
	// skipped when no OIDC token is available.
	skipFlags := "docker"
	if oidcRequestToken == nil {
		skipFlags = "docker,sign"
	}

	ctr = ctr.WithEnvVariable("ACTIONS_ID_TOKEN_REQUEST_URL", oidcRequestURL)
	if oidcRequestToken != nil {
		ctr = ctr.WithSecretVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", oidcRequestToken)
	}

	return ctr.
		WithExec([]string{"goreleaser", "release", "--clean", "--skip=" + skipFlags}).
		Directory("/src/dist")
}

// GoreleaserBuild runs GoReleaser in snapshot mode, producing binaries for
// all platforms. Returns the dist/ directory. Uses [Go.GoreleaserReleaseBase]
// internally because GoReleaser validates the full config (including signing
// and SBOM sections) even in snapshot mode.
func (m *Go) GoreleaserBuild(
	ctx context.Context,
	// Git remote URL for GoReleaser repository resolution.
	remoteURL string,
	// GoReleaser version.
	// +optional
	goreleaserVersion string,
	// Cosign version.
	// +optional
	cosignVersion string,
	// Syft version.
	// +optional
	syftVersion string,
) *dagger.Directory {
	return m.GoreleaserReleaseBase(remoteURL, goreleaserVersion, cosignVersion, syftVersion).
		WithExec([]string{
			"goreleaser", "release", "--snapshot", "--clean",
			"--skip=docker,homebrew,nix,sign,sbom",
			"--parallelism=0",
		}).
		Directory("/src/dist")
}

// GoreleaserCheck validates the GoReleaser configuration. Uses
// [Go.GoreleaserBase] with a minimal git repo; the goreleaser config
// must be in the source directory.
//
// +check
func (m *Go) GoreleaserCheck(
	ctx context.Context,
	// Git remote URL for GoReleaser repository resolution. Optional for
	// config validation; required when the goreleaser config references
	// repository URLs (e.g. homebrew taps).
	// +optional
	remoteURL string,
	// GoReleaser version.
	// +optional
	version string,
) error {
	_, err := m.GoreleaserBase(remoteURL, version).
		WithExec([]string{"goreleaser", "check"}).
		Sync(ctx)
	return err
}

// VerifyBinaryPlatform runs the file command on a built binary and asserts
// that the reported architecture matches the expected architecture for the
// given platform. Returns an error if the architecture string is absent from
// the output, indicating a cross-compilation mismatch.
func (m *Go) VerifyBinaryPlatform(
	ctx context.Context,
	// Binary file to verify.
	bin *dagger.File,
	// Expected target platform (e.g. "linux/amd64").
	platform dagger.Platform,
) error {
	name, err := bin.Name(ctx)
	if err != nil {
		return fmt.Errorf("get binary name: %w", err)
	}

	arch := strings.SplitN(string(platform), "/", 2)[1]
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

// ensureGitRepo initializes a git repository in the container's workdir if
// one does not already exist, and optionally configures a remote URL. This
// is needed by GoReleaser which inspects git state for changelog generation
// and homebrew/nix repository resolution.
func ensureGitRepo(ctr *dagger.Container, remoteURL string) *dagger.Container {
	remoteCmd := ""
	if remoteURL != "" {
		remoteCmd = "(git remote get-url origin 2>/dev/null || git remote add origin " + remoteURL + ") && "
	}
	return ctr.
		WithExec([]string{"sh", "-c",
			"git init -q /src 2>/dev/null || true && " +
				"cd /src && " +
				"git config user.email 'ci@dagger.io' && " +
				"git config user.name 'Dagger CI' && " +
				remoteCmd +
				"git add -A && git diff-index --quiet HEAD -- 2>/dev/null || git commit -q --allow-empty -m 'init'"})
}

// platformToFileArch maps a Go platform architecture name to the architecture
// string produced by the file command.
var platformToFileArch = map[string]string{
	"amd64": "x86-64",
	"arm64": "aarch64",
}

// goreleaserArchSuffix maps a Go architecture name to the default GoReleaser
// directory suffix. These correspond to the default GOAMD64 (v1) and GOARM64
// (v8.0) values that GoReleaser uses when not overridden in the config.
var goreleaserArchSuffix = map[string]string{
	"amd64": "v1",
	"arm64": "v8.0",
}

// GoreleaserDistBinary returns a binary file from a GoReleaser dist directory
// for the given platform. The path follows GoReleaser's default naming
// convention: {name}_{os}_{arch}_{variant}/{name}.
func (m *Go) GoreleaserDistBinary(
	// GoReleaser dist directory.
	dist *dagger.Directory,
	// Binary name (e.g. "terrarium").
	name string,
	// Target platform (e.g. "linux/amd64").
	platform dagger.Platform,
) *dagger.File {
	parts := strings.SplitN(string(platform), "/", 3)
	os, arch := parts[0], parts[1]
	suffix := goreleaserArchSuffix[arch]
	return dist.File(fmt.Sprintf("%s_%s_%s_%s/%s", name, os, arch, suffix, name))
}
