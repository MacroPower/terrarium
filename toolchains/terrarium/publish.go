package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/terrarium/internal/dagger"

	"golang.org/x/sync/errgroup"
)

// ReleaseReport captures the results of a release operation including
// image digests, artifact checksums, and a human-readable summary.
// Create instances via [Terrarium.Release].
type ReleaseReport struct {
	// Dist directory containing release artifacts.
	Dist *dagger.Directory
	// Tag is the version tag that was released (e.g. "v1.2.3").
	Tag string
	// ImageDigests contains published image digest references
	// (e.g. "registry/image:tag@sha256:hex"), one per tag published.
	ImageDigests []string
	// UniqueDigestCount is the number of unique image digests.
	// Tags may share a manifest, so this can be less than [TagCount].
	UniqueDigestCount int
	// TagCount is the number of tags published.
	TagCount int
}

// Summary returns a Markdown summary of the release suitable for
// $GITHUB_STEP_SUMMARY.
func (r *ReleaseReport) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Release Summary\n\n")
	if r.Tag != "" {
		fmt.Fprintf(&b, "- **Version:** `%s`\n", r.Tag)
	}
	fmt.Fprintf(&b, "- **Tags published:** %d\n", r.TagCount)
	fmt.Fprintf(&b, "- **Unique image digests:** %d\n\n", r.UniqueDigestCount)

	if len(r.ImageDigests) > 0 {
		fmt.Fprintf(&b, "### Published Image Digests\n\n")
		fmt.Fprintf(&b, "| Tag Reference | Digest |\n")
		fmt.Fprintf(&b, "| --- | --- |\n")
		for _, ref := range r.ImageDigests {
			parts := strings.SplitN(ref, "@", 2)
			if len(parts) == 2 {
				fmt.Fprintf(&b, "| `%s` | `%s` |\n", parts[0], parts[1])
			} else {
				fmt.Fprintf(&b, "| `%s` | — |\n", ref)
			}
		}
	}

	return b.String()
}

// optSecretVariable returns a [dagger.WithContainerFunc] that conditionally
// adds a secret environment variable. If the secret is nil, the container
// is returned unchanged.
func optSecretVariable(name string, secret *dagger.Secret) dagger.WithContainerFunc {
	return func(ctr *dagger.Container) *dagger.Container {
		if secret != nil {
			return ctr.WithSecretVariable(name, secret)
		}
		return ctr
	}
}

// dockerConfigFile generates a Docker config.json file containing registry
// credentials. The file is built in a helper container so that the password
// remains a [dagger.Secret] throughout. The resulting file can be mounted
// into containers that need to authenticate to the registry (e.g. cosign).
func dockerConfigFile(host, username string, password *dagger.Secret) *dagger.File {
	return dag.Container().
		From("alpine:3").
		WithSecretVariable("REG_PASS", password).
		WithExec([]string{"sh", "-c",
			fmt.Sprintf(
				`printf '{"auths":{"%s":{"auth":"%%s"}}}' "$(printf '%s:%%s' "$REG_PASS" | base64 -w0)" > /tmp/config.json`,
				host, username,
			),
		}).
		File("/tmp/config.json")
}

// isPrerelease reports whether the version tag contains a pre-release
// identifier (e.g. "v1.0.0-rc.1", "v2.0.0-beta.1"). Detection checks for
// a hyphen in any of the first three dot-separated version components after
// stripping the "v" prefix. Build metadata (e.g. "v1.0.0+build.1") does not
// contain a hyphen and is correctly treated as a stable release.
func isPrerelease(tag string) bool {
	v := strings.TrimPrefix(tag, "v")
	for _, part := range strings.SplitN(v, ".", 3) {
		if strings.Contains(part, "-") {
			return true
		}
	}
	return false
}

// VersionTags returns the image tags derived from a version tag string.
// For example, "v1.2.3" yields ["latest", "v1.2.3", "v1", "v1.2"].
// Pre-release versions (e.g. "v1.0.0-rc.1") yield only the exact tag.
func (m *Terrarium) VersionTags(
	// Version tag (e.g. "v1.2.3").
	tag string,
) []string {
	if isPrerelease(tag) {
		return []string{tag}
	}

	v := strings.TrimPrefix(tag, "v")
	parts := strings.SplitN(v, ".", 3)

	tags := []string{"latest", tag}
	if len(parts) >= 1 {
		tags = append(tags, "v"+parts[0])
	}
	if len(parts) >= 2 {
		tags = append(tags, "v"+parts[0]+"."+parts[1])
	}
	return tags
}

// variantTags applies [variantTag] to each base tag, producing the
// variant-specific tag list for publishing.
func variantTags(baseTags []string, variant Variant) []string {
	tags := make([]string, len(baseTags))
	for i, t := range baseTags {
		tags[i] = variantTag(t, variant)
	}
	return tags
}

// variantTag returns the tag with a variant suffix appended. The default
// variant ([VariantScratch]) returns the tag unchanged. For other variants,
// "latest" becomes the variant name (e.g. "debian") and versioned tags
// gain a suffix (e.g. "v1.2.3-alpine").
func variantTag(tag string, variant Variant) string {
	if variant == VariantScratch {
		return tag
	}
	if tag == "latest" {
		return string(variant)
	}
	return tag + "-" + string(variant)
}

// FormatDigestChecksums converts publish output references to the
// checksums format expected by actions/attest-build-provenance. Each reference
// has the form "registry/image:tag@sha256:hex"; this function emits
// "hex  registry/image:tag" lines, deduplicating by digest.
func (m *Terrarium) FormatDigestChecksums(
	// Image references (e.g. "registry/image:tag@sha256:hex").
	refs []string,
) string {
	seen := make(map[string]bool)
	var b strings.Builder
	for _, ref := range refs {
		parts := strings.SplitN(ref, "@sha256:", 2)
		if len(parts) != 2 {
			continue
		}
		hex := parts[1]
		if seen[hex] {
			continue
		}
		seen[hex] = true
		fmt.Fprintf(&b, "%s  %s\n", hex, parts[0])
	}
	return b.String()
}

// DeduplicateDigests returns unique image references from a list, keeping
// only the first occurrence of each sha256 digest.
func (m *Terrarium) DeduplicateDigests(
	// Image references (e.g. "registry/image:tag@sha256:hex").
	refs []string,
) []string {
	seen := make(map[string]bool)
	var unique []string
	for _, ref := range refs {
		parts := strings.SplitN(ref, "@sha256:", 2)
		if len(parts) != 2 {
			continue
		}
		if !seen[parts[1]] {
			seen[parts[1]] = true
			unique = append(unique, ref)
		}
	}
	return unique
}

// RegistryHost extracts the host (with optional port) from a registry
// address. For example, "ghcr.io/macropower/terrarium" returns "ghcr.io".
func (m *Terrarium) RegistryHost(
	// Registry address (e.g. "ghcr.io/macropower/terrarium").
	registry string,
) string {
	return strings.SplitN(registry, "/", 2)[0]
}

// PublishImages builds multi-arch container images for all variants
// (scratch, debian, alpine) and publishes them to the registry. Each
// variant gets its own set of tags via [variantTag].
//
// Stable releases are published with multiple tags per variant. For
// scratch (default): :latest, :vX.Y.Z, :vX, :vX.Y. For debian/alpine
// the variant name is appended: :debian, :vX.Y.Z-debian, etc.
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
		dist, err = m.Build(ctx)
		if err != nil {
			return "", err
		}
	}

	sets, err := buildAllImages(ctx, dist, version)
	if err != nil {
		return "", err
	}

	allDigests, totalTags, err := m.publishAllVariants(ctx, sets, tags, registryUsername, registryPassword)
	if err != nil {
		return "", err
	}

	if err := m.signImages(ctx, allDigests, registryUsername, registryPassword, oidcRequestURL, oidcRequestToken); err != nil {
		return "", err
	}

	unique := m.DeduplicateDigests(allDigests)
	return fmt.Sprintf("published %d tags (%d unique digests)\n%s", totalTags, len(unique), strings.Join(allDigests, "\n")), nil
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
// Returns a [ReleaseReport] containing the dist/ directory (with checksums.txt
// and digests.txt for attestation), published image digests, and a Markdown
// summary suitable for $GITHUB_STEP_SUMMARY.
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
	ctr, err := m.releaserBase(ctx)
	if err != nil {
		return nil, err
	}
	ctr = ctr.WithSecretVariable("GITHUB_TOKEN", githubToken)

	// Conditionally forward OIDC credentials for GoReleaser blob signing.
	// Cosign (invoked by GoReleaser's signs section) detects
	// ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN and fetches fresh OIDC tokens
	// on demand via its built-in GitHub Actions provider.
	skipFlags := "docker"
	if oidcRequestToken == nil {
		skipFlags = "docker,sign"
	}
	ctr = ctr.
		WithEnvVariable("ACTIONS_ID_TOKEN_REQUEST_URL", oidcRequestURL).
		With(optSecretVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", oidcRequestToken))

	// Run GoReleaser for binaries, archives, Homebrew, Nix (and signing
	// when identityToken is provided). Docker is always skipped -- images
	// are published natively via Dagger below.
	dist := ctr.
		WithExec([]string{"goreleaser", "release", "--clean", "--skip=" + skipFlags}).
		Directory("/src/dist")

	// Derive base image tags from the version tag.
	baseTags := m.VersionTags(tag)

	// Build and publish all image variants via Dagger-native API.
	sets, err := buildAllImages(ctx, dist, tag)
	if err != nil {
		return nil, fmt.Errorf("build runtime images: %w", err)
	}

	allDigests, totalTags, err := m.publishAllVariants(ctx, sets, baseTags, registryUsername, registryPassword)
	if err != nil {
		return nil, err
	}

	if err := m.signImages(ctx, allDigests, registryUsername, registryPassword, oidcRequestURL, oidcRequestToken); err != nil {
		return nil, err
	}

	// Write digests in checksums format for attest-build-provenance.
	if len(allDigests) > 0 {
		checksums := m.FormatDigestChecksums(allDigests)
		dist = dist.WithNewFile("digests.txt", checksums)
	}

	unique := m.DeduplicateDigests(allDigests)
	return &ReleaseReport{
		Dist:              dist,
		Tag:               tag,
		ImageDigests:      allDigests,
		UniqueDigestCount: len(unique),
		TagCount:          totalTags,
	}, nil
}

// publishAllVariants publishes all variant sets concurrently. Returns the
// combined digest list and total tag count across all variants.
func (m *Terrarium) publishAllVariants(
	ctx context.Context,
	sets []variantSet,
	baseTags []string,
	registryUsername string,
	registryPassword *dagger.Secret,
) ([]string, int, error) {
	type result struct {
		digests []string
		tagCount int
	}

	results := make([]result, len(sets))
	g, gCtx := errgroup.WithContext(ctx)
	for i, s := range sets {
		varTags := variantTags(baseTags, s.variant)
		g.Go(func() error {
			digests, err := m.publishImages(gCtx, s.containers, varTags, registryUsername, registryPassword)
			if err != nil {
				return fmt.Errorf("publish %s: %w", s.variant, err)
			}
			results[i] = result{digests: digests, tagCount: len(varTags)}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, 0, err
	}

	var allDigests []string
	var totalTags int
	for _, r := range results {
		allDigests = append(allDigests, r.digests...)
		totalTags += r.tagCount
	}
	return allDigests, totalTags, nil
}

// publishImages publishes pre-built container image variants to the registry.
// Returns the list of published digest references (one per tag,
// e.g. "registry/image:tag@sha256:hex").
func (m *Terrarium) publishImages(
	ctx context.Context,
	variants []*dagger.Container,
	tags []string,
	registryUsername string,
	registryPassword *dagger.Secret,
) ([]string, error) {
	publisher := dag.Container()
	if registryPassword != nil {
		publisher = publisher.WithRegistryAuth(m.RegistryHost(m.Registry), registryUsername, registryPassword)
	}

	digests := make([]string, len(tags))
	g, gCtx := errgroup.WithContext(ctx)
	for i, t := range tags {
		ref := fmt.Sprintf("%s:%s", m.Registry, t)
		g.Go(func() error {
			digest, err := publisher.Publish(gCtx, ref, dagger.ContainerPublishOpts{
				PlatformVariants: variants,
			})
			if err != nil {
				return fmt.Errorf("publish %s: %w", ref, err)
			}
			digests[i] = digest
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	return digests, nil
}

// signImages signs published image digests using cosign keyless signing
// (Fulcio + Rekor). Cosign's built-in GitHub Actions provider uses the
// request URL and token to fetch fresh OIDC tokens on demand, avoiding
// expiry issues. Digests are deduplicated before signing since multiple
// tags often share one manifest. Does nothing when oidcRequestToken is nil.
func (m *Terrarium) signImages(
	ctx context.Context,
	digests []string,
	registryUsername string,
	registryPassword *dagger.Secret,
	oidcRequestURL string,
	oidcRequestToken *dagger.Secret,
) error {
	if oidcRequestToken == nil {
		return nil
	}

	toSign := m.DeduplicateDigests(digests)

	cosignCtr := dag.Container().
		From("gcr.io/projectsigstore/cosign:" + cosignVersion).
		WithEnvVariable("ACTIONS_ID_TOKEN_REQUEST_URL", oidcRequestURL).
		WithSecretVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", oidcRequestToken)
	if registryPassword != nil {
		// Mount a Docker config.json so cosign can authenticate to the
		// registry. WithRegistryAuth only covers Dagger/BuildKit operations;
		// cosign makes its own HTTP requests and reads credentials from the
		// Docker config.
		cfg := dockerConfigFile(m.RegistryHost(m.Registry), registryUsername, registryPassword)
		cosignCtr = cosignCtr.
			WithMountedFile("/tmp/docker/config.json", cfg).
			WithEnvVariable("DOCKER_CONFIG", "/tmp/docker")
	}

	g, gCtx := errgroup.WithContext(ctx)
	for _, digest := range toSign {
		g.Go(func() error {
			_, err := cosignCtr.
				WithExec([]string{"cosign", "sign", digest, "--yes"}).
				Sync(gCtx)
			if err != nil {
				return fmt.Errorf("sign image %s: %w", digest, err)
			}
			return nil
		})
	}
	return g.Wait()
}
