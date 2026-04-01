package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/go/internal/dagger"

	"golang.org/x/sync/errgroup"
)

// ReleaseReport captures the results of a release operation including
// image digests, artifact checksums, and a human-readable summary.
// Create instances with [Go.NewReleaseReport].
type ReleaseReport struct {
	// Dist directory containing release artifacts.
	Dist *dagger.Directory
	// Tag is the version tag that was released (e.g. "v1.2.3").
	Tag string
	// ImageDigests contains published image digest references
	// (e.g. "registry/image:tag@sha256:hex"), one per tag published.
	ImageDigests []string
	// UniqueDigestCount is the number of unique image digests.
	// Tags may share a manifest, so this can be less than [ReleaseReport.TagCount].
	UniqueDigestCount int
	// TagCount is the number of tags published.
	TagCount int
}

// NewReleaseReport creates a new [ReleaseReport].
func (m *Go) NewReleaseReport(
	// Dist directory containing release artifacts.
	dist *dagger.Directory,
	// Version tag (e.g. "v1.2.3").
	tag string,
	// Published image digest references.
	imageDigests []string,
	// Number of unique image digests.
	uniqueDigestCount int,
	// Number of tags published.
	tagCount int,
) *ReleaseReport {
	return &ReleaseReport{
		Dist:              dist,
		Tag:               tag,
		ImageDigests:      imageDigests,
		UniqueDigestCount: uniqueDigestCount,
		TagCount:          tagCount,
	}
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

// PlatformBinary pairs a target platform with its binary file from a
// GoReleaser dist directory, used by [Go.ReleaseDryRun] to verify
// cross-compilation correctness. Create instances with [Go.NewPlatformBinary].
type PlatformBinary struct {
	// Target platform (e.g. "linux/amd64").
	Platform dagger.Platform
	// Binary file from the GoReleaser dist directory.
	Binary *dagger.File
}

// NewPlatformBinary creates a new [PlatformBinary].
func (m *Go) NewPlatformBinary(
	// Target platform (e.g. "linux/amd64").
	platform dagger.Platform,
	// Binary file from the GoReleaser dist directory.
	binary *dagger.File,
) *PlatformBinary {
	return &PlatformBinary{Platform: platform, Binary: binary}
}

// VariantSet pairs a variant name with its pre-built platform containers
// for multi-arch image publishing. Create instances with [Go.NewVariantSet].
type VariantSet struct {
	// Variant name (e.g. "scratch", "debian").
	Variant string
	// Pre-built platform variant containers.
	Containers []*dagger.Container
}

// NewVariantSet creates a new [VariantSet].
func (m *Go) NewVariantSet(
	// Variant name (e.g. "scratch", "debian").
	variant string,
	// Pre-built platform variant containers.
	containers []*dagger.Container,
) *VariantSet {
	return &VariantSet{Variant: variant, Containers: containers}
}

// PublishVariants publishes multiple image [VariantSet]s concurrently. For
// each set, variant-specific tags are computed via [Go.VariantTags] and images
// are published via [Go.PublishImages]. Returns the combined digest list
// across all variants.
//
// +cache="never"
func (m *Go) PublishVariants(
	ctx context.Context,
	// Variant sets to publish.
	sets []*VariantSet,
	// Base tags before variant suffixes are applied (e.g. ["latest", "v1.2.3"]).
	baseTags []string,
	// Registry address (e.g. "ghcr.io/macropower/terrarium").
	registry string,
	// The default variant whose tags are returned unchanged (e.g. "scratch").
	defaultVariant string,
	// Registry username for authentication.
	// +optional
	registryUsername string,
	// Registry password or token for authentication.
	// +optional
	registryPassword *dagger.Secret,
) ([]string, error) {
	results := make([][]string, len(sets))
	g, gCtx := errgroup.WithContext(ctx)
	for i, s := range sets {
		varTags := m.VariantTags(baseTags, s.Variant, defaultVariant)
		g.Go(func() error {
			digests, err := m.PublishImages(gCtx, s.Containers, varTags, registry, registryUsername, registryPassword)
			if err != nil {
				return fmt.Errorf("publish %s: %w", s.Variant, err)
			}
			results[i] = digests
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	var allDigests []string
	for _, digests := range results {
		allDigests = append(allDigests, digests...)
	}
	return allDigests, nil
}

// VersionTags returns the image tags derived from a version tag string.
// For example, "v1.2.3" yields ["latest", "v1.2.3", "v1", "v1.2"].
// Pre-release versions (e.g. "v1.0.0-rc.1") yield only the exact tag.
func (m *Go) VersionTags(
	// Version tag (e.g. "v1.2.3").
	tag string,
) []string {
	if isPrerelease(tag) {
		return []string{tag}
	}

	v := strings.TrimPrefix(tag, "v")
	parts := strings.SplitN(v, ".", 3)

	// SplitN always returns at least one element.
	tags := []string{"latest", tag, "v" + parts[0]}
	if len(parts) >= 2 {
		tags = append(tags, "v"+parts[0]+"."+parts[1])
	}
	return tags
}

// VariantTag returns the tag with a variant suffix appended. When variant
// equals defaultVariant, the tag is returned unchanged. For other variants,
// "latest" becomes the variant name (e.g. "debian") and versioned tags gain
// a suffix (e.g. "v1.2.3-debian").
func (m *Go) VariantTag(
	// Base tag (e.g. "v1.2.3", "latest").
	tag string,
	// Variant name (e.g. "scratch", "debian").
	variant string,
	// The default variant whose tags are returned unchanged.
	defaultVariant string,
) string {
	if variant == defaultVariant {
		return tag
	}
	if tag == "latest" {
		return variant
	}
	return tag + "-" + variant
}

// VariantTags applies [Go.VariantTag] to each base tag, producing the
// variant-specific tag list for publishing.
func (m *Go) VariantTags(
	// Base tags (e.g. ["latest", "v1.2.3", "v1", "v1.2"]).
	baseTags []string,
	// Variant name.
	variant string,
	// The default variant whose tags are returned unchanged.
	defaultVariant string,
) []string {
	tags := make([]string, len(baseTags))
	for i, t := range baseTags {
		tags[i] = m.VariantTag(t, variant, defaultVariant)
	}
	return tags
}

// PublishImages publishes pre-built container image variants to a registry.
// Returns the list of published digest references (one per tag,
// e.g. "registry/image:tag@sha256:hex").
func (m *Go) PublishImages(
	ctx context.Context,
	// Pre-built platform variant containers.
	containers []*dagger.Container,
	// Tags to publish (e.g. ["latest", "v1.2.3"]).
	tags []string,
	// Registry address (e.g. "ghcr.io/macropower/terrarium").
	registry string,
	// Registry username for authentication.
	// +optional
	registryUsername string,
	// Registry password or token for authentication.
	// +optional
	registryPassword *dagger.Secret,
) ([]string, error) {
	host := m.RegistryHost(registry)

	publisher := dag.Container()
	if registryPassword != nil {
		publisher = publisher.WithRegistryAuth(host, registryUsername, registryPassword)
	}

	digests := make([]string, len(tags))
	g, gCtx := errgroup.WithContext(ctx)
	for i, t := range tags {
		ref := fmt.Sprintf("%s:%s", registry, t)
		g.Go(func() error {
			digest, err := publisher.Publish(gCtx, ref, dagger.ContainerPublishOpts{
				PlatformVariants: containers,
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

// SignImages signs published image digests using cosign keyless signing
// (Fulcio + Rekor). Cosign's built-in GitHub Actions provider uses the
// request URL and token to fetch fresh OIDC tokens on demand, avoiding
// expiry issues. Digests are deduplicated before signing since multiple
// tags often share one manifest. Does nothing when oidcRequestToken is nil.
func (m *Go) SignImages(
	ctx context.Context,
	// Published image digest references.
	digests []string,
	// Registry address for authentication.
	registry string,
	// Registry username for authentication.
	// +optional
	registryUsername string,
	// Registry password or token for authentication.
	// +optional
	registryPassword *dagger.Secret,
	// Cosign image version. Defaults to the version pinned in this module.
	// +optional
	cosignVersion string,
	// OIDC token request URL for keyless Sigstore signing.
	// +optional
	oidcRequestURL string,
	// Bearer token for the OIDC token request.
	// +optional
	oidcRequestToken *dagger.Secret,
) error {
	if oidcRequestToken == nil {
		return nil
	}

	if cosignVersion == "" {
		cosignVersion = defaultCosignVersion
	}

	toSign := m.DeduplicateDigests(digests)
	host := m.RegistryHost(registry)

	cosignCtr := dag.Container().
		From("gcr.io/projectsigstore/cosign:" + cosignVersion).
		WithEnvVariable("ACTIONS_ID_TOKEN_REQUEST_URL", oidcRequestURL).
		WithSecretVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", oidcRequestToken)
	if registryPassword != nil {
		// Mount a Docker config.json so cosign can authenticate to the
		// registry. WithRegistryAuth only covers Dagger/BuildKit operations;
		// cosign makes its own HTTP requests and reads credentials from the
		// Docker config.
		cfg := dockerConfigFile(host, registryUsername, registryPassword)
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

// FormatDigestChecksums converts publish output references to the
// checksums format expected by actions/attest-build-provenance. Each reference
// has the form "registry/image:tag@sha256:hex"; this function emits
// "hex  registry/image:tag" lines, deduplicating by digest.
func (m *Go) FormatDigestChecksums(
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
func (m *Go) DeduplicateDigests(
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
func (m *Go) RegistryHost(
	// Registry address (e.g. "ghcr.io/macropower/terrarium").
	registry string,
) string {
	return strings.SplitN(registry, "/", 2)[0]
}

// PublishAndSign publishes image [VariantSet]s and signs them via cosign
// keyless signing. Combines [Go.PublishVariants] and [Go.SignImages] into
// a single call. Returns the list of published digest references across
// all variants.
//
// +cache="never"
func (m *Go) PublishAndSign(
	ctx context.Context,
	// Variant sets to publish.
	sets []*VariantSet,
	// Base tags before variant suffixes are applied (e.g. ["latest", "v1.2.3"]).
	tags []string,
	// Registry address (e.g. "ghcr.io/macropower/terrarium").
	registry string,
	// The default variant whose tags are returned unchanged (e.g. "scratch").
	defaultVariant string,
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
) ([]string, error) {
	allDigests, err := m.PublishVariants(ctx, sets, tags, registry, defaultVariant,
		registryUsername, registryPassword)
	if err != nil {
		return nil, err
	}

	if err := m.SignImages(ctx, allDigests, registry,
		registryUsername, registryPassword, "", oidcRequestURL, oidcRequestToken,
	); err != nil {
		return nil, err
	}

	return allDigests, nil
}

// Release publishes image variant sets with signing, writes a digests.txt
// attestation file to the dist directory, and returns a [ReleaseReport].
//
// The caller is responsible for running GoReleaser and building container
// images; this method handles everything after image construction.
//
// +cache="never"
func (m *Go) Release(
	ctx context.Context,
	// Variant sets to publish (pre-built platform containers).
	sets []*VariantSet,
	// Version tag to release (e.g. "v1.2.3").
	tag string,
	// GoReleaser dist directory containing release artifacts.
	dist *dagger.Directory,
	// Registry address (e.g. "ghcr.io/macropower/terrarium").
	registry string,
	// The default variant whose tags are returned unchanged (e.g. "scratch").
	defaultVariant string,
	// Registry username for authentication.
	// +optional
	registryUsername string,
	// Registry password or token for authentication.
	// +optional
	registryPassword *dagger.Secret,
	// OIDC token request URL for keyless Sigstore signing. In GitHub Actions
	// this is the ACTIONS_ID_TOKEN_REQUEST_URL environment variable.
	// +optional
	oidcRequestURL string,
	// Bearer token for the OIDC token request. In GitHub Actions this is the
	// ACTIONS_ID_TOKEN_REQUEST_TOKEN environment variable.
	// +optional
	oidcRequestToken *dagger.Secret,
) (*ReleaseReport, error) {
	baseTags := m.VersionTags(tag)

	allDigests, err := m.PublishAndSign(ctx, sets, baseTags, registry, defaultVariant,
		registryUsername, registryPassword, oidcRequestURL, oidcRequestToken)
	if err != nil {
		return nil, err
	}

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
		TagCount:          len(baseTags) * len(sets),
	}, nil
}

// ReleaseDryRun validates release artifacts without publishing. Verifies
// each binary's architecture matches its target platform and syncs all
// provided containers to catch build errors. Runs all checks in parallel.
func (m *Go) ReleaseDryRun(
	ctx context.Context,
	// Binaries to verify against their target platforms.
	binaries []*PlatformBinary,
	// Containers to sync (e.g. built images). Each is evaluated to
	// catch build errors without publishing.
	// +optional
	containers []*dagger.Container,
) error {
	g, ctx := errgroup.WithContext(ctx)

	for _, b := range binaries {
		g.Go(func() error {
			if err := m.VerifyBinaryPlatform(ctx, b.Binary, b.Platform); err != nil {
				return fmt.Errorf("platform verification for %s: %w", b.Platform, err)
			}
			return nil
		})
	}

	for _, ctr := range containers {
		g.Go(func() error {
			_, err := ctr.Sync(ctx)
			return err
		})
	}

	return g.Wait()
}

// isPrerelease reports whether the version tag contains a pre-release
// identifier (e.g. "v1.0.0-rc.1", "v2.0.0-beta.1"). Detection checks for
// a hyphen in any of the first three dot-separated version components after
// stripping the "v" prefix.
func isPrerelease(tag string) bool {
	v := strings.TrimPrefix(tag, "v")
	for _, part := range strings.SplitN(v, ".", 3) {
		if strings.Contains(part, "-") {
			return true
		}
	}
	return false
}

// dockerConfigFile generates a Docker config.json file containing registry
// credentials. The file is built in a helper container so that the password
// remains a [dagger.Secret] throughout. The resulting file can be mounted
// into containers that need to authenticate to the registry (e.g. cosign).
func dockerConfigFile(host, username string, password *dagger.Secret) *dagger.File {
	return dag.Container().
		From("debian:13-slim").
		WithSecretVariable("REG_PASS", password).
		WithExec([]string{"sh", "-c",
			fmt.Sprintf(
				`printf '{"auths":{"%s":{"auth":"%%s"}}}' "$(printf '%s:%%s' "$REG_PASS" | base64 -w0)" > /tmp/config.json`,
				host, username,
			),
		}).
		File("/tmp/config.json")
}
