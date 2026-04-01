// Integration tests for the [Terrarium] module. Individual tests are annotated
// with +check so `dagger check -m toolchains/terrarium/tests` runs them all concurrently.
package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"dagger/tests/internal/dagger"

	"golang.org/x/sync/errgroup"
)

// Tests provides integration tests for the [Terrarium] module. Create instances
// with [New].
type Tests struct{}

// All runs all tests in parallel.
func (m *Tests) All(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { return m.TestBuildImageMetadata(ctx) })
	g.Go(func() error { return m.TestBuildVariantContents(ctx) })
	g.Go(func() error { return m.TestBinary(ctx) })

	return g.Wait()
}

// TestBuildImageMetadata verifies that [Terrarium.BuildImages] produces
// containers with expected OCI labels and entrypoint for each variant.
//
// +check
func (m *Tests) TestBuildImageMetadata(ctx context.Context) error {
	dist := dag.Go().GoreleaserBuild("https://github.com/macropower/terrarium.git")

	for _, variant := range []string{"scratch", "debian"} {
		containers, err := dag.Terrarium().BuildImages(ctx, dagger.TerrariumBuildImagesOpts{
			Version: "v0.0.0-test",
			Dist:    dist,
			Variant: variant,
		})
		if err != nil {
			return fmt.Errorf("%s: build images: %w", variant, err)
		}
		if len(containers) != 2 {
			return fmt.Errorf("%s: expected 2 platform containers, got %d", variant, len(containers))
		}

		for i, ctr := range containers {
			version, err := ctr.Label(ctx, "org.opencontainers.image.version")
			if err != nil {
				return fmt.Errorf("%s[%d]: version label: %w", variant, i, err)
			}
			if version != "v0.0.0-test" {
				return fmt.Errorf("%s[%d]: version label = %q, want %q", variant, i, version, "v0.0.0-test")
			}

			title, err := ctr.Label(ctx, "org.opencontainers.image.title")
			if err != nil {
				return fmt.Errorf("%s[%d]: title label: %w", variant, i, err)
			}
			if title != "terrarium" {
				return fmt.Errorf("%s[%d]: title label = %q, want %q", variant, i, title, "terrarium")
			}

			created, err := ctr.Label(ctx, "org.opencontainers.image.created")
			if err != nil {
				return fmt.Errorf("%s[%d]: created label: %w", variant, i, err)
			}
			if created == "" {
				return fmt.Errorf("%s[%d]: created label is empty", variant, i)
			}

			ep, err := ctr.Entrypoint(ctx)
			if err != nil {
				return fmt.Errorf("%s[%d]: entrypoint: %w", variant, i, err)
			}
			if len(ep) != 1 || ep[0] != "terrarium" {
				return fmt.Errorf("%s[%d]: entrypoint = %v, want [terrarium]", variant, i, ep)
			}
		}
	}

	return nil
}

// TestBuildVariantContents verifies that the debian image contains envoy.
// Only tests the first platform container (linux/amd64) since dependency
// installation is platform-independent.
//
// +check
func (m *Tests) TestBuildVariantContents(ctx context.Context) error {
	dist := dag.Go().GoreleaserBuild("https://github.com/macropower/terrarium.git")

	containers, err := dag.Terrarium().BuildImages(ctx, dagger.TerrariumBuildImagesOpts{
		Version: "v0.0.0-test",
		Dist:    dist,
		Variant: "debian",
	})
	if err != nil {
		return fmt.Errorf("debian: build: %w", err)
	}

	_, err = containers[0].WithExec([]string{"which", "envoy"}).Sync(ctx)
	if err != nil {
		return fmt.Errorf("debian: expected envoy to be installed: %w", err)
	}

	return nil
}

// TestPublishImages verifies that [Terrarium.PublishImages] builds and
// publishes all variant images concurrently to a registry. Uses ttl.sh
// as an anonymous temporary registry (images expire after the tag duration).
//
// Signing is not tested here because keyless cosign requires an OIDC identity
// token (e.g. from GitHub Actions). Signing is exercised during real releases.
//
// Not annotated with +check because it depends on external network access
// to ttl.sh and takes ~5 minutes. Run manually:
//
//	dagger call -m toolchains/terrarium/tests test-publish-images
func (m *Tests) TestPublishImages(ctx context.Context) error {
	// Use a unique registry path on ttl.sh to avoid collisions between runs.
	registry := fmt.Sprintf("ttl.sh/terrarium-ci-%d", time.Now().UnixNano())
	ci := dag.Terrarium(dagger.TerrariumOpts{Registry: registry})

	// Publish 2 tags to exercise deduplication (both tags share one manifest
	// digest) and concurrent variant publishing.
	dist := dag.Go().GoreleaserBuild("https://github.com/macropower/terrarium.git")
	result, err := ci.PublishImages(ctx, []string{"1h", "2h"}, dagger.TerrariumPublishImagesOpts{
		Dist: dist,
	})
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	// Verify the result contains sha256 digest references.
	if !strings.Contains(result, "sha256:") {
		return fmt.Errorf("expected sha256 digest in result, got: %s", result)
	}

	// Verify 4 tags were published (2 base tags x 2 variants).
	if !strings.Contains(result, "published 4 tags") {
		return fmt.Errorf("expected 'published 4 tags' in result, got: %s", result)
	}

	// Verify deduplication: 2 unique digests (one per variant, each with
	// 2 tags sharing a manifest).
	if !strings.Contains(result, "2 unique digests") {
		return fmt.Errorf("expected '2 unique digests' in result, got: %s", result)
	}

	// Verify both variants were published by checking for variant-specific
	// tag references in the digest output. The scratch variant uses base tags
	// directly, while debian gets suffixed tags.
	lines := strings.Split(strings.TrimSpace(result), "\n")
	digestLines := lines[1:] // skip summary line

	var hasScratch, hasDebian bool
	for _, line := range digestLines {
		switch {
		case strings.Contains(line, ":debian@") || strings.Contains(line, "-debian@"):
			hasDebian = true
		case strings.Contains(line, "@sha256:"):
			// Any digest line without a variant suffix is scratch.
			hasScratch = true
		}
	}
	if !hasScratch {
		return fmt.Errorf("missing scratch variant in digests: %s", result)
	}
	if !hasDebian {
		return fmt.Errorf("missing debian variant in digests: %s", result)
	}

	// Verify that all 2 unique digests are distinct (each variant produces
	// its own manifest).
	seen := make(map[string]bool)
	for _, line := range digestLines {
		parts := strings.SplitN(line, "@sha256:", 2)
		if len(parts) == 2 {
			seen[parts[1]] = true
		}
	}
	if len(seen) != 2 {
		return fmt.Errorf("expected 2 distinct digests across variants, got %d: %s", len(seen), result)
	}

	return nil
}



// TestBinary verifies that [Terrarium.Binary] compiles the terrarium binary.
//
// +check
func (m *Tests) TestBinary(ctx context.Context) error {
	binary := dag.Terrarium().Binary(dagger.TerrariumBinaryOpts{})
	size, err := binary.Size(ctx)
	if err != nil {
		return fmt.Errorf("binary: %w", err)
	}
	if size == 0 {
		return fmt.Errorf("binary has zero size")
	}
	return nil
}
