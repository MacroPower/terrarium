package main

import (
	"context"
	"fmt"

	"dagger/ci/internal/dagger"

	"golang.org/x/sync/errgroup"
)

// ReleaseDryRun validates the full release pipeline without publishing.
// Builds snapshot binaries via GoReleaser, verifies each binary's architecture
// matches its target platform, and constructs multi-arch container images,
// catching cross-compilation failures, missing tool binaries, and image build
// errors that would surface only during a real release.
//
// For a fast goreleaser config-only check, see [Ci.LintReleaser].
func (m *Ci) ReleaseDryRun(ctx context.Context) error {
	// platformBinaries maps each target platform to its GoReleaser dist path.
	type platformBinary struct {
		platform dagger.Platform
		distDir  string
	}
	targets := []platformBinary{
		{platform: "linux/amd64", distDir: "terrarium_linux_amd64_v1"},
		{platform: "linux/arm64", distDir: "terrarium_linux_arm64_v8.0"},
	}

	// Snapshot build -- exercises goreleaser cross-compilation for all
	// platforms, releaserBase tool setup (cosign, syft), and
	// archive/checksum generation.
	dist, err := m.Build(ctx)
	if err != nil {
		return err
	}

	g, ctx := errgroup.WithContext(ctx)

	// Platform verification -- asserts each binary is for the intended
	// architecture, catching cross-compilation mismatches early.
	for _, t := range targets {
		g.Go(func() error {
			bin := dist.File(t.distDir + "/terrarium")
			if err := m.Goreleaser.VerifyBinaryPlatform(ctx, bin, t.platform); err != nil {
				return fmt.Errorf("platform verification for %s: %w", t.platform, err)
			}
			return nil
		})
	}

	// Container image build -- exercises runtime base image construction,
	// binary packaging, and OCI metadata for all platforms.
	g.Go(func() error {
		containers, err := m.BuildImages(ctx, "dry-run", dist, "")
		if err != nil {
			return err
		}
		for _, ctr := range containers {
			if _, err := ctr.Sync(ctx); err != nil {
				return err
			}
		}
		return nil
	})

	return g.Wait()
}
