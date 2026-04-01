package main

import (
	"context"
	"path/filepath"

	"dagger/go/internal/dagger"
)

// FormatGo runs golangci-lint --fix across all discovered Go modules and
// returns the merged changeset of Go source file changes.
func (m *Go) FormatGo(
	ctx context.Context,
	// Include only modules whose directory matches one of these globs.
	// +optional
	include []string,
	// Exclude modules whose directory matches any of these globs.
	// +optional
	exclude []string,
) (*dagger.Changeset, error) {
	mods, err := m.Modules(ctx, include, exclude)
	if err != nil {
		return nil, err
	}

	changesets := make([]*dagger.Changeset, len(mods))
	p := newParallel().withLimit(3)
	for i, mod := range mods {
		p = p.withJob("format-go:"+mod, func(ctx context.Context) error {
			changesets[i] = m.FormatGoModule(mod)
			return nil
		})
	}
	if err := p.run(ctx); err != nil {
		return nil, err
	}
	return mergeChangesets(changesets), nil
}

// FormatGoModule runs golangci-lint --fix on a single module directory
// and returns the changeset.
func (m *Go) FormatGoModule(
	// Module directory relative to the source root.
	mod string,
) *dagger.Changeset {
	outDir := "/src"
	if mod != "" && mod != "." {
		outDir = filepath.Join("/src", mod)
	}
	goFmt := m.lintBase(mod).
		WithExec([]string{"golangci-lint", "run", "--fix"}).
		Directory(outDir)
	if mod != "" && mod != "." {
		// Re-assemble into a full-source changeset so callers get
		// paths relative to the source root.
		full := m.Source.WithDirectory(mod, goFmt)
		return full.Changes(m.Source)
	}
	return goFmt.Changes(m.Source)
}

// FormatPrettier runs prettier --write on YAML, JSON, and Markdown files
// and returns the changeset against the original source directory.
func (m *Go) FormatPrettier(
	// Prettier config file path relative to source root.
	// +optional
	configPath string,
	// File patterns to format.
	// +optional
	patterns []string,
) *dagger.Changeset {
	if configPath == "" {
		configPath = "./.prettierrc.yaml"
	}
	if len(patterns) == 0 {
		patterns = defaultPrettierPatterns()
	}
	prettierFmt := m.prettierBase().
		WithMountedDirectory("/src", m.Source).
		WithWorkdir("/src").
		WithExec(append(
			[]string{"prettier", "--config", configPath, "-w"},
			patterns...,
		)).
		Directory("/src")
	return prettierFmt.Changes(m.Source)
}

// Format runs golangci-lint --fix and prettier --write, returning the
// merged changeset against the original source directory.
//
// Both formatters operate on non-overlapping file types (.go vs
// .yaml/.md/.json), so they run against the original source in parallel.
// The changesets are merged using [Go.FormatGo] and [Go.FormatPrettier].
//
// +generate
func (m *Go) Format(
	ctx context.Context,
	// Include only modules whose directory matches one of these globs.
	// Passed through to [Go.FormatGo]; prettier always formats all
	// matching files.
	// +optional
	include []string,
	// Exclude modules whose directory matches any of these globs.
	// Passed through to [Go.FormatGo]; prettier always formats all
	// matching files.
	// +optional
	exclude []string,
) (*dagger.Changeset, error) {
	goChangeset, err := m.FormatGo(ctx, include, exclude)
	if err != nil {
		return nil, err
	}
	prettierChangeset := m.FormatPrettier("", nil)
	return mergeChangesets([]*dagger.Changeset{goChangeset, prettierChangeset}), nil
}

// Generate runs go generate and returns the changeset of generated files
// against the original source.
//
// +generate
func (m *Go) Generate() *dagger.Changeset {
	generated := m.Env("").
		WithExec([]string{"go", "generate", "./..."}).
		Directory("/src").
		WithoutDirectory(".git")
	return generated.Changes(m.Source)
}
