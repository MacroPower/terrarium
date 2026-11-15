package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// modulePaths returns the paths of the go.mod file and the go.sum file of
// the module in dir.
func modulePaths(dir string) (string, string) {
	return filepath.Join(dir, "go.mod"), filepath.Join(dir, "go.sum")
}

// goModule holds the requirements of a go.mod file and the lines of the
// go.sum file next to it. Create instances with [readModule].
type goModule struct {
	modPath string
	sumPath string
	reqs    []requirement
	lines   []sumLine
}

// readModule reads go.mod and go.sum of the module in dir. A module
// without a go.sum file has no lines.
func readModule(dir string) (*goModule, error) {
	modPath, sumPath := modulePaths(dir)

	data, err := os.ReadFile(modPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrModFile, err)
	}

	reqs, err := requirements(modPath, data)
	if err != nil {
		return nil, err
	}

	data, err = os.ReadFile(sumPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %w", ErrSumFile, err)
	}

	lines, err := parseSums(sumPath, data)
	if err != nil {
		return nil, err
	}

	return &goModule{modPath: modPath, sumPath: sumPath, reqs: reqs, lines: lines}, nil
}

// stale returns an [ErrStale] error that lists each of the [problems] of
// the module, or nil for a module without problems. The message names
// the command in fix when fix is not empty.
func (m *goModule) stale(fix string) error {
	msgs := problems(m.reqs, m.lines)
	if len(msgs) == 0 {
		return nil
	}

	advice := ""
	if fix != "" {
		advice = " (run `" + fix + "`)"
	}

	return fmt.Errorf(
		"%w: %s does not match %s%s:\n\tit holds %s",
		ErrStale, m.sumPath, m.modPath, advice, strings.Join(msgs, "\n\tit holds "),
	)
}

// download writes the hashes that go.mod requires into go.sum in the
// module in dir. It runs the go command with the environment in env and
// with GOWORK=off, because the module is outside the workspace.
//
// The go command adds a hash and never removes one, so the function
// first removes the hashes of the versions that go.mod does not select,
// with [trim]. `go mod download` with the path of each required module
// then adds the two hashes of each selected version. `go mod download`
// without arguments adds the go.mod hash of each other version that the
// go command reads to select the versions of the build. It also raises a
// requirement in go.mod when another required module needs a later
// version, so the function runs it before it reads go.mod.
func download(ctx context.Context, dir string, env []string) error {
	// The go command reports a file that it cannot parse in its own
	// words. Reading the module first reports it as the check command
	// does.
	_, err := readModule(dir)
	if err != nil {
		return err
	}

	err = goModDownload(ctx, dir, env)
	if err != nil {
		return err
	}

	mod, err := readModule(dir)
	if err != nil {
		return err
	}

	kept := trim(mod.reqs, mod.lines)
	if len(kept) != len(mod.lines) {
		err = writeFile(mod.sumPath, formatSums(kept))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSumFile, err)
		}
	}

	if len(mod.reqs) > 0 {
		paths := make([]string, 0, len(mod.reqs))
		for _, req := range mod.reqs {
			paths = append(paths, req.path)
		}

		err = goModDownload(ctx, dir, env, paths...)
		if err != nil {
			return err
		}
	}

	err = goModDownload(ctx, dir, env)
	if err != nil {
		return err
	}

	mod, err = readModule(dir)
	if err != nil {
		return err
	}

	return mod.stale("")
}

// goModDownload runs `go mod download` in dir with the module paths in
// paths as its arguments.
func goModDownload(ctx context.Context, dir string, env []string, paths ...string) error {
	args := append([]string{"mod", "download"}, paths...)

	//nolint:gosec // G204: the go command, and module paths of a go.mod file of this repository.
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir

	cmd.Env = append(slices.Clone(env), "GOWORK=off")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: go mod download in %s: %w: %s", ErrDownload, dir, err, bytes.TrimSpace(output))
	}

	return nil
}

// fileState is the content of a file at one moment. Create instances
// with [readState].
type fileState struct {
	path   string
	data   []byte
	exists bool
}

// readState reads the file at path. A missing file is a state too.
func readState(path string) (fileState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fileState{path: path}, nil
	}

	if err != nil {
		return fileState{}, fmt.Errorf("read state: %w", err)
	}

	return fileState{path: path, data: data, exists: true}, nil
}

// equal reports whether s and other hold the same content.
func (s fileState) equal(other fileState) bool {
	return s.exists == other.exists && bytes.Equal(s.data, other.data)
}

// restore writes the content of s to its file, or removes a file that did
// not exist. It leaves a file that holds the content unchanged.
func (s fileState) restore() error {
	now, err := readState(s.path)
	if err != nil {
		return err
	}

	if now.equal(s) {
		return nil
	}

	if !s.exists {
		err = os.Remove(s.path)
		if err != nil {
			return fmt.Errorf("restore: %w", err)
		}

		return nil
	}

	err = writeFile(s.path, s.data)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}

	return nil
}

// writeFile replaces the content of the file at path with data and keeps
// the permissions of the file.
func writeFile(path string, data []byte) error {
	mode := fs.FileMode(0o644)

	info, err := os.Stat(path)
	if err == nil {
		mode = info.Mode().Perm()
	}

	err = os.WriteFile(path, data, mode)
	if err != nil {
		return fmt.Errorf("write file: %w", err)
	}

	return nil
}
