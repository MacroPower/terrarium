package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"go.jacobcolvin.com/terrarium/envoybin"
)

// ErrEnvoyNotFound means that the --envoy-path flag or the envoy.path
// config key names a binary that the proxy cannot execute.
var ErrEnvoyNotFound = errors.New("envoy binary not found")

// envoyBinary is the Envoy executable of one proxy run. Create
// instances with [resolveEnvoy].
type envoyBinary struct {
	// The open managed binary whose hash [resolveEnvoy] checked. It is
	// nil for an unpinned binary.
	file *os.File

	// The location of the executable.
	path string
}

// resolveEnvoy returns the Envoy binary that the proxy runs. The caller
// closes the binary after it starts the command.
//
// With an empty override, the binary is the managed build of inst, and
// resolveEnvoy hashes the installed binary on every call. When the
// install path holds no binary, it installs the build first, and ctx
// bounds that install. It returns an error that wraps
// [envoybin.ErrHashMismatch] when the installed binary does not have
// the pinned hash, and it does not replace that binary. It returns an
// error that wraps [envoybin.ErrUnsupportedPlatform] when inst has no
// build for the host.
//
// A non-empty override names an unpinned binary, which resolveEnvoy
// does not hash. It logs a warning that names the binary. An override
// without a path separator is a command name, and resolveEnvoy looks it
// up on PATH. It returns [ErrEnvoyNotFound] when the override names no
// executable file. An override leaves inst unused.
func resolveEnvoy(ctx context.Context, inst *envoybin.Installer, override string) (*envoyBinary, error) {
	if override != "" {
		return unpinnedEnvoy(ctx, override)
	}

	return managedEnvoy(ctx, inst)
}

// unpinnedEnvoy returns the binary that name selects, without a hash
// check. See [resolveEnvoy].
func unpinnedEnvoy(ctx context.Context, name string) (*envoyBinary, error) {
	// LookPath reads PATH only for a name without a path separator.
	path, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEnvoyNotFound, err)
	}

	slog.WarnContext(ctx, "proxy: envoy build is unpinned, terrarium does not check its hash",
		slog.String("path", path))

	return &envoyBinary{path: path}, nil
}

// managedEnvoy returns the open, hash-checked managed build of inst and
// installs the build when it is missing. See [resolveEnvoy].
func managedEnvoy(ctx context.Context, inst *envoybin.Installer) (*envoyBinary, error) {
	path, err := inst.Path()
	if err != nil {
		return nil, fmt.Errorf(
			"%w: set --envoy-path or the envoy.path config key to run another envoy binary", err)
	}

	f, err := inst.Open()
	if errors.Is(err, envoybin.ErrNotInstalled) {
		slog.InfoContext(ctx, "proxy: installing the managed envoy build",
			slog.String("path", path))

		// A hash mismatch of the download names the URL, so the advice
		// to remove the installed file does not apply to it.
		_, err = inst.Install(ctx)
		if err != nil {
			return nil, fmt.Errorf("installing the managed envoy build: %w", err)
		}

		f, err = inst.Open()
	}

	if errors.Is(err, envoybin.ErrHashMismatch) {
		return nil, fmt.Errorf(
			"checking the managed envoy binary: %w: "+
				"inspect the file, remove it, and run `terrarium envoy install`", err)
	}

	if err != nil {
		return nil, fmt.Errorf("checking the managed envoy binary: %w", err)
	}

	return &envoyBinary{file: f, path: path}, nil
}

// command returns the command that runs the binary with args. The
// command has the path of the binary as its first argument.
//
// The command of a managed binary executes the open, hash-checked file
// where the platform allows it. See [execOpenFile].
func (b *envoyBinary) command(ctx context.Context, args ...string) *exec.Cmd {
	//nolint:gosec // G204: the managed build, or the binary that the user names.
	cmd := exec.CommandContext(ctx, b.path, args...)

	if b.file != nil {
		execOpenFile(cmd, b.file)
	}

	return cmd
}

// Close closes the open file of a managed binary. A process that the
// command of the binary started keeps running.
func (b *envoyBinary) Close() error {
	if b.file == nil {
		return nil
	}

	err := b.file.Close()
	if err != nil {
		return fmt.Errorf("closing envoy binary: %w", err)
	}

	return nil
}
