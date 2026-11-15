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
)

// ErrVendor means that the command cannot create the vendor tree of the
// module.
var ErrVendor = errors.New("vendor module")

// vendorHash returns the hash that the buildGoModule function of nixpkgs
// requires as vendorHash for the Go module in dir. It is the [narHash] of
// the tree that `go mod vendor` creates.
//
// The function creates the tree in a temporary directory and removes it,
// so it changes nothing in dir. It runs the go command with GOWORK=off,
// because the go command does not vendor one module of a workspace.
func vendorHash(ctx context.Context, dir string) (string, error) {
	tmp, err := os.MkdirTemp("", "vendorhash-")
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrVendor, err)
	}

	defer os.RemoveAll(tmp)

	tree := filepath.Join(tmp, "vendor")

	//nolint:gosec // G204: the go command, and a tree in a new temporary directory.
	cmd := exec.CommandContext(ctx, "go", "mod", "vendor", "-o", tree)
	cmd.Dir = dir

	cmd.Env = append(os.Environ(), "GOWORK=off")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w: go mod vendor: %w: %s", ErrVendor, err, bytes.TrimSpace(output))
	}

	// The go command creates no tree for a module without dependencies.
	_, err = os.Stat(tree)
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("%w: the module in %s has no dependencies", ErrVendor, dir)
	}

	sum, err := narHash(tree)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrVendor, err)
	}

	return sum, nil
}
