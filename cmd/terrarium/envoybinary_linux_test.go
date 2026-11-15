package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnvoyBinaryCommandRunsCheckedFile checks that the command of a
// managed binary runs the file that [resolveEnvoy] hashed. Another file
// takes the install path between the hash check and the start of the
// command.
func TestEnvoyBinaryCommandRunsCheckedFile(t *testing.T) {
	t.Parallel()

	out := filepath.Join(t.TempDir(), "out")

	// script returns a program that writes word to the out file. It
	// runs only shell builtins, so it does not depend on PATH.
	script := func(word string) []byte {
		return []byte("#!/bin/sh\necho " + word + " > '" + out + "'\n")
	}

	inst, path, _ := managedEnvoyInstaller(t, script("checked"))

	bin, err := resolveEnvoy(t.Context(), inst, "")
	require.NoError(t, err)
	closeEnvoyBinary(t, bin)

	// A rename puts another file at the install path. A write to the
	// path changes the checked file itself.
	other := filepath.Join(filepath.Dir(path), "other")
	require.NoError(t, os.WriteFile(other, script("replaced"), 0o755))
	require.NoError(t, os.Rename(other, path))

	cmd := bin.command(t.Context())
	require.NoError(t, cmd.Run())

	data, err := os.ReadFile(out) //nolint:gosec // test fixture path.
	require.NoError(t, err)
	assert.Equal(t, "checked\n", string(data))

	// The command line of the process names the install path.
	assert.Equal(t, []string{path}, cmd.Args)
}
