package privdrop

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLookPath(t *testing.T) { //nolint:tparallel // subtests use t.Setenv which conflicts with t.Parallel
	t.Run("absolute path", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		bin := filepath.Join(dir, "mybin")

		err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755)
		require.NoError(t, err)

		got, err := lookPath(bin)
		require.NoError(t, err)
		assert.Equal(t, bin, got)
	})

	t.Run("found in PATH", func(t *testing.T) {
		dir := t.TempDir()
		bin := filepath.Join(dir, "mybin")

		err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755)
		require.NoError(t, err)

		t.Setenv("PATH", dir)

		got, err := lookPath("mybin")
		require.NoError(t, err)
		assert.Equal(t, bin, got)
	})

	t.Run("not found", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())

		_, err := lookPath("nonexistent-binary-xyz")
		require.Error(t, err)
	})
}
