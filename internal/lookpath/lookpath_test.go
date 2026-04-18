package lookpath_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/internal/lookpath"
)

// TestFindSlashAndEmpty covers cases that do not read PATH so they
// can run in parallel.
func TestFindSlashAndEmpty(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	bin := filepath.Join(dir, "myprog")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755))

	tests := map[string]struct {
		input     string
		wantPath  string
		wantErr   bool
		errSubstr string
	}{
		"absolute-executable": {
			input:    bin,
			wantPath: bin,
		},
		"relative-with-slash-missing": {
			input:     "./does-not-exist",
			wantErr:   true,
			errSubstr: "does-not-exist",
		},
		"empty-name": {
			input:   "",
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := lookpath.Find(tc.input)

			if tc.wantErr {
				require.Error(t, err)

				if tc.errSubstr != "" {
					assert.Contains(t, err.Error(), tc.errSubstr)
				}

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantPath, got)
		})
	}
}

// TestFindViaPATH mutates PATH via t.Setenv and therefore cannot run
// in parallel.
//
//nolint:paralleltest // t.Setenv is not compatible with t.Parallel.
func TestFindViaPATH(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "myprog")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755))

	t.Setenv("PATH", dir)

	got, err := lookpath.Find("myprog")
	require.NoError(t, err)
	assert.Equal(t, bin, got)

	_, err = lookpath.Find("nonexistent-prog")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in PATH")
}
