package main

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// busyBinary writes a shell script that exits with status 7. It returns
// the path of the script and a descriptor that holds the script open
// for writing. The script is busy until the caller closes the
// descriptor, and the test closes the descriptor when it ends.
func busyBinary(t *testing.T) (string, *os.File) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "envoy")
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nexit 7\n"), 0o755))

	w, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // test fixture path.
	require.NoError(t, err)
	t.Cleanup(func() {
		w.Close() //nolint:errcheck,gosec // the caller might have closed it.
	})

	return path, w
}

// TestStartEnvoyWhenFree checks how often [startEnvoyWhenFree] starts a
// command. Only a busy binary makes it start a command again.
func TestStartEnvoyWhenFree(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// binary returns the path of the binary that every command
		// executes.
		binary func(t *testing.T) string
		// err is the error that the start must wrap.
		err error
		// want is the number of commands that the function starts.
		want int
	}{
		"free binary": {
			binary: func(*testing.T) string { return "true" },
			want:   1,
		},
		"missing binary": {
			binary: func(t *testing.T) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "missing")
			},
			err:  fs.ErrNotExist,
			want: 1,
		},
		"binary that stays busy": {
			binary: func(t *testing.T) string {
				t.Helper()

				path, _ := busyBinary(t)

				return path
			},
			err:  syscall.ETXTBSY,
			want: 1 + busyStartRetries,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			binary := tt.binary(t)

			var starts int

			proc, err := startEnvoyWhenFree(t.Context(), func() *exec.Cmd {
				starts++

				return exec.CommandContext(t.Context(), binary)
			})

			assert.Equal(t, tt.want, starts)

			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				assert.Nil(t, proc)

				return
			}

			require.NoError(t, err)
			require.NoError(t, proc.wait())
		})
	}
}

// TestStartEnvoyWhenFreeAfterRelease checks that [startEnvoyWhenFree]
// runs a binary that is busy during its first starts.
func TestStartEnvoyWhenFreeAfterRelease(t *testing.T) {
	t.Parallel()

	path, w := busyBinary(t)

	// The number of the start before which the binary becomes free.
	const release = 3

	var starts int

	proc, err := startEnvoyWhenFree(t.Context(), func() *exec.Cmd {
		starts++

		if starts == release {
			require.NoError(t, w.Close())
		}

		return exec.CommandContext(t.Context(), path)
	})
	require.NoError(t, err)

	// A child process of another test can hold the descriptor for a
	// moment after the close. A later start can therefore be the first
	// one that runs the binary.
	assert.GreaterOrEqual(t, starts, release)

	var exitErr *exec.ExitError

	require.ErrorAs(t, proc.wait(), &exitErr)
	assert.Equal(t, 7, exitErr.ExitCode())
}

// TestStartEnvoyWhenFreeCanceled checks that [startEnvoyWhenFree]
// returns the error of its context when the context ends during the
// pause after the start of a busy binary.
func TestStartEnvoyWhenFreeCanceled(t *testing.T) {
	t.Parallel()

	path, _ := busyBinary(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	proc, err := startEnvoyWhenFree(ctx, func() *exec.Cmd {
		cancel()

		// The command has the context of the test, so the canceled
		// context does not keep it from the start.
		return exec.CommandContext(t.Context(), path)
	})
	require.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, proc)
}
