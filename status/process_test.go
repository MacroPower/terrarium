package status_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/status"
)

func TestCollectProcessMissingPIDFile(t *testing.T) {
	t.Parallel()

	opts := status.Options{
		PIDFile: filepath.Join(t.TempDir(), "does-not-exist.pid"),
	}

	r := status.Collect(t.Context(), opts)

	assert.Equal(t, status.DaemonNotRunning, r.Process.Daemon.State)
	assert.False(t, r.Process.Daemon.Stale)
	assert.NoError(t, r.Process.Err)
}

func TestCollectProcessMalformedPIDFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")

	require.NoError(t, os.WriteFile(path, []byte("not-a-pid"), 0o644))

	opts := status.Options{PIDFile: path}

	r := status.Collect(t.Context(), opts)

	assert.Equal(t, status.DaemonUnknown, r.Process.Daemon.State)
	assert.Error(t, r.Process.Err)
}

func TestCollectProcessStalePID(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")

	// Use PID 2^22-1 which is almost certainly not running.
	require.NoError(t, os.WriteFile(path, []byte("4194303"), 0o644))

	opts := status.Options{PIDFile: path}

	r := status.Collect(t.Context(), opts)

	assert.Equal(t, status.DaemonNotRunning, r.Process.Daemon.State)
	assert.True(t, r.Process.Daemon.Stale)
	assert.Equal(t, 4194303, r.Process.Daemon.PID)
}

func TestCollectProcessLiveSelf(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")

	// Use the test's own PID as a stand-in for a live daemon.
	require.NoError(t, os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o644))

	opts := status.Options{PIDFile: path}

	r := status.Collect(t.Context(), opts)

	assert.Equal(t, status.DaemonRunning, r.Process.Daemon.State)
	assert.Equal(t, os.Getpid(), r.Process.Daemon.PID)
	assert.True(t, r.Process.Daemon.UptimeOK)
	// Uptime can round to zero when the process has only been alive
	// for a fraction of a clock tick; require non-negative and a
	// sane upper bound.
	assert.GreaterOrEqual(t, r.Process.Daemon.Uptime, time.Duration(0))
	assert.Less(t, r.Process.Daemon.Uptime, 24*time.Hour)
}

func TestCollectProcessPIDFilePermission(t *testing.T) {
	t.Parallel()

	if os.Getuid() == 0 {
		t.Skip("chmod 000 is ignored by root")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")

	require.NoError(t, os.WriteFile(path, []byte("1234"), 0o644))
	require.NoError(t, os.Chmod(path, 0o000))

	t.Cleanup(func() {
		_ = os.Chmod(path, 0o644)
	})

	opts := status.Options{PIDFile: path}

	r := status.Collect(t.Context(), opts)

	assert.Equal(t, status.DaemonUnknown, r.Process.Daemon.State)
	assert.ErrorIs(t, r.Process.Err, fs.ErrPermission)
}
