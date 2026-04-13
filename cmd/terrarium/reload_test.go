package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
)

func TestWritePIDFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "test.pid")

	err := writePIDFile(path)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	pid, err := strconv.Atoi(string(data))
	require.NoError(t, err)
	assert.Equal(t, os.Getpid(), pid)
}

func TestDaemonReloadRequiresRoot(t *testing.T) {
	t.Parallel()

	if os.Getuid() == 0 {
		t.Skip("test requires non-root")
	}

	usr := config.NewUser()
	err := DaemonReload(t.Context(), usr, "/nonexistent.pid")
	require.ErrorIs(t, err, ErrNotRoot)
}

func TestDaemonReloadInvalidConfig(t *testing.T) {
	t.Parallel()

	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	err := os.WriteFile(configPath, []byte("invalid: [yaml: {{{"), 0o644)
	require.NoError(t, err)

	usr := config.NewUser()
	usr.ConfigPath = configPath

	err = DaemonReload(t.Context(), usr, filepath.Join(dir, "test.pid"))
	assert.ErrorContains(t, err, "parsing config")
}

func TestDaemonReloadMissingPIDFile(t *testing.T) {
	t.Parallel()

	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	// Write a valid minimal config (empty egress = unrestricted).
	err := os.WriteFile(configPath, []byte("{}"), 0o644)
	require.NoError(t, err)

	usr := config.NewUser()
	usr.ConfigPath = configPath

	err = DaemonReload(t.Context(), usr, filepath.Join(dir, "nonexistent.pid"))
	assert.ErrorContains(t, err, "reading PID file")
}

func TestDaemonReloadStalePID(t *testing.T) {
	t.Parallel()

	if os.Getuid() != 0 {
		t.Skip("test requires root")
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	err := os.WriteFile(configPath, []byte("{}"), 0o644)
	require.NoError(t, err)

	pidPath := filepath.Join(dir, "test.pid")

	// Use PID 2^22-1 which is almost certainly not running.
	err = os.WriteFile(pidPath, []byte("4194303"), 0o644)
	require.NoError(t, err)

	usr := config.NewUser()
	usr.ConfigPath = configPath

	err = DaemonReload(t.Context(), usr, pidPath)
	require.ErrorIs(t, err, ErrDaemonNotRunning)
}
