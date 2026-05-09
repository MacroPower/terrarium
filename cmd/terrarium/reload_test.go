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

func TestValidateStartupOnlyStatsChanges(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		bound boundStats
		cfg   *config.Config
		want  error
	}{
		"stats disabled, group differs, no error": {
			bound: boundStats{enabled: false, nflogGroup: 5000},
			cfg: &config.Config{
				Stats: &config.Stats{
					Enabled:  false,
					Firewall: &config.StatsFirewall{NFLogGroup: 6000},
				},
			},
			want: nil,
		},
		"stats enabled, group matches, no error": {
			bound: boundStats{enabled: true, nflogGroup: 5000},
			cfg: &config.Config{
				Stats: &config.Stats{
					Enabled:  true,
					Firewall: &config.StatsFirewall{NFLogGroup: 5000},
				},
			},
			want: nil,
		},
		"stats enabled, group changed, error": {
			bound: boundStats{enabled: true, nflogGroup: 5000},
			cfg: &config.Config{
				Stats: &config.Stats{
					Enabled:  true,
					Firewall: &config.StatsFirewall{NFLogGroup: 7000},
				},
			},
			want: ErrReloadNFLogGroupChanged,
		},
		"stats enabled, default vs explicit default match": {
			bound: boundStats{enabled: true, nflogGroup: config.DefaultStatsFirewallNFLogGroup},
			cfg: &config.Config{
				Stats: &config.Stats{Enabled: true},
			},
			want: nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := validateStartupOnlyStatsChanges(t.Context(), tt.bound, tt.cfg)
			if tt.want != nil {
				require.ErrorIs(t, err, tt.want)
			} else {
				require.NoError(t, err)
			}
		})
	}
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
