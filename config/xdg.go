package config

import (
	"os"
	"path/filepath"
)

const defaultHome = "/home/dev"

// userHomeDir returns the user's home directory via [os.UserHomeDir],
// falling back to [defaultHome] on error.
func userHomeDir() string {
	d, err := os.UserHomeDir()
	if err == nil {
		return d
	}

	return defaultHome
}

// userConfigDir returns the user's config directory via [os.UserConfigDir],
// falling back to $HOME/.config.
func userConfigDir() string {
	d, err := os.UserConfigDir()
	if err == nil {
		return d
	}

	return filepath.Join(userHomeDir(), ".config")
}

// userDataDir returns $XDG_DATA_HOME, falling back to $HOME/.local/share.
func userDataDir() string {
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return d
	}

	return filepath.Join(userHomeDir(), ".local", "share")
}

// userStateDir returns $XDG_STATE_HOME, falling back to $HOME/.local/state.
func userStateDir() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return d
	}

	return filepath.Join(userHomeDir(), ".local", "state")
}

// envoyConfigDefault returns the default Envoy config output path.
// It prefers $XDG_RUNTIME_DIR/terrarium/envoy.yaml, falling back to
// the state directory.
func envoyConfigDefault() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "terrarium", "envoy.yaml")
	}

	return filepath.Join(userStateDir(), "terrarium", "envoy.yaml")
}

// envoyLogDefault returns the default Envoy process log file path.
// It prefers $XDG_RUNTIME_DIR/terrarium/envoy.log, falling back to
// the state directory.
func envoyLogDefault() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "terrarium", "envoy.log")
	}

	return filepath.Join(userStateDir(), "terrarium", "envoy.log")
}

// ProxyEnvoyLogDefault returns the default Envoy process log path of
// the proxy that has the name instance. The path is the file
// envoy-proxy-<instance>.log in the directory of the container-mode
// log. That directory is $XDG_RUNTIME_DIR/terrarium, or the state
// directory when XDG_RUNTIME_DIR is not set. Each proxy name
// therefore has its own log file, which container mode does not write.
//
// The instance argument must be one path element.
func ProxyEnvoyLogDefault(instance string) string {
	return filepath.Join(filepath.Dir(envoyLogDefault()), "envoy-proxy-"+instance+".log")
}

// StatsDBDefault returns the default SQLite event store path. It
// follows XDG conventions ($XDG_DATA_HOME/terrarium/stats.db) so the
// store sits alongside the CA and certs directories.
func StatsDBDefault() string {
	return filepath.Join(userDataDir(), "terrarium", "stats.db")
}

// ProxyStatsSocketDefault returns the default gRPC ALS socket path for
// proxy mode. It prefers $XDG_RUNTIME_DIR/terrarium/accesslog.sock and
// falls back to the state directory, so the user who runs the proxy
// can create the socket without root. Container mode uses
// [DefaultStatsSocket].
func ProxyStatsSocketDefault() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "terrarium", "accesslog.sock")
	}

	return filepath.Join(userStateDir(), "terrarium", "accesslog.sock")
}

// EnvoyDirDefault returns the default directory for managed Envoy
// binaries, $XDG_DATA_HOME/terrarium/envoy. The directory has the same
// parent as the CA directory, so one sandbox rule can cover both.
func EnvoyDirDefault() string {
	return filepath.Join(userDataDir(), "terrarium", "envoy")
}
