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

// envoyAccessLogDefault returns the default Envoy access log file path.
// It prefers $XDG_RUNTIME_DIR/terrarium/envoy-access.log, falling back
// to the state directory.
func envoyAccessLogDefault() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "terrarium", "envoy-access.log")
	}

	return filepath.Join(userStateDir(), "terrarium", "envoy-access.log")
}
