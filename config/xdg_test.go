package config_test

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"go.jacobcolvin.com/terrarium/config"
)

// These tests use t.Setenv, which is incompatible with t.Parallel().

func TestRegisterFlagsXDGDefaults(t *testing.T) {
	tests := map[string]struct {
		env  map[string]string
		want map[string]string
	}{
		"all XDG vars set": {
			env: map[string]string{
				"HOME":            "/home/user",
				"XDG_CONFIG_HOME": "/custom/config",
				"XDG_DATA_HOME":   "/custom/data",
				"XDG_STATE_HOME":  "/custom/state",
				"XDG_RUNTIME_DIR": "/run/user/1000",
			},
			want: map[string]string{
				"config":       "/custom/config/terrarium/config.yaml",
				"certs-dir":    "/custom/data/terrarium/certs",
				"ca-dir":       "/custom/data/terrarium/ca",
				"envoy-config": "/run/user/1000/terrarium/envoy.yaml",
			},
		},
		"HOME only": {
			env: map[string]string{
				"HOME":            "/home/user",
				"XDG_CONFIG_HOME": "",
				"XDG_DATA_HOME":   "",
				"XDG_STATE_HOME":  "",
				"XDG_RUNTIME_DIR": "",
			},
			want: map[string]string{
				"config":       "/home/user/.config/terrarium/config.yaml",
				"certs-dir":    "/home/user/.local/share/terrarium/certs",
				"ca-dir":       "/home/user/.local/share/terrarium/ca",
				"envoy-config": "/home/user/.local/state/terrarium/envoy.yaml",
			},
		},
		"nothing set": {
			env: map[string]string{
				"HOME":            "",
				"XDG_CONFIG_HOME": "",
				"XDG_DATA_HOME":   "",
				"XDG_STATE_HOME":  "",
				"XDG_RUNTIME_DIR": "",
			},
			want: map[string]string{
				"config":       "/home/dev/.config/terrarium/config.yaml",
				"certs-dir":    "/home/dev/.local/share/terrarium/certs",
				"ca-dir":       "/home/dev/.local/share/terrarium/ca",
				"envoy-config": "/home/dev/.local/state/terrarium/envoy.yaml",
			},
		},
		"runtime dir falls back to state dir": {
			env: map[string]string{
				"HOME":            "/home/user",
				"XDG_CONFIG_HOME": "",
				"XDG_DATA_HOME":   "",
				"XDG_STATE_HOME":  "/custom/state",
				"XDG_RUNTIME_DIR": "",
			},
			want: map[string]string{
				"envoy-config": "/custom/state/terrarium/envoy.yaml",
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			u := config.NewUser()
			fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
			u.RegisterFlags(fs)

			for flag, want := range tt.want {
				f := fs.Lookup(flag)
				if assert.NotNilf(t, f, "flag %q not found", flag) {
					assert.Equal(t, want, f.DefValue, "flag %q", flag)
				}
			}
		})
	}
}

func TestProxyStatsSocketDefault(t *testing.T) {
	tests := map[string]struct {
		env  map[string]string
		want string
	}{
		"runtime dir set": {
			env: map[string]string{
				"HOME":            "/home/user",
				"XDG_STATE_HOME":  "/custom/state",
				"XDG_RUNTIME_DIR": "/run/user/1000",
			},
			want: "/run/user/1000/terrarium/accesslog.sock",
		},
		"runtime dir falls back to state dir": {
			env: map[string]string{
				"HOME":            "/home/user",
				"XDG_STATE_HOME":  "/custom/state",
				"XDG_RUNTIME_DIR": "",
			},
			want: "/custom/state/terrarium/accesslog.sock",
		},
		"HOME only": {
			env: map[string]string{
				"HOME":            "/Users/user",
				"XDG_STATE_HOME":  "",
				"XDG_RUNTIME_DIR": "",
			},
			want: "/Users/user/.local/state/terrarium/accesslog.sock",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			assert.Equal(t, tt.want, config.ProxyStatsSocketDefault())
		})
	}
}

func TestProxyEnvoyLogDefault(t *testing.T) {
	tests := map[string]struct {
		env      map[string]string
		instance string
		want     string
	}{
		"runtime dir set": {
			env: map[string]string{
				"HOME":            "/home/user",
				"XDG_STATE_HOME":  "/custom/state",
				"XDG_RUNTIME_DIR": "/run/user/1000",
			},
			instance: "127.0.0.1-8080",
			want:     "/run/user/1000/terrarium/envoy-proxy-127.0.0.1-8080.log",
		},
		"another instance": {
			env: map[string]string{
				"HOME":            "/home/user",
				"XDG_STATE_HOME":  "/custom/state",
				"XDG_RUNTIME_DIR": "/run/user/1000",
			},
			instance: "::1-3128",
			want:     "/run/user/1000/terrarium/envoy-proxy-::1-3128.log",
		},
		"runtime dir falls back to state dir": {
			env: map[string]string{
				"HOME":            "/home/user",
				"XDG_STATE_HOME":  "/custom/state",
				"XDG_RUNTIME_DIR": "",
			},
			instance: "127.0.0.1-8080",
			want:     "/custom/state/terrarium/envoy-proxy-127.0.0.1-8080.log",
		},
		"HOME only": {
			env: map[string]string{
				"HOME":            "/Users/user",
				"XDG_STATE_HOME":  "",
				"XDG_RUNTIME_DIR": "",
			},
			instance: "127.0.0.1-8080",
			want:     "/Users/user/.local/state/terrarium/envoy-proxy-127.0.0.1-8080.log",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			u := config.NewUser()
			fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
			u.RegisterFlags(fs)

			got := config.ProxyEnvoyLogDefault(tt.instance)
			assert.Equal(t, tt.want, got)

			// Container mode keeps its own log file.
			assert.NotEqual(t, fs.Lookup("envoy-log").DefValue, got)
		})
	}
}

func TestEnvoyDirDefault(t *testing.T) {
	tests := map[string]struct {
		env  map[string]string
		want string
	}{
		"XDG_DATA_HOME set": {
			env:  map[string]string{"HOME": "/home/user", "XDG_DATA_HOME": "/custom/data"},
			want: "/custom/data/terrarium/envoy",
		},
		"HOME only": {
			env:  map[string]string{"HOME": "/home/user", "XDG_DATA_HOME": ""},
			want: "/home/user/.local/share/terrarium/envoy",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			assert.Equal(t, tt.want, config.EnvoyDirDefault())
		})
	}
}
