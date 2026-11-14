//go:build linux

package main

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLinuxCommandUserFlags names each test case after the command
// path that it inspects.
func TestLinuxCommandUserFlags(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		want []string
	}{
		"terrarium init": {
			want: []string{
				"ca-dir", "certs-dir", "config", "envoy-config", "envoy-log",
				"envoy-uid", "exclude-dns-uids", "gid", "ready-file", "uid",
			},
		},
		"terrarium daemon": {
			want: []string{
				"ca-dir", "certs-dir", "config", "envoy-config", "envoy-log",
				"envoy-uid", "exclude-dns-uids", "ready-file", "uid",
			},
		},
		"terrarium daemon reload": {
			want: []string{"config"},
		},
		"terrarium status": {
			want: []string{"config", "envoy-config", "envoy-log"},
		},
	}

	for command, tt := range tests {
		t.Run(command, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, userFlagsOf(t, command))
		})
	}
}

// TestLinuxCommandRejectsUnreadFlags names each test case after the
// command line that it runs. Every command line ends with --help, so
// that a command that accepts the flag prints its help and returns
// before its body runs. The bodies of the init and daemon commands
// load the firewall.
func TestLinuxCommandRejectsUnreadFlags(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err string
	}{
		"init --username=dev --help":       {err: "unknown flag: --username"},
		"init --home-dir=/home/dev --help": {err: "unknown flag: --home-dir"},
		"daemon --gid=1000 --help":         {err: "unknown flag: --gid"},
	}

	for line, tt := range tests {
		t.Run(line, func(t *testing.T) {
			t.Parallel()

			// Cobra reports the unknown flag before it acts on --help.
			// Discard the usage text that cobra prints for a flag error.
			root := newRootCmd()
			root.SetArgs(strings.Fields(line))
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)

			err := root.ExecuteContext(t.Context())
			require.ErrorContains(t, err, tt.err)
		})
	}
}
