//go:build linux

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
				"envoy-uid", "exclude-dns-uids", "gid", "home-dir",
				"ready-file", "uid", "username",
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
