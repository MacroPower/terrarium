//go:build linux

package firewall_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/firewall"
	"go.jacobcolvin.com/terrarium/sysctl"
)

// writeSysctl creates the file of a kernel parameter under root.
func writeSysctl(t *testing.T, root, param, value string) {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(param))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(value), 0o644))
}

// readSysctl returns the content of the file of a kernel parameter
// under root.
func readSysctl(t *testing.T, root, param string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(param)))
	require.NoError(t, err)

	return string(data)
}

func TestSetupForwardRouting(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// defaultRPFilter is the value that the host gives new
		// interfaces.
		defaultRPFilter string
	}{
		"default rp_filter off":    {defaultRPFilter: "0\n"},
		"default rp_filter strict": {defaultRPFilter: "1\n"},
		"default rp_filter loose":  {defaultRPFilter: "2\n"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			writeSysctl(t, root, "net/ipv4/conf/all/route_localnet", "0\n")
			// SetupPolicyRouting leaves loose mode for all
			// interfaces.
			writeSysctl(t, root, "net/ipv4/conf/all/rp_filter", "2\n")
			writeSysctl(t, root, "net/ipv4/conf/default/rp_filter", tc.defaultRPFilter)

			err := firewall.SetupForwardRouting(t.Context(), sysctl.New(sysctl.WithProcRoot(root)))
			require.NoError(t, err)

			assert.Equal(t, "1", readSysctl(t, root, "net/ipv4/conf/all/route_localnet"))
			assert.Equal(t, "0", readSysctl(t, root, "net/ipv4/conf/all/rp_filter"))

			// The host owns the value of new interfaces.
			assert.Equal(t, tc.defaultRPFilter, readSysctl(t, root, "net/ipv4/conf/default/rp_filter"))
		})
	}
}

func TestSetupForwardRouting_MissingParameter(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// params are the kernel parameters that exist.
		params []string
	}{
		"no all directory": {
			params: []string{"net/ipv4/conf/default/rp_filter"},
		},
		"no default rp_filter": {
			params: []string{
				"net/ipv4/conf/all/route_localnet",
				"net/ipv4/conf/all/rp_filter",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			for _, param := range tc.params {
				writeSysctl(t, root, param, "0\n")
			}

			err := firewall.SetupForwardRouting(t.Context(), sysctl.New(sysctl.WithProcRoot(root)))
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestSetupForwardRouting_InvalidDefault(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeSysctl(t, root, "net/ipv4/conf/all/route_localnet", "0\n")
	writeSysctl(t, root, "net/ipv4/conf/all/rp_filter", "2\n")
	writeSysctl(t, root, "net/ipv4/conf/default/rp_filter", "loose\n")

	err := firewall.SetupForwardRouting(t.Context(), sysctl.New(sysctl.WithProcRoot(root)))
	require.ErrorContains(t, err, "reading default rp_filter")
}
