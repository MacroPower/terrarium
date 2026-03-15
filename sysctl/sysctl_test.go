package sysctl_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/sysctl"
)

// writeParam creates a parameter file under root and writes value to it.
func writeParam(t *testing.T, root string, param []string, value string) {
	t.Helper()

	p := filepath.Join(append([]string{root}, param...)...)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(value), 0o644))
}

// readParam reads the raw contents of a parameter file under root.
func readParam(t *testing.T, root string, param []string) string {
	t.Helper()

	p := filepath.Join(append([]string{root}, param...)...)
	data, err := os.ReadFile(p)
	require.NoError(t, err)

	return string(data)
}

func TestRead(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		param []string
		value string
		want  string
	}{
		"simple value": {
			param: []string{"net", "ipv4", "ip_forward"},
			value: "1\n",
			want:  "1",
		},
		"value with trailing space": {
			param: []string{"net", "ipv4", "ip_forward"},
			value: "0 \n",
			want:  "0",
		},
		"multi-word value": {
			param: []string{"net", "ipv4", "ping_group_range"},
			value: "0 1000\n",
			want:  "0 1000",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			writeParam(t, root, tc.param, tc.value)

			sys := sysctl.New(sysctl.WithProcRoot(root))
			got, err := sys.Read(tc.param...)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestReadNotExist(t *testing.T) {
	t.Parallel()

	sys := sysctl.New(sysctl.WithProcRoot(t.TempDir()))
	_, err := sys.Read("net", "ipv4", "nonexistent")
	require.Error(t, err)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestReadInt(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	param := []string{"net", "ipv4", "ip_forward"}
	writeParam(t, root, param, "42\n")

	sys := sysctl.New(sysctl.WithProcRoot(root))
	got, err := sys.ReadInt(param...)
	require.NoError(t, err)
	assert.Equal(t, int64(42), got)
}

func TestWrite(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		param []string
		value string
	}{
		"boolean flag": {
			param: []string{"net", "ipv6", "conf", "all", "disable_ipv6"},
			value: "1",
		},
		"range value": {
			param: []string{"net", "ipv4", "ping_group_range"},
			value: "0 1000",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			// Create parent directories.
			p := filepath.Join(append([]string{root}, tc.param...)...)
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))

			sys := sysctl.New(sysctl.WithProcRoot(root))
			require.NoError(t, sys.Write(tc.value, tc.param...))
			assert.Equal(t, tc.value, readParam(t, root, tc.param))
		})
	}
}

func TestWriteNotExist(t *testing.T) {
	t.Parallel()

	sys := sysctl.New(sysctl.WithProcRoot(t.TempDir()))
	err := sys.Write("1", "no", "such", "dir", "param")
	require.Error(t, err)
	assert.True(t, errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission))
}

func TestWriteInt(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	param := []string{"net", "ipv4", "ip_forward"}
	p := filepath.Join(append([]string{root}, param...)...)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))

	sys := sysctl.New(sysctl.WithProcRoot(root))
	require.NoError(t, sys.WriteInt(99, param...))
	assert.Equal(t, "99", readParam(t, root, param))
}

func TestEnable(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	param := []string{"net", "ipv6", "conf", "all", "disable_ipv6"}
	p := filepath.Join(append([]string{root}, param...)...)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))

	sys := sysctl.New(sysctl.WithProcRoot(root))
	require.NoError(t, sys.Enable(param...))
	assert.Equal(t, "1", readParam(t, root, param))
}

func TestDisable(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	param := []string{"net", "ipv6", "conf", "all", "disable_ipv6"}
	p := filepath.Join(append([]string{root}, param...)...)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))

	sys := sysctl.New(sysctl.WithProcRoot(root))
	require.NoError(t, sys.Disable(param...))
	assert.Equal(t, "0", readParam(t, root, param))
}
