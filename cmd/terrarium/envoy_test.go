package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/envoybin"
)

// newEnvoyRoot returns a root command that holds the envoy command group.
// Cobra checks the arguments of a nested group differently from those of
// a root command, so the tests run the group the way the CLI nests it.
// The root has the name of the terrarium root command, so the error
// messages name the same command paths as the CLI.
func newEnvoyRoot(inst *envoybin.Installer, out *bytes.Buffer, args ...string) *cobra.Command {
	root := &cobra.Command{Use: newRootCmd().Name(), SilenceUsage: true}
	root.AddCommand(envoyCmd(inst))
	root.SetArgs(append([]string{"envoy"}, args...))
	root.SetOut(out)
	root.SetErr(&bytes.Buffer{})

	return root
}

func TestEnvoyInstallCommand(t *testing.T) {
	t.Parallel()

	binary := []byte("fake envoy")
	sum := sha256.Sum256(binary)
	host := envoybin.HostPlatform()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write(binary)
		assert.NoError(t, err)
	}))
	t.Cleanup(srv.Close)

	manifest := envoybin.Manifest{
		Version: "v9.9.9",
		Builds: map[envoybin.Platform]envoybin.Build{
			host: {
				URL:            srv.URL + "/envoy",
				Format:         envoybin.FormatBinary,
				DownloadSHA256: hex.EncodeToString(sum[:]),
				BinarySHA256:   hex.EncodeToString(sum[:]),
			},
		},
	}

	install := []string{"install"}

	tests := map[string]struct {
		err      error
		platform envoybin.Platform
		msg      string
		wantPath string
		args     []string
	}{
		"host platform": {
			args:     install,
			platform: host,
			wantPath: filepath.Join("v9.9.9", host.String(), "envoy"),
		},
		"platform without a build": {
			args:     install,
			platform: envoybin.Platform{OS: "plan9", Arch: "mips"},
			err:      envoybin.ErrUnsupportedPlatform,
		},
		"mistyped subcommand": {
			args:     []string{"instll"},
			platform: host,
			msg:      `unknown command "instll" for "terrarium envoy"`,
		},
		"argument after install": {
			args:     append(install, "extra"),
			platform: host,
			msg:      `unknown command "extra" for "terrarium envoy install"`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()

			var out bytes.Buffer

			cmd := newEnvoyRoot(envoybin.NewInstaller(dir,
				envoybin.WithManifest(manifest),
				envoybin.WithPlatform(tc.platform),
			), &out, tc.args...)

			err := cmd.ExecuteContext(t.Context())
			if tc.err != nil || tc.msg != "" {
				require.Error(t, err)

				if tc.err != nil {
					require.ErrorIs(t, err, tc.err)
				}

				require.ErrorContains(t, err, tc.msg)
				assert.Empty(t, out.String())
				assert.NoDirExists(t, filepath.Join(dir, "v9.9.9"))

				return
			}

			require.NoError(t, err)
			assert.Equal(t, filepath.Join(dir, tc.wantPath)+"\n", out.String())
			assert.FileExists(t, filepath.Join(dir, tc.wantPath))
		})
	}
}

// writerFunc is a function that implements [io.Writer].
type writerFunc func(p []byte) (int, error)

// Write calls f.
func (f writerFunc) Write(p []byte) (int, error) {
	return f(p)
}

func TestInstallEnvoyPrintFails(t *testing.T) {
	t.Parallel()

	binary := []byte("fake envoy")
	sum := sha256.Sum256(binary)
	host := envoybin.HostPlatform()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := w.Write(binary)
		assert.NoError(t, err)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()

	inst := envoybin.NewInstaller(dir, envoybin.WithManifest(envoybin.Manifest{
		Version: "v9.9.9",
		Builds: map[envoybin.Platform]envoybin.Build{
			host: {
				URL:            srv.URL + "/envoy",
				Format:         envoybin.FormatBinary,
				DownloadSHA256: hex.EncodeToString(sum[:]),
				BinarySHA256:   hex.EncodeToString(sum[:]),
			},
		},
	}))

	errWrite := errors.New("output closed")

	err := installEnvoy(t.Context(), writerFunc(func([]byte) (int, error) {
		return 0, errWrite
	}), inst)
	require.ErrorIs(t, err, errWrite)
	require.ErrorContains(t, err, "print envoy path")

	// The write fails after the install, so the binary is in place.
	path := filepath.Join(dir, "v9.9.9", host.String(), "envoy")

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, binary, data)

	verified, err := inst.Verify()
	require.NoError(t, err)
	assert.Equal(t, path, verified)
}

func TestEnvoyCommandHelp(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer

	cmd := newEnvoyRoot(envoybin.NewInstaller(t.TempDir()), &out)

	require.NoError(t, cmd.ExecuteContext(t.Context()))
	assert.Contains(t, out.String(), "Install the pinned Envoy build")
}

// TestEnvoyInstallDefaultDir checks that the envoy install command of
// the CLI keeps its binaries in $XDG_DATA_HOME/terrarium/envoy. A file
// with a wrong hash at the install path stops the command before a
// download, and the error names the path.
//
//nolint:paralleltest // t.Setenv does not allow a parallel test.
func TestEnvoyInstallDefaultDir(t *testing.T) {
	data := t.TempDir()
	t.Setenv("XDG_DATA_HOME", data)
	t.Setenv("HOME", t.TempDir())

	path, err := envoybin.NewInstaller(filepath.Join(data, "terrarium", "envoy")).Path()
	if errors.Is(err, envoybin.ErrUnsupportedPlatform) {
		t.Skip("no managed envoy build for this host")
	}

	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte("not envoy"), 0o755))

	// The root command replaces the default logger before it runs a
	// command.
	logger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(logger) })

	// The hash check does not read the context. A canceled context
	// keeps a command that looks in another directory from starting a
	// download.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	root := newRootCmd()
	root.SetArgs(strings.Fields("envoy install"))
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)

	err = root.ExecuteContext(ctx)
	require.ErrorIs(t, err, envoybin.ErrHashMismatch)
	require.ErrorContains(t, err, path)
}
