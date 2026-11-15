package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoybin"
)

// managedEnvoyInstaller returns an installer whose build for the host
// is binary, which a local HTTP server offers for download. It also
// returns the install path of the binary and the number of downloads
// that the server answered.
func managedEnvoyInstaller(t *testing.T, binary []byte) (*envoybin.Installer, string, *atomic.Int64) {
	t.Helper()

	var requests atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)

		_, err := w.Write(binary)
		assert.NoError(t, err)
	}))
	t.Cleanup(srv.Close)

	sum := sha256.Sum256(binary)

	inst := envoybin.NewInstaller(t.TempDir(), envoybin.WithManifest(envoybin.Manifest{
		Version: "v9.9.9",
		Builds: map[envoybin.Platform]envoybin.Build{
			envoybin.HostPlatform(): {
				URL:            srv.URL + "/envoy",
				Format:         envoybin.FormatBinary,
				DownloadSHA256: hex.EncodeToString(sum[:]),
				BinarySHA256:   hex.EncodeToString(sum[:]),
			},
		},
	}))

	path, err := inst.Path()
	require.NoError(t, err)

	return inst, path, &requests
}

// closeEnvoyBinary closes bin when the test ends.
func closeEnvoyBinary(t *testing.T, bin *envoyBinary) {
	t.Helper()

	t.Cleanup(func() {
		assert.NoError(t, bin.Close())
	})
}

// changeByte flips one bit in the middle of the file at path and
// returns the new content.
func changeByte(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec // test fixture path.
	require.NoError(t, err)

	data[len(data)/2] ^= 0x01

	require.NoError(t, os.WriteFile(path, data, 0o755)) //nolint:gosec // G306: an executable.

	return data
}

func TestResolveEnvoyManaged(t *testing.T) {
	t.Parallel()

	binary := []byte("#!/bin/sh\necho fake envoy\n")
	inst, path, requests := managedEnvoyInstaller(t, binary)

	// The first call installs the missing build, and the second call
	// finds it.
	for range 2 {
		bin, err := resolveEnvoy(t.Context(), inst, "")
		require.NoError(t, err)
		closeEnvoyBinary(t, bin)

		assert.Equal(t, path, bin.path)
		require.NotNil(t, bin.file, "a managed binary keeps its checked file open")
		assert.Equal(t, path, bin.file.Name())
		assert.Equal(t, int64(1), requests.Load())
	}

	data, err := os.ReadFile(path) //nolint:gosec // test fixture path.
	require.NoError(t, err)
	assert.Equal(t, binary, data)
}

func TestResolveEnvoyManagedChanged(t *testing.T) {
	t.Parallel()

	inst, path, requests := managedEnvoyInstaller(t, []byte("#!/bin/sh\necho fake envoy\n"))

	_, err := inst.Install(t.Context())
	require.NoError(t, err)

	changed := changeByte(t, path)

	bin, err := resolveEnvoy(t.Context(), inst, "")
	require.ErrorIs(t, err, envoybin.ErrHashMismatch)
	require.ErrorContains(t, err, path)
	require.ErrorContains(t, err, "remove it, and run `terrarium envoy install`")
	assert.Nil(t, bin)

	// The proxy does not replace the changed binary.
	assert.Equal(t, int64(1), requests.Load())

	data, err := os.ReadFile(path) //nolint:gosec // test fixture path.
	require.NoError(t, err)
	assert.Equal(t, changed, data)
}

func TestResolveEnvoyManagedUnreadable(t *testing.T) {
	t.Parallel()

	inst, path, requests := managedEnvoyInstaller(t, []byte("managed envoy"))

	// A directory at the install path opens, but the hash cannot read it.
	require.NoError(t, os.MkdirAll(path, 0o755))

	bin, err := resolveEnvoy(t.Context(), inst, "")
	require.ErrorContains(t, err, "checking the managed envoy binary")
	require.ErrorContains(t, err, path)
	require.NotErrorIs(t, err, envoybin.ErrHashMismatch)
	assert.NotContains(t, err.Error(), "terrarium envoy install")
	assert.Nil(t, bin)

	// The proxy installs nothing over a file that it cannot check.
	assert.Zero(t, requests.Load())
	assert.DirExists(t, path)
}

func TestResolveEnvoyManagedErrors(t *testing.T) {
	t.Parallel()

	binary := []byte("#!/bin/sh\necho fake envoy\n")
	sum := sha256.Sum256(binary)
	host := envoybin.HostPlatform()

	tests := map[string]struct {
		platform envoybin.Platform
		err      error
		// status is the status of the download response.
		status int
		// body is the body of the download response.
		body []byte
		msg  string
		// noMsg is text that the error must not hold.
		noMsg string
		// wantRequests is the number of downloads.
		wantRequests int64
	}{
		"host without a managed build": {
			platform: envoybin.Platform{OS: "plan9", Arch: "mips"},
			err:      envoybin.ErrUnsupportedPlatform,
			status:   http.StatusOK,
			body:     binary,
			msg:      "plan9-mips: set --envoy-path or the envoy.path config key",
		},
		"download does not complete": {
			platform:     host,
			err:          envoybin.ErrDownload,
			status:       http.StatusInternalServerError,
			msg:          "installing the managed envoy build",
			wantRequests: 1,
		},
		// The advice to remove the installed file does not fit a
		// download, which leaves no file.
		"download has another hash": {
			platform:     host,
			err:          envoybin.ErrHashMismatch,
			status:       http.StatusOK,
			body:         []byte("not envoy"),
			msg:          "installing the managed envoy build",
			noMsg:        "terrarium envoy install",
			wantRequests: 1,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var requests atomic.Int64

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(tt.status)

				_, err := w.Write(tt.body)
				assert.NoError(t, err)
			}))
			t.Cleanup(srv.Close)

			dir := t.TempDir()

			inst := envoybin.NewInstaller(dir,
				envoybin.WithPlatform(tt.platform),
				envoybin.WithManifest(envoybin.Manifest{
					Version: "v9.9.9",
					Builds: map[envoybin.Platform]envoybin.Build{
						host: {
							URL:            srv.URL + "/envoy",
							Format:         envoybin.FormatBinary,
							DownloadSHA256: hex.EncodeToString(sum[:]),
							BinarySHA256:   hex.EncodeToString(sum[:]),
						},
					},
				}),
			)

			bin, err := resolveEnvoy(t.Context(), inst, "")
			require.ErrorIs(t, err, tt.err)
			require.ErrorContains(t, err, tt.msg)
			assert.Nil(t, bin)

			if tt.noMsg != "" {
				assert.NotContains(t, err.Error(), tt.noMsg)
			}

			assert.Equal(t, tt.wantRequests, requests.Load())

			// The install leaves no binary and no temporary file in
			// the directory of any platform.
			files, err := filepath.Glob(filepath.Join(dir, "*", "*", "*"))
			require.NoError(t, err)
			assert.Empty(t, files)
		})
	}
}

// TestResolveEnvoyOverride replaces the default logger, which is
// incompatible with t.Parallel().
//
//nolint:paralleltest,tparallel // see comment above.
func TestResolveEnvoyOverride(t *testing.T) {
	dir := t.TempDir()

	executable := filepath.Join(dir, "custom-envoy")
	require.NoError(t, os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o755))

	// The file has no execute permission.
	data := filepath.Join(dir, "data")
	require.NoError(t, os.WriteFile(data, []byte("#!/bin/sh\n"), 0o644))

	// The shell is a command that every PATH of a test host holds.
	shell, err := exec.LookPath("sh")
	require.NoError(t, err)

	tests := map[string]struct {
		override string
		want     string
		err      bool
	}{
		"path of an executable": {
			override: executable,
			want:     executable,
		},
		"command on PATH": {
			override: "sh",
			want:     shell,
		},
		"command that PATH does not hold": {
			override: "terrarium-test-no-such-envoy",
			err:      true,
		},
		"path without a file": {
			override: filepath.Join(dir, "missing"),
			err:      true,
		},
		"path of a file that is not executable": {
			override: data,
			err:      true,
		},
		// PATH does not apply to a name with a path separator.
		"path that ends in a command on PATH": {
			override: filepath.Join(dir, "sh"),
			err:      true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			logs := captureLogs(t)

			inst, installPath, requests := managedEnvoyInstaller(t, []byte("managed envoy"))

			bin, err := resolveEnvoy(t.Context(), inst, tt.override)

			// An override keeps the proxy from installing the managed
			// build.
			assert.Zero(t, requests.Load())
			assert.NoFileExists(t, installPath)

			if tt.err {
				require.ErrorIs(t, err, ErrEnvoyNotFound)
				require.ErrorContains(t, err, tt.override)
				assert.Nil(t, bin)
				assert.NotContains(t, logs.String(), "unpinned")

				return
			}

			require.NoError(t, err)
			closeEnvoyBinary(t, bin)

			assert.Equal(t, tt.want, bin.path)
			assert.Nil(t, bin.file, "an unpinned binary has no checked file")

			out := logs.String()
			assert.Contains(t, out, "level=WARN")
			assert.Contains(t, out, "envoy build is unpinned")
			assert.Contains(t, out, "path="+tt.want)
		})
	}
}

func TestEnvoyBinaryCommand(t *testing.T) {
	t.Parallel()

	bin := &envoyBinary{path: "/opt/envoy/bin/envoy"}

	cmd := bin.command(t.Context(), "-c", "bootstrap.yaml")

	// An unpinned binary runs by its path.
	assert.Equal(t, bin.path, cmd.Path)
	assert.Equal(t, []string{bin.path, "-c", "bootstrap.yaml"}, cmd.Args)
	assert.Empty(t, cmd.ExtraFiles)
	require.NoError(t, bin.Close())
}

func TestProxyEnvoyPath(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *config.Config
		flag string
		want string
	}{
		"neither is set": {
			cfg: &config.Config{},
		},
		"flag": {
			cfg:  &config.Config{},
			flag: "/flag/envoy",
			want: "/flag/envoy",
		},
		"config key": {
			cfg:  &config.Config{Envoy: &config.EnvoySettings{Path: "/key/envoy"}},
			want: "/key/envoy",
		},
		"flag overrides the config key": {
			cfg:  &config.Config{Envoy: &config.EnvoySettings{Path: "/key/envoy"}},
			flag: "/flag/envoy",
			want: "/flag/envoy",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, proxyEnvoyPath(tt.cfg, proxyOptions{envoyPath: tt.flag}))
		})
	}
}

// runStubProxy runs [Proxy] with the stub envoy that writes started
// until the stub starts, and then shuts the proxy down.
func runStubProxy(
	t *testing.T, usr *config.User, inst *envoybin.Installer, opts proxyOptions, started string,
) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		errCh <- Proxy(ctx, usr, inst, opts)
	}()

	requireStubStarted(t, started)
	cancel()
	requireProxyShutDown(t, errCh)
}

// TestProxyManagedEnvoy checks that [Proxy] installs and runs the
// managed build when no envoy is on PATH. A later start then runs the
// installed build without a download. A stub envoy stands for the
// managed build.
//
//nolint:paralleltest // sets PATH and replaces the default logger.
func TestProxyManagedEnvoy(t *testing.T) {
	stub, started, argsPath := stubEnvoyScript(t.TempDir())
	inst, path, requests := managedEnvoyInstaller(t, []byte(stub))

	// No directory of PATH holds an envoy.
	t.Setenv("PATH", t.TempDir())

	logs := captureLogs(t)

	for _, run := range []string{"installs a missing build", "runs the installed build"} {
		t.Run(run, func(t *testing.T) {
			usr := stubProxyUser(t, t.TempDir(), "egress: []\n")
			opts := proxyOptions{bindAddress: loopbackIPv4, httpPort: freePort(t)}

			runStubProxy(t, usr, inst, opts, started)

			// The stub that started is the installed build.
			args, err := os.ReadFile(argsPath) //nolint:gosec // test fixture path.
			require.NoError(t, err)
			assert.Contains(t, string(args), proxyBootstrapPath(usr))

			assert.Equal(t, int64(1), requests.Load())
			assert.FileExists(t, path)

			require.NoError(t, os.Remove(started))
			require.NoError(t, os.Remove(argsPath))
		})
	}

	out := logs.String()
	assert.Equal(t, 1, strings.Count(out, "installing the managed envoy build"))
	assert.Contains(t, out, "path="+path)
	assert.NotContains(t, out, "unpinned")
}

// TestProxyManagedEnvoyIgnoresPath checks that a [Proxy] without an
// Envoy override runs the managed build when PATH holds an envoy.
//
//nolint:paralleltest // sets PATH for the whole process.
func TestProxyManagedEnvoyIgnoresPath(t *testing.T) {
	// The stub on PATH must not start.
	pathStarted, _ := stubEnvoy(t)

	stub, started, _ := stubEnvoyScript(t.TempDir())
	inst, path, requests := managedEnvoyInstaller(t, []byte(stub))

	usr := stubProxyUser(t, t.TempDir(), "egress: []\n")
	opts := proxyOptions{bindAddress: loopbackIPv4, httpPort: freePort(t)}

	runStubProxy(t, usr, inst, opts, started)

	assert.NoFileExists(t, pathStarted, "the envoy on PATH must not start")
	assert.Equal(t, int64(1), requests.Load())
	assert.FileExists(t, path)
}

// TestProxyCancelDuringInstall checks that [Proxy] returns nil when its
// context ends during the download of the managed build, and that it
// leaves no file at the install path.
func TestProxyCancelDuringInstall(t *testing.T) {
	t.Parallel()

	requested := make(chan struct{})

	// The server never answers, so the download lasts until the proxy
	// gives it up.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(requested)
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	sum := sha256.Sum256([]byte("managed envoy"))

	inst := envoybin.NewInstaller(t.TempDir(), envoybin.WithManifest(envoybin.Manifest{
		Version: "v9.9.9",
		Builds: map[envoybin.Platform]envoybin.Build{
			envoybin.HostPlatform(): {
				URL:            srv.URL + "/envoy",
				Format:         envoybin.FormatBinary,
				DownloadSHA256: hex.EncodeToString(sum[:]),
				BinarySHA256:   hex.EncodeToString(sum[:]),
			},
		},
	}))

	path, err := inst.Path()
	require.NoError(t, err)

	dir := t.TempDir()
	usr := stubProxyUser(t, dir, "egress: []\n")
	usr.ReadyFile = filepath.Join(dir, "ready")

	opts := proxyOptions{bindAddress: loopbackIPv4, httpPort: freePort(t)}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	errCh := make(chan error, 1)

	go func() {
		errCh <- Proxy(ctx, usr, inst, opts)
	}()

	select {
	case <-requested:
	case <-time.After(15 * time.Second):
		t.Fatal("proxy did not start the download")
	}

	cancel()
	requireProxyShutDown(t, errCh)

	assert.NoFileExists(t, path)
	assert.NoFileExists(t, usr.ReadyFile)
}

// TestProxyManagedEnvoyChanged checks that [Proxy] returns the hash
// mismatch and starts nothing when a byte of the managed binary
// changed.
func TestProxyManagedEnvoyChanged(t *testing.T) {
	t.Parallel()

	stub, started, _ := stubEnvoyScript(t.TempDir())
	inst, path, requests := managedEnvoyInstaller(t, []byte(stub))

	_, err := inst.Install(t.Context())
	require.NoError(t, err)

	changed := changeByte(t, path)

	dir := t.TempDir()
	usr := stubProxyUser(t, dir, "egress: []\n")
	usr.ReadyFile = filepath.Join(dir, "ready")

	opts := proxyOptions{bindAddress: loopbackIPv4, httpPort: freePort(t)}

	err = Proxy(t.Context(), usr, inst, opts)
	require.ErrorIs(t, err, envoybin.ErrHashMismatch)
	require.ErrorContains(t, err, path)
	require.ErrorContains(t, err, "remove it, and run `terrarium envoy install`")

	assert.NoFileExists(t, started, "the changed binary must not start")
	assert.NoFileExists(t, usr.ReadyFile)

	// The proxy does not download a replacement.
	assert.Equal(t, int64(1), requests.Load())

	data, err := os.ReadFile(path) //nolint:gosec // test fixture path.
	require.NoError(t, err)
	assert.Equal(t, changed, data)
}

// TestProxyEnvoyOverride checks that [Proxy] runs the binary that the
// --envoy-path flag or the envoy.path config key names. The proxy then
// logs that the build is unpinned, and it does not install the managed
// build.
//
//nolint:paralleltest,tparallel // replaces the default logger.
func TestProxyEnvoyOverride(t *testing.T) {
	tests := map[string]struct {
		// flag and key say whether the flag and the config key name
		// the stub envoy. With both set, the key names a missing file.
		flag bool
		key  bool
	}{
		"flag":                          {flag: true},
		"config key":                    {key: true},
		"flag overrides the config key": {flag: true, key: true},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			logs := captureLogs(t)

			// The directory of the stub is not on PATH.
			binDir := t.TempDir()
			stub, started, _ := stubEnvoyScript(binDir)
			stubPath := filepath.Join(binDir, "custom-envoy")

			require.NoError(t, os.WriteFile(stubPath, []byte(stub), 0o755))

			inst, installPath, requests := managedEnvoyInstaller(t, []byte("managed envoy"))

			policy := "egress: []\n"
			opts := proxyOptions{bindAddress: loopbackIPv4, httpPort: freePort(t)}

			switch {
			case tt.flag && tt.key:
				policy += "envoy:\n  path: " + filepath.Join(binDir, "missing") + "\n"
				opts.envoyPath = stubPath

			case tt.flag:
				opts.envoyPath = stubPath

			default:
				policy += "envoy:\n  path: " + stubPath + "\n"
			}

			usr := stubProxyUser(t, t.TempDir(), policy)

			runStubProxy(t, usr, inst, opts, started)

			assert.Zero(t, requests.Load())
			assert.NoFileExists(t, installPath)

			out := logs.String()
			assert.Contains(t, out, "level=WARN")
			assert.Contains(t, out, "envoy build is unpinned")
			assert.Contains(t, out, "path="+stubPath)
		})
	}
}

// TestProxyCommandEnvoy runs the proxy command the way the CLI nests
// it, so that the --envoy-path flag and the installer of the command
// reach [Proxy]. Every case ends before the proxy starts Envoy.
func TestProxyCommandEnvoy(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing-envoy")

	tests := map[string]struct {
		err  error
		msg  string
		args []string
	}{
		"flag names a missing binary": {
			args: []string{"--envoy-path", missing},
			err:  ErrEnvoyNotFound,
			msg:  missing,
		},
		"no flag and no managed build": {
			err: envoybin.ErrUnsupportedPlatform,
			msg: "--envoy-path",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			policy := filepath.Join(dir, "policy.yaml")
			require.NoError(t, os.WriteFile(policy, []byte("egress: []\n"), 0o644))

			usr := config.NewUser()

			root := &cobra.Command{Use: newRootCmd().Name(), SilenceUsage: true, SilenceErrors: true}
			usr.RegisterFlags(root.PersistentFlags(), usr.Flags.ConfigPath)
			root.AddCommand(proxyCmd(usr, noManagedEnvoy()))

			root.SetArgs(append([]string{
				"proxy",
				"--config", policy,
				"--envoy-config", filepath.Join(dir, "envoy.yaml"),
				"--http-port", strconv.Itoa(freePort(t)),
			}, tt.args...))

			err := root.ExecuteContext(t.Context())
			require.ErrorIs(t, err, tt.err)
			require.ErrorContains(t, err, tt.msg)
		})
	}
}
