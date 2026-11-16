//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// proxyHelperDirEnv names the variable that makes [TestProxyHelper]
// run [Proxy]. Its value is the directory of the policy of that proxy.
const proxyHelperDirEnv = "TERRARIUM_TEST_PROXY_HELPER_DIR"

// TestProxyEnvoyParentDeath checks that Envoy does not outlive a proxy
// that a signal kills without a shutdown. Envoy runs in a process
// group of its own, so a signal to the group of the proxy does not
// reach it. A helper process runs [Proxy] with the stub envoy, and the
// test kills the helper with SIGKILL.
func TestProxyEnvoyParentDeath(t *testing.T) {
	t.Parallel()

	binDir := t.TempDir()
	stub, started, _ := stubEnvoyScript(binDir)
	require.NoError(t, os.WriteFile(filepath.Join(binDir, envoyCommand), []byte(stub), 0o755))

	helper := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestProxyHelper$")
	helper.Env = append(os.Environ(),
		proxyHelperDirEnv+"="+t.TempDir(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)

	require.NoError(t, helper.Start())

	requireStubStarted(t, started)

	pid := stubPID(t, started)

	// Without the signal of the kernel, the stub runs on after the
	// test. The error is ESRCH when the stub has exited.
	t.Cleanup(func() {
		syscall.Kill(pid, syscall.SIGKILL) //nolint:errcheck,gosec // see comment above.
	})

	require.NoError(t, helper.Process.Signal(syscall.SIGKILL))

	err := helper.Wait()

	var exitErr *exec.ExitError

	require.ErrorAs(t, err, &exitErr)

	assert.Eventually(t, func() bool {
		return processEnded(pid)
	}, 5*time.Second, 10*time.Millisecond, "envoy must not outlive the proxy")
}

// TestProxyHangup checks that a SIGHUP shuts the proxy down and stops
// Envoy. Envoy runs in a process group of its own, so a hangup of the
// terminal reaches the proxy and not Envoy. A proxy that starts with
// SIGHUP ignored, as under nohup, keeps running after a SIGHUP. A
// helper process runs [Proxy] with the stub envoy.
func TestProxyHangup(t *testing.T) {
	t.Parallel()

	if signal.Ignored(syscall.SIGHUP) {
		t.Skip("the test process ignores SIGHUP, and the helper inherits the ignore")
	}

	tcs := map[string]struct {
		// ignored starts the helper with SIGHUP ignored.
		ignored bool
	}{
		"SIGHUP shuts the proxy down": {},
		"SIGHUP ignored at start":     {ignored: true},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			binDir := t.TempDir()
			stub, started, _ := stubEnvoyScript(binDir)
			require.NoError(t, os.WriteFile(filepath.Join(binDir, envoyCommand), []byte(stub), 0o755))

			args := []string{os.Args[0], "-test.run=^TestProxyHelper$"}
			if tc.ignored {
				// The shell sets the ignore and then runs the
				// helper in its own process.
				args = append([]string{"/bin/sh", "-c", `trap "" HUP; exec "$0" "$@"`}, args...)
			}

			helper := exec.CommandContext(t.Context(), args[0], args[1:]...) //nolint:gosec // the test binary.
			helper.Env = append(os.Environ(),
				proxyHelperDirEnv+"="+t.TempDir(),
				"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
			)

			require.NoError(t, helper.Start())

			requireStubStarted(t, started)

			pid := stubPID(t, started)

			// The stub has exited unless the test failed, and the
			// error is then ESRCH.
			t.Cleanup(func() {
				syscall.Kill(pid, syscall.SIGKILL) //nolint:errcheck,gosec // see comment above.
			})

			require.NoError(t, helper.Process.Signal(syscall.SIGHUP))

			if tc.ignored {
				assert.Never(t, func() bool {
					return processEnded(helper.Process.Pid)
				}, 300*time.Millisecond, 10*time.Millisecond, "the proxy must ignore SIGHUP")

				require.NoError(t, helper.Process.Signal(syscall.SIGTERM))
			}

			// Without the handler, SIGHUP kills the helper, and Wait
			// returns an error.
			require.NoError(t, helper.Wait())

			assert.Eventually(t, func() bool {
				return processEnded(pid)
			}, 5*time.Second, 10*time.Millisecond, "the proxy must stop envoy")
		})
	}
}

// TestProxyHelper runs [Proxy] with the envoy on PATH until a signal
// stops or kills its process. [TestProxyEnvoyParentDeath],
// [TestProxyEnvoyOutputPipes], and [TestProxyHangup] start it in a
// process of their own. It skips in every other run of the tests.
func TestProxyHelper(t *testing.T) {
	t.Parallel()

	dir := os.Getenv(proxyHelperDirEnv)
	if dir == "" {
		t.Skip("runs only in the helper process of another test")
	}

	usr := stubProxyUser(t, dir, "egress: []\n")

	opts := proxyOptions{
		envoyPath:   envoyCommand,
		bindAddress: loopbackIPv4,
		httpPort:    freePort(t),
	}

	// The stub never listens, so Proxy waits for the listener until
	// a signal reaches this process.
	err := Proxy(t.Context(), usr, noManagedEnvoy(), opts)
	require.NoError(t, err)
}

// TestProxyEnvoyOutputPipes checks that Envoy writes its stdout and
// stderr to pipes of the proxy. It also checks that the proxy copies
// the output to its own stdout and stderr. Envoy runs in a background
// process group, and a terminal with tostop stops each background
// process that writes to it. A helper process runs [Proxy] with
// regular files as its stdout and stderr. Without the pipes, the stub
// envoy writes to those files.
func TestProxyEnvoyOutputPipes(t *testing.T) {
	t.Parallel()

	binDir := t.TempDir()
	stub, started, _ := stubEnvoyScript(binDir)
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "stub-envoy"), []byte(stub), 0o755))

	kinds := filepath.Join(binDir, "kinds")
	// The loop records the kinds in a variable, because a redirect
	// of the loop replaces its stdout.
	wrapper := "#!/bin/sh\n" +
		"k=\n" +
		"for f in /dev/stdout /dev/stderr; do\n" +
		"  if [ -p \"$f\" ]; then k=\"$k pipe\"; else k=\"$k other\"; fi\n" +
		"done\n" +
		"echo \"$k\" > '" + kinds + "'\n" +
		"echo 'stub envoy stdout'\n" +
		"echo 'stub envoy stderr' >&2\n" +
		"exec '" + filepath.Join(binDir, "stub-envoy") + "' \"$@\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(binDir, envoyCommand), []byte(wrapper), 0o755))

	outDir := t.TempDir()

	stdout, err := os.Create(filepath.Join(outDir, "stdout"))
	require.NoError(t, err)

	stderr, err := os.Create(filepath.Join(outDir, "stderr"))
	require.NoError(t, err)

	helper := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestProxyHelper$")
	helper.Env = append(os.Environ(),
		proxyHelperDirEnv+"="+t.TempDir(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	helper.Stdout = stdout
	helper.Stderr = stderr

	require.NoError(t, helper.Start())

	// The helper holds its own copies of the files.
	require.NoError(t, stdout.Close())
	require.NoError(t, stderr.Close())

	requireStubStarted(t, started)

	pid := stubPID(t, started)

	t.Cleanup(func() {
		syscall.Kill(pid, syscall.SIGKILL) //nolint:errcheck,gosec // the stub has exited unless the test failed.
	})

	got, err := os.ReadFile(kinds)
	require.NoError(t, err)
	assert.Equal(t, " pipe pipe\n", string(got), "the stdout and the stderr of envoy must be pipes")

	// SIGTERM makes Proxy stop Envoy and return.
	require.NoError(t, helper.Process.Signal(syscall.SIGTERM))
	require.NoError(t, helper.Wait())

	out, err := os.ReadFile(stdout.Name())
	require.NoError(t, err)
	assert.Contains(t, string(out), "stub envoy stdout")

	out, err = os.ReadFile(stderr.Name())
	require.NoError(t, err)
	assert.Contains(t, string(out), "stub envoy stderr")
}

// processEnded reports whether the process pid has exited. A process
// that has exited but that its parent has not reaped still answers
// signal 0, so processEnded also reports true for that process.
func processEnded(pid int) bool {
	err := syscall.Kill(pid, 0)
	if errors.Is(err, syscall.ESRCH) {
		return true
	}

	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if errors.Is(err, os.ErrNotExist) {
		return true
	}

	// The state follows the command name, which ends at the last
	// closing parenthesis.
	i := bytes.LastIndexByte(data, ')')
	if err != nil || i < 0 || len(data) <= i+2 {
		return false
	}

	return data[i+2] == 'Z'
}
