package main

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// envoyGuardHelperDirEnv names the variable that makes
// [TestEnvoyGuardHelper] start a guard. Its value is the directory of
// the files that the helper writes.
const envoyGuardHelperDirEnv = "TERRARIUM_TEST_ENVOY_GUARD_HELPER_DIR"

// guardPIDFile is the name of the file that holds the process ID of
// the guard process of [TestEnvoyGuardHelper].
const guardPIDFile = "guard"

// TestMain runs the guard process of an [envoyGuard] when the first
// argument of the test binary is [envoyGuardCommand], as the terrarium
// binary does. [startEnvoyGuard] starts the executable of its caller,
// which is the test binary in a test. Every other run executes the
// tests.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == envoyGuardCommand {
		envoyGuardMain()
	}

	os.Exit(m.Run())
}

// TestEnvoyGuardParentDeath checks that the guard kills the processes
// of its group when the process that started it dies without a stop of
// the guard. A helper process starts the guard and the stub envoy, and
// the test kills the helper with SIGKILL.
func TestEnvoyGuardParentDeath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, started, _ := stubEnvoyScript(dir)

	helper := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestEnvoyGuardHelper$")

	helper.Env = append(os.Environ(), envoyGuardHelperDirEnv+"="+dir)

	require.NoError(t, helper.Start())

	requireStubStarted(t, started)

	pid := stubPID(t, started)

	// The helper writes the file before it starts the stub.
	data, err := os.ReadFile(filepath.Join(dir, guardPIDFile))
	require.NoError(t, err)

	guardPID, err := strconv.Atoi(strings.TrimSpace(string(data)))
	require.NoError(t, err)

	// Both processes have exited unless the test failed, and the
	// error is then ESRCH.
	t.Cleanup(func() {
		syscall.Kill(pid, syscall.SIGKILL)      //nolint:errcheck,gosec // see comment above.
		syscall.Kill(guardPID, syscall.SIGKILL) //nolint:errcheck,gosec // see comment above.
	})

	pgid, err := syscall.Getpgid(pid)
	require.NoError(t, err)
	assert.Equal(t, guardPID, pgid, "the stub must run in the group of the guard")
	assert.NotEqual(t, syscall.Getpgrp(), pgid, "the guard must lead a group of its own")

	require.NoError(t, helper.Process.Signal(syscall.SIGKILL))

	err = helper.Wait()

	var exitErr *exec.ExitError

	require.ErrorAs(t, err, &exitErr)

	assert.Eventually(t, func() bool {
		return processEnded(pid)
	}, 5*time.Second, 10*time.Millisecond, "the guard must kill the stub")

	assert.Eventually(t, func() bool {
		return processEnded(guardPID)
	}, 5*time.Second, 10*time.Millisecond, "the guard must not outlive its group")
}

// TestEnvoyGuardHelper starts a guard and the stub envoy in the group
// of that guard, and then waits for the stub.
// [TestEnvoyGuardParentDeath] starts it in a process of its own. It
// skips in every other run of the tests.
func TestEnvoyGuardHelper(t *testing.T) {
	t.Parallel()

	dir := os.Getenv(envoyGuardHelperDirEnv)
	if dir == "" {
		t.Skip("runs only in the helper process of another test")
	}

	guard, err := startEnvoyGuard(t.Context())
	require.NoError(t, err)

	// The helper never stops the guard. Without this call, the
	// garbage collector can close the write end of the guard pipe
	// before the test kills the helper.
	defer runtime.KeepAlive(guard)

	pid := strconv.Itoa(guard.cmd.Process.Pid)
	require.NoError(t, os.WriteFile(filepath.Join(dir, guardPIDFile), []byte(pid), 0o644))

	stub, _, _ := stubEnvoyScript(dir)
	path := filepath.Join(dir, envoyCommand)
	require.NoError(t, os.WriteFile(path, []byte(stub), 0o755))

	// The stub must outlive the context of this test, which ends
	// with the helper.
	cmd := exec.CommandContext(t.Context(), path)
	cmd.SysProcAttr = guard.procAttr()

	require.NoError(t, cmd.Start())

	// The test kills this process before the stub exits.
	require.Error(t, cmd.Wait())
}

// TestEnvoyGuardStop checks that [envoyGuard.stop] kills the processes
// in the group of the guard and reaps the guard process. It also
// checks that stop does not depend on the guard process, which cannot
// act after a SIGSTOP.
func TestEnvoyGuardStop(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		// suspended sends SIGSTOP to the guard process before the
		// stop.
		suspended bool
	}{
		"guard process runs":      {},
		"guard process suspended": {suspended: true},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			guard, err := startEnvoyGuard(t.Context())
			require.NoError(t, err)

			stopped := false

			t.Cleanup(func() {
				if !stopped {
					guard.stop(t.Context())
				}
			})

			cmd := exec.CommandContext(t.Context(), "sleep", "60")
			cmd.SysProcAttr = guard.procAttr()

			require.NoError(t, cmd.Start())

			pgid, err := syscall.Getpgid(cmd.Process.Pid)
			require.NoError(t, err)
			assert.Equal(t, guard.cmd.Process.Pid, pgid, "the process must run in the group of the guard")

			if tc.suspended {
				require.NoError(t, guard.cmd.Process.Signal(syscall.SIGSTOP))
			}

			guard.stop(t.Context())

			stopped = true

			require.NotNil(t, guard.cmd.ProcessState, "stop must wait for the guard process")
			assert.Equal(t, syscall.SIGKILL, endingSignalOf(t, guard.cmd.ProcessState.Sys()))

			err = cmd.Wait()

			var exitErr *exec.ExitError

			require.ErrorAs(t, err, &exitErr)
			assert.Equal(t, syscall.SIGKILL, endingSignalOf(t, exitErr.Sys()))
		})
	}
}

// endingSignalOf returns the signal that ended the process with the
// wait status sys. It returns 0 for a process that exited by itself.
func endingSignalOf(t *testing.T, sys any) syscall.Signal {
	t.Helper()

	status, ok := sys.(syscall.WaitStatus)
	require.True(t, ok)

	if !status.Signaled() {
		return 0
	}

	return status.Signal()
}

// TestEnvoyGuardMainNotLeader checks that [envoyGuardMain] sends no
// signal from a process that does not lead its process group. A shell
// leads a new group and runs the guard as a second process of that
// group, with an empty stdin. A guard that sends its signal kills the
// shell as well.
func TestEnvoyGuardMainNotLeader(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer

	//nolint:gosec // G204: the test binary.
	cmd := exec.CommandContext(t.Context(),
		"/bin/sh", "-c", `"$0" "$1" </dev/null; echo "status=$?"`, os.Args[0], envoyGuardCommand)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	require.NoError(t, cmd.Run(), "the guard must not kill the shell")

	assert.Equal(t, "status=1\n", stdout.String())
	assert.Contains(t, stderr.String(), "does not lead its process group")
}

// TestEnvoyGuardIgnoredSignals checks that the guard process survives
// each signal of [envoyGuardIgnoredSignals] and still kills its group
// when the pipe closes. A signal sent by the name of the process
// reaches the proxy and the guard process together. A guard process
// that died from it left Envoy behind.
func TestEnvoyGuardIgnoredSignals(t *testing.T) {
	t.Parallel()

	guard, err := startEnvoyGuard(t.Context())
	require.NoError(t, err)

	stopped := false

	t.Cleanup(func() {
		if !stopped {
			guard.stop(t.Context())
		}
	})

	cmd := exec.CommandContext(t.Context(), "sleep", "60")
	cmd.SysProcAttr = guard.procAttr()

	require.NoError(t, cmd.Start())

	for _, sig := range envoyGuardIgnoredSignals {
		require.NoError(t, guard.cmd.Process.Signal(sig), "sending %v", sig)
	}

	assert.Never(t, func() bool {
		return processEnded(guard.cmd.Process.Pid) || processEnded(cmd.Process.Pid)
	}, 250*time.Millisecond, 10*time.Millisecond, "the signals must not end the guard or its group")

	// The guard process kills its group, and itself, when the read
	// of the pipe ends. The waits below reap both processes, so the
	// cleanup must not stop the guard.
	stopped = true

	require.NoError(t, guard.pipe.Close())

	waited := make(chan error, 2)

	go func() { waited <- cmd.Wait() }()
	go func() { waited <- guard.cmd.Wait() }()

	for range 2 {
		select {
		case err := <-waited:
			var exitErr *exec.ExitError

			require.ErrorAs(t, err, &exitErr)
			assert.Equal(t, syscall.SIGKILL, endingSignalOf(t, exitErr.Sys()))

		case <-time.After(5 * time.Second):
			// The error is ESRCH when the group has ended.
			syscall.Kill(-guard.cmd.Process.Pid, syscall.SIGKILL) //nolint:errcheck,gosec // see comment above.
			require.FailNow(t, "the guard must kill its group after the pipe closes")
		}
	}
}

// TestStartEnvoyGuardNotReady checks that [startEnvoyGuardProcess]
// returns an error when the guard process exits or writes other text
// before [envoyGuardReady]. A shell script stands in for the guard.
// Before it writes, it starts a `sleep` in its group and writes the
// process ID of that `sleep` to a file. The `sleep` does not hold the
// ready pipe. The call must kill the group, so the `sleep` must end,
// and the call must reap the script, so the call must return.
func TestStartEnvoyGuardNotReady(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		// output is the text that the script writes to its stdout.
		output string
		// exits makes the script exit after it writes output. Without
		// it, the script waits for the `sleep`.
		exits bool
		err   error
	}{
		"exits before ready": {
			exits: true,
			err:   io.EOF,
		},
		"exits after part of ready": {
			output: "rea",
			exits:  true,
			err:    io.ErrUnexpectedEOF,
		},
		"writes other text": {
			output: "other\n",
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			pidFile := filepath.Join(dir, "sleep")

			end := "wait"
			if tc.exits {
				end = "exit 1"
			}

			script := "#!/bin/sh\n" +
				"sleep 60 >/dev/null &\n" +
				"echo $! > '" + pidFile + "'\n" +
				"printf '%s' '" + tc.output + "'\n" +
				end + "\n"

			exe := filepath.Join(dir, "guard")
			require.NoError(t, os.WriteFile(exe, []byte(script), 0o755))

			var (
				guard *envoyGuard
				err   error
			)

			// A child that another test starts during the write of
			// the script can hold the script open for writing for a
			// moment. See [startEnvoyWhenFree].
			for pause := busyStartPause; ; pause *= 2 {
				guard, err = startEnvoyGuardProcess(t.Context(), exe)
				if !errors.Is(err, syscall.ETXTBSY) || pause > time.Second {
					break
				}

				time.Sleep(pause)
			}

			// Without a start, the script writes no file.
			require.NotErrorIs(t, err, syscall.ETXTBSY)

			data, readErr := os.ReadFile(pidFile)
			require.NoError(t, readErr)

			pid, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
			require.NoError(t, convErr)

			// The error is ESRCH when the call killed the group.
			t.Cleanup(func() {
				syscall.Kill(pid, syscall.SIGKILL) //nolint:errcheck,gosec // see comment above.
			})

			require.Error(t, err)
			assert.Nil(t, guard)
			assert.Contains(t, err.Error(), "waiting for the envoy guard")

			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			} else {
				assert.Contains(t, err.Error(), "unexpected output")
			}

			assert.Eventually(t, func() bool {
				return processEnded(pid)
			}, 5*time.Second, 10*time.Millisecond, "the call must kill the group of the guard")
		})
	}
}

// TestStartEnvoyGuardNoStart checks that [startEnvoyGuardProcess]
// returns an error that wraps the cause when the guard process does
// not start.
func TestStartEnvoyGuardNoStart(t *testing.T) {
	t.Parallel()

	exe := filepath.Join(t.TempDir(), "missing")

	guard, err := startEnvoyGuardProcess(t.Context(), exe)
	require.ErrorIs(t, err, fs.ErrNotExist)
	assert.Contains(t, err.Error(), "starting the envoy guard")
	assert.Nil(t, guard)
}
