//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeDaemon runs the signal loop of the daemon with [serveReloads] in
// the test process, with a reload that the test supplies.
// It receives signals through its signal method, so the test process
// gets no real signal.
type fakeDaemon struct {
	// Closes when the signal loop has returned, which stands for the
	// exit of the daemon.
	done chan struct{}

	sigCh chan os.Signal

	// Receives one value for each SIGHUP that the signal method gets.
	hups chan struct{}

	statusPath string
}

// startFakeDaemon starts a [fakeDaemon] that calls reload for each
// SIGHUP. The daemon stops when the test ends. A reload that blocks
// must return before then.
func startFakeDaemon(t *testing.T, reload func(ctx context.Context) error) *fakeDaemon {
	t.Helper()

	d := &fakeDaemon{
		done:       make(chan struct{}),
		sigCh:      make(chan os.Signal, 1),
		hups:       make(chan struct{}, 16),
		statusPath: reloadStatusPath(filepath.Join(t.TempDir(), "daemon.pid")),
	}

	recorder, err := newReloadRecorder(d.statusPath)
	require.NoError(t, err)

	ctx := context.WithoutCancel(t.Context())

	go func() {
		defer close(d.done)

		err := serveReloads(ctx, d.sigCh, func(context.Context, string) {}, recorder, reload,
			func(context.Context) {})
		if err != nil {
			t.Logf("daemon exited: %v", err)
		}
	}()

	t.Cleanup(func() {
		select {
		case d.sigCh <- syscall.SIGTERM:
		case <-d.done:
		}

		<-d.done
	})

	return d
}

// signal delivers sig to the daemon as [os.Process.Signal] does. It
// returns [os.ErrProcessDone] after the daemon exited. As
// [os/signal.Notify] does, it drops a signal when the channel of the
// daemon is full.
func (d *fakeDaemon) signal(sig os.Signal) error {
	select {
	case <-d.done:
		return os.ErrProcessDone
	default:
	}

	if sig == syscall.Signal(0) {
		return nil
	}

	select {
	case d.sigCh <- sig:
	default:
	}

	if sig == syscall.SIGHUP {
		d.hups <- struct{}{}
	}

	return nil
}

// receive returns the next value of ch. It fails the test when no
// value arrives in 30 seconds.
func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()

	select {
	case v := <-ch:
		return v
	case <-time.After(30 * time.Second):
		require.FailNow(t, "no value arrived in 30 seconds")

		panic("unreachable")
	}
}

// TestRequestReload checks that the reload command returns only after
// the daemon finished the reload, and that it reports each outcome of
// the reload.
func TestRequestReload(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// The error of the reload in the daemon.
		reloadErr error

		err      error
		wantText string

		// Whether the daemon exits after the reload.
		wantExit bool
	}{
		"reload completes": {},
		"daemon rejects the config": {
			reloadErr: fmt.Errorf("%w: parsing config", ErrReloadRejected),
			err:       ErrDaemonKeptConfig,
			wantText:  "reload rejected: parsing config",
		},
		"reload ends the daemon": {
			reloadErr: errors.New("starting envoy"),
			err:       ErrReloadEndedDaemon,
			wantText:  "starting envoy",
			wantExit:  true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var finished atomic.Bool

			// The reload takes several polls of the status, so a
			// command that does not wait for the outcome returns
			// before the reload finishes.
			d := startFakeDaemon(t, func(context.Context) error {
				time.Sleep(3 * reloadPollInterval)
				finished.Store(true)

				return tt.reloadErr
			})

			err := requestReload(t.Context(), d.statusPath, os.Getpid(), d.signal)

			assert.True(t, finished.Load(), "the command returned before the reload finished")

			if tt.err == nil {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, tt.err)
				require.ErrorContains(t, err, tt.wantText)
			}

			if !tt.wantExit {
				require.NoError(t, d.signal(syscall.Signal(0)), "the daemon must still run")

				return
			}

			receive(t, d.done)

			// The status of the reload that ended the daemon stays,
			// so a command that reads it later reports the same error.
			status, err := readReloadStatus(d.statusPath)
			require.NoError(t, err)
			assert.Equal(t, reloadFailed, status.Outcome)
		})
	}
}

// TestRequestReloadDuringReload checks a reload command that starts
// during a reload. That reload might have read the config file before
// the command started. The command must therefore report the outcome
// of the reload that the daemon starts after it.
func TestRequestReloadDuringReload(t *testing.T) {
	t.Parallel()

	var reloads atomic.Int32

	entered := make(chan struct{}, 1)
	release := make(chan struct{})

	d := startFakeDaemon(t, func(context.Context) error {
		if reloads.Add(1) == 1 {
			entered <- struct{}{}

			<-release

			return nil
		}

		return fmt.Errorf("%w: parsing config", ErrReloadRejected)
	})

	require.NoError(t, d.signal(syscall.SIGHUP))
	receive(t, d.hups)
	receive(t, entered)

	result := make(chan error, 1)

	go func() {
		result <- requestReload(t.Context(), d.statusPath, os.Getpid(), d.signal)
	}()

	// The command reads the status before it sends the signal, so it
	// has read the status of the first reload here.
	receive(t, d.hups)
	close(release)

	err := receive(t, result)
	require.ErrorIs(t, err, ErrDaemonKeptConfig)
	assert.Equal(t, int32(2), reloads.Load())
}

// TestRequestReloadDaemonExits checks a daemon that exits during the
// wait without an outcome of the reload, as it does for a termination
// signal.
func TestRequestReloadDaemonExits(t *testing.T) {
	t.Parallel()

	d := startFakeDaemon(t, func(context.Context) error {
		assert.Fail(t, "unexpected reload")

		return nil
	})

	// The daemon gets a termination signal in place of the SIGHUP.
	signal := func(sig os.Signal) error {
		if sig == syscall.SIGHUP {
			sig = syscall.SIGTERM
		}

		return d.signal(sig)
	}

	err := requestReload(t.Context(), d.statusPath, os.Getpid(), signal)
	require.ErrorIs(t, err, ErrDaemonNotRunning)
	require.ErrorContains(t, err, "daemon exited during reload")

	// The daemon removes the status when it shuts down for a
	// termination signal.
	receive(t, d.done)
	assert.NoFileExists(t, d.statusPath)
}

// TestRequestReloadCanceled checks that the wait for the reload ends
// with the context.
func TestRequestReloadCanceled(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{}, 1)
	release := make(chan struct{})

	d := startFakeDaemon(t, func(context.Context) error {
		entered <- struct{}{}

		<-release

		return nil
	})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	result := make(chan error, 1)

	go func() {
		result <- requestReload(ctx, d.statusPath, os.Getpid(), d.signal)
	}()

	receive(t, entered)
	cancel()

	err := receive(t, result)
	require.ErrorIs(t, err, context.Canceled)

	close(release)
}

// TestRequestReloadBeforeSignal checks the errors that stop the reload
// command before it signals the daemon.
func TestRequestReloadBeforeSignal(t *testing.T) {
	t.Parallel()

	pid := os.Getpid()

	tests := map[string]struct {
		// The content of the status file. Empty means that the file
		// does not exist.
		status string

		// The error of the signal that checks whether the daemon
		// runs.
		aliveErr error

		err error

		// A second error that the error wraps, beside err.
		cause error

		wantText string
	}{
		"daemon does not run": {
			status:   fmt.Sprintf(`{"pid":%d,"started":0,"finished":0}`, pid),
			aliveErr: os.ErrProcessDone,
			err:      ErrDaemonNotRunning,
		},
		"no status file": {
			err:      ErrReloadStatus,
			cause:    fs.ErrNotExist,
			wantText: "restart the daemon",
		},
		"status that does not parse": {
			status: "{",
			err:    ErrReloadStatus,
		},
		"status of another daemon": {
			status: fmt.Sprintf(`{"pid":%d,"started":0,"finished":0}`, pid+1),
			err:    ErrReloadStatus,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "daemon.pid.reload")

			if tt.status != "" {
				require.NoError(t, os.WriteFile(path, []byte(tt.status), 0o644))
			}

			signal := func(sig os.Signal) error {
				assert.Equal(t, syscall.Signal(0), sig, "the command signaled the daemon")

				return tt.aliveErr
			}

			err := requestReload(t.Context(), path, pid, signal)
			require.ErrorIs(t, err, tt.err)

			if tt.cause != nil {
				require.ErrorIs(t, err, tt.cause)
			}

			if tt.wantText != "" {
				require.ErrorContains(t, err, tt.wantText)
			}
		})
	}
}

// TestAwaitReload checks what the wait for a reload returns for each
// reload status and each state of the daemon. Every case ends the
// wait at the first read of the status.
func TestAwaitReload(t *testing.T) {
	t.Parallel()

	const (
		pid    = 100
		target = 3
	)

	tests := map[string]struct {
		// A nil status means that the status file does not exist.
		status *reloadStatus

		// The content of the status file when status is nil. Empty
		// means that the file does not exist.
		content string

		// The error of the signal that checks whether the daemon
		// runs.
		aliveErr error

		err      error
		wantText string
	}{
		"awaited reload completed": {
			status: &reloadStatus{PID: pid, Started: 3, Finished: 3, Outcome: reloadCompleted},
		},
		"later reload completed": {
			status: &reloadStatus{PID: pid, Started: 5, Finished: 4, Outcome: reloadCompleted},
		},
		"awaited reload rejected": {
			status: &reloadStatus{
				PID:      pid,
				Started:  3,
				Finished: 3,
				Outcome:  reloadRejected,
				Error:    "parsing config",
			},
			err:      ErrDaemonKeptConfig,
			wantText: "parsing config",
		},
		"awaited reload ended the daemon": {
			status:   &reloadStatus{PID: pid, Started: 3, Finished: 3, Outcome: reloadFailed, Error: "starting envoy"},
			err:      ErrReloadEndedDaemon,
			wantText: "starting envoy",
		},
		"awaited reload ended the daemon that exited": {
			status:   &reloadStatus{PID: pid, Started: 3, Finished: 3, Outcome: reloadFailed, Error: "starting envoy"},
			aliveErr: os.ErrProcessDone,
			err:      ErrReloadEndedDaemon,
			wantText: "starting envoy",
		},
		"earlier reload ended the daemon": {
			status:   &reloadStatus{PID: pid, Started: 2, Finished: 2, Outcome: reloadFailed, Error: "starting envoy"},
			err:      ErrReloadEndedDaemon,
			wantText: "starting envoy",
		},
		"daemon exited after an earlier reload": {
			status:   &reloadStatus{PID: pid, Started: 2, Finished: 2, Outcome: reloadCompleted},
			aliveErr: os.ErrProcessDone,
			err:      ErrDaemonNotRunning,
		},
		"daemon exited and removed the status": {
			aliveErr: os.ErrProcessDone,
			err:      ErrDaemonNotRunning,
		},
		"daemon restarted": {
			status:   &reloadStatus{PID: pid + 1, Started: 3, Finished: 3, Outcome: reloadCompleted},
			aliveErr: os.ErrProcessDone,
			err:      ErrDaemonNotRunning,
		},
		"unknown outcome": {
			status:   &reloadStatus{PID: pid, Started: 3, Finished: 3, Outcome: "paused"},
			err:      ErrReloadStatus,
			wantText: `"paused"`,
		},
		"status that does not parse": {
			content:  "{",
			err:      ErrReloadStatus,
			wantText: "parsing reload status",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "daemon.pid.reload")

			if tt.status != nil {
				recorder := &reloadRecorder{path: path, status: *tt.status}
				require.NoError(t, recorder.write())
			}

			if tt.content != "" {
				require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o644))
			}

			signal := func(os.Signal) error {
				return tt.aliveErr
			}

			err := awaitReload(t.Context(), path, pid, target, signal)

			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}

			if tt.wantText != "" {
				require.ErrorContains(t, err, tt.wantText)
			}
		})
	}
}

// TestReloadRecorder checks the status that the recorder writes
// before, during, and after each reload.
func TestReloadRecorder(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "run", "daemon.pid.reload")

	// A status that a previous daemon left.
	require.NoError(t, os.Mkdir(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(`{"pid":1,"started":7,"finished":7,"outcome":"failed"}`), 0o644))

	recorder, err := newReloadRecorder(path)
	require.NoError(t, err)

	pid := os.Getpid()

	status, err := readReloadStatus(path)
	require.NoError(t, err)
	assert.Equal(t, &reloadStatus{PID: pid}, status)

	errRejected := fmt.Errorf("%w: parsing config", ErrReloadRejected)
	errIncomplete := errors.New("starting envoy")

	// The reloads run in this order, and each one reads the status
	// that the reload before it left.
	steps := []struct {
		err  error
		want reloadStatus
	}{
		{
			want: reloadStatus{PID: pid, Started: 1, Finished: 1, Outcome: reloadCompleted},
		},
		{
			err: errRejected,
			want: reloadStatus{
				PID: pid, Started: 2, Finished: 2, Outcome: reloadRejected, Error: errRejected.Error(),
			},
		},
		{
			want: reloadStatus{PID: pid, Started: 3, Finished: 3, Outcome: reloadCompleted},
		},
		{
			err: errIncomplete,
			want: reloadStatus{
				PID: pid, Started: 4, Finished: 4, Outcome: reloadFailed, Error: errIncomplete.Error(),
			},
		},
	}

	before := reloadStatus{PID: pid}

	for _, step := range steps {
		err := recorder.record(t.Context(), func(context.Context) error {
			// During the reload, the status names the reload as
			// started and still holds the outcome of the reload
			// before it.
			during := before
			during.Started++

			status, err := readReloadStatus(path)
			require.NoError(t, err)
			assert.Equal(t, &during, status)

			return step.err
		})
		if step.err == nil {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, step.err)
		}

		status, err := readReloadStatus(path)
		require.NoError(t, err)
		assert.Equal(t, &step.want, status)

		before = step.want
	}

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm())

	// Each write replaces the file through a temporary file, which
	// must not stay in the directory.
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.Len(t, entries, 1)

	recorder.remove(t.Context())
	assert.NoFileExists(t, path)

	// A second removal finds no file and must not fail the caller.
	recorder.remove(t.Context())
}
