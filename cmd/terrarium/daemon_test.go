//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// feedSignals returns the two channels of a signal loop and sends
// signals to them in order. SIGHUP goes to hupCh, and every other
// signal goes to termCh. The channels have no buffer, so the loop
// receives each signal only after it handled the signal before it.
// termCh closes after the last signal.
func feedSignals(t *testing.T, signals []os.Signal) (<-chan os.Signal, <-chan os.Signal) {
	t.Helper()

	termCh := make(chan os.Signal)
	hupCh := make(chan os.Signal)
	ctx := t.Context()

	go func() {
		defer close(termCh)

		for _, sig := range signals {
			ch := termCh
			if sig == syscall.SIGHUP {
				ch = hupCh
			}

			// A loop that returned reads no more signals.
			select {
			case ch <- sig:
			case <-ctx.Done():
				return
			}
		}
	}()

	return termCh, hupCh
}

// TestServeSignals checks which states the daemon reports for each
// result of a reload, and when the daemon stops handling signals.
func TestServeSignals(t *testing.T) {
	t.Parallel()

	errIncomplete := errors.New("starting envoy")
	errRejected := fmt.Errorf("%w: parsing config", ErrReloadRejected)

	tests := map[string]struct {
		err         error
		signals     []os.Signal
		reloads     []error
		wantStates  []string
		wantReloads int
	}{
		"termination signal": {
			signals: []os.Signal{syscall.SIGTERM, syscall.SIGHUP},
		},
		"closed channel": {},
		"reload completes": {
			signals:     []os.Signal{syscall.SIGHUP, syscall.SIGINT},
			reloads:     []error{nil},
			wantStates:  []string{"RELOADING=1", "READY=1"},
			wantReloads: 1,
		},
		"rejected reload keeps the daemon ready": {
			signals:     []os.Signal{syscall.SIGHUP, syscall.SIGHUP, syscall.SIGTERM},
			reloads:     []error{errRejected, nil},
			wantStates:  []string{"RELOADING=1", "READY=1", "RELOADING=1", "READY=1"},
			wantReloads: 2,
		},
		"incomplete reload stops the daemon": {
			signals:     []os.Signal{syscall.SIGHUP, syscall.SIGHUP},
			reloads:     []error{errIncomplete, nil},
			wantStates:  []string{"RELOADING=1"},
			wantReloads: 1,
			err:         errIncomplete,
		},
		"incomplete reload after a completed one": {
			signals:     []os.Signal{syscall.SIGHUP, syscall.SIGHUP},
			reloads:     []error{nil, errIncomplete},
			wantStates:  []string{"RELOADING=1", "READY=1", "RELOADING=1"},
			wantReloads: 2,
			err:         errIncomplete,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			termCh, hupCh := feedSignals(t, tt.signals)

			var (
				states  []string
				reloads int
			)

			notify := func(_ context.Context, state string) {
				states = append(states, state)
			}

			reload := func(context.Context) error {
				require.Less(t, reloads, len(tt.reloads), "unexpected reload")

				err := tt.reloads[reloads]
				reloads++

				return err
			}

			err := serveSignals(t.Context(), termCh, hupCh, notify, reload)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantStates, states)
			assert.Equal(t, tt.wantReloads, reloads)
		})
	}
}

// TestServeSignalsTerminationDuringReload checks that the daemon shuts
// down for a termination signal that arrives during a reload,
// whatever number of SIGHUP signals arrive before it. The daemon must
// not start the reload for those SIGHUP signals.
func TestServeSignalsTerminationDuringReload(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		// The signals that arrive during the first reload, in order.
		during []os.Signal
	}{
		"SIGTERM": {
			during: []os.Signal{syscall.SIGTERM},
		},
		"SIGTERM after a SIGHUP": {
			during: []os.Signal{syscall.SIGHUP, syscall.SIGTERM},
		},
		"SIGINT after a SIGHUP": {
			during: []os.Signal{syscall.SIGHUP, syscall.SIGINT},
		},
		"SIGTERM after several SIGHUP signals": {
			during: []os.Signal{syscall.SIGHUP, syscall.SIGHUP, syscall.SIGHUP, syscall.SIGTERM},
		},
		"SIGTERM before a SIGHUP": {
			during: []os.Signal{syscall.SIGTERM, syscall.SIGHUP},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var reloads atomic.Int32

			entered := make(chan struct{}, 1)
			release := make(chan struct{})

			d := startFakeDaemon(t, func(context.Context) error {
				if reloads.Add(1) == 1 {
					entered <- struct{}{}

					<-release
				}

				return nil
			})

			require.NoError(t, d.signal(syscall.SIGHUP))
			receive(t, entered)

			for _, sig := range tt.during {
				require.NoError(t, d.signal(sig))
			}

			close(release)
			receive(t, d.done)

			assert.Equal(t, int32(1), reloads.Load())
			assert.NoFileExists(t, d.statusPath)
		})
	}
}

// TestServeReloads checks the reload status file and the shutdown of
// the daemon after its signal loop returns. The status of a reload
// that ends the daemon must stay, so the reload command can report
// its error. The status must go when the daemon shuts down for a
// termination signal.
func TestServeReloads(t *testing.T) {
	t.Parallel()

	pid := os.Getpid()
	errIncomplete := errors.New("starting envoy")
	errRejected := fmt.Errorf("%w: parsing config", ErrReloadRejected)

	tests := map[string]struct {
		err        error
		signals    []os.Signal
		reloads    []error
		wantStates []string

		// The status file after the daemon shut down. Nil means that
		// the file does not exist.
		wantStatus *reloadStatus
	}{
		"termination signal": {
			signals:    []os.Signal{syscall.SIGTERM},
			wantStates: []string{"STOPPING=1"},
		},
		"closed channel after a completed reload": {
			signals:    []os.Signal{syscall.SIGHUP},
			reloads:    []error{nil},
			wantStates: []string{"RELOADING=1", "READY=1", "STOPPING=1"},
		},
		"termination signal after a rejected reload": {
			signals:    []os.Signal{syscall.SIGHUP, syscall.SIGTERM},
			reloads:    []error{errRejected},
			wantStates: []string{"RELOADING=1", "READY=1", "STOPPING=1"},
		},
		"reload ends the daemon": {
			signals:    []os.Signal{syscall.SIGHUP, syscall.SIGHUP},
			reloads:    []error{nil, errIncomplete},
			wantStates: []string{"RELOADING=1", "READY=1", "RELOADING=1", "STOPPING=1"},
			wantStatus: &reloadStatus{
				PID:      pid,
				Started:  2,
				Finished: 2,
				Outcome:  reloadFailed,
				Error:    errIncomplete.Error(),
			},
			err: errIncomplete,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := reloadStatusPath(filepath.Join(t.TempDir(), "daemon.pid"))

			recorder, err := newReloadRecorder(path)
			require.NoError(t, err)

			termCh, hupCh := feedSignals(t, tt.signals)

			var (
				states    []string
				reloads   int
				shutdowns int
			)

			notify := func(_ context.Context, state string) {
				states = append(states, state)
			}

			reload := func(context.Context) error {
				require.Less(t, reloads, len(tt.reloads), "unexpected reload")

				err := tt.reloads[reloads]
				reloads++

				return err
			}

			shutdown := func(context.Context) {
				shutdowns++

				// The daemon reports that it stops before it shuts
				// down, and it removes the status only after the
				// shutdown.
				assert.Equal(t, "STOPPING=1", states[len(states)-1])
				assert.FileExists(t, path)
			}

			err = serveReloads(t.Context(), termCh, hupCh, notify, recorder, reload, shutdown)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantStates, states)
			assert.Equal(t, len(tt.reloads), reloads)
			assert.Equal(t, 1, shutdowns)

			if tt.wantStatus == nil {
				assert.NoFileExists(t, path)

				return
			}

			status, err := readReloadStatus(path)
			require.NoError(t, err)
			assert.Equal(t, tt.wantStatus, status)
		})
	}
}

// TestDiscardBootstrapOnError checks which Envoy bootstrap a setup
// that returns an error leaves on disk. The next start of the daemon
// generates its configs only when the bootstrap does not exist. A
// bootstrap that the setup generated must therefore not stay after
// an error.
func TestDiscardBootstrapOnError(t *testing.T) {
	t.Parallel()

	errSetup := errors.New("setup")

	tests := map[string]struct {
		err error

		// The bootstrap that exists before the setup. Empty means that
		// no bootstrap exists.
		before string

		// The bootstrap that the setup generates. The setup generates
		// it only when no bootstrap exists, as [setupInfrastructure]
		// does. Empty means that the setup stops before it generates.
		generated string

		// The bootstrap that exists after the setup. Empty means that
		// no bootstrap exists.
		want string
	}{
		"setup generates the bootstrap and fails": {
			generated: "generated",
			err:       errSetup,
		},
		"setup generates the bootstrap and succeeds": {
			generated: "generated",
			want:      "generated",
		},
		"setup fails before it generates the bootstrap": {
			err: errSetup,
		},
		"setup fails with a bootstrap that existed before": {
			before:    "before",
			generated: "generated",
			err:       errSetup,
			want:      "before",
		},
		"setup succeeds with a bootstrap that existed before": {
			before:    "before",
			generated: "generated",
			want:      "before",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "envoy.yaml")

			if tt.before != "" {
				require.NoError(t, os.WriteFile(path, []byte(tt.before), 0o644))
			}

			want := &infra{}

			setup := func() (*infra, error) {
				_, err := os.Stat(path)
				if os.IsNotExist(err) && tt.generated != "" {
					require.NoError(t, os.WriteFile(path, []byte(tt.generated), 0o644))
				}

				if tt.err != nil {
					return nil, tt.err
				}

				return want, nil
			}

			got, err := discardBootstrapOnError(t.Context(), path, setup)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.Same(t, want, got)
			}

			if tt.want == "" {
				assert.NoFileExists(t, path)

				return
			}

			content, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(content))
		})
	}
}
