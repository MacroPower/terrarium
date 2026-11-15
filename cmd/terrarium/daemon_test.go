//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

			sigCh := make(chan os.Signal, len(tt.signals))
			for _, sig := range tt.signals {
				sigCh <- sig
			}

			close(sigCh)

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

			err := serveSignals(t.Context(), sigCh, notify, reload)
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
