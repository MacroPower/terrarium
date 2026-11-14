package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWaitForListener(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err      error
		notErr   error
		timeout  time.Duration
		listen   bool
		canceled bool
	}{
		"listener accepts": {
			listen:  true,
			timeout: 15 * time.Second,
		},
		"timeout expires": {
			timeout: 150 * time.Millisecond,
			err:     ErrListenerNotReady,
		},
		"caller cancels": {
			canceled: true,
			timeout:  15 * time.Second,
			err:      context.Canceled,
			notErr:   ErrListenerNotReady,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			addr := fmt.Sprintf("%s:%d", loopbackIPv4, freePort(t))

			if tt.listen {
				lc := net.ListenConfig{}

				ln, err := lc.Listen(t.Context(), "tcp", addr)
				require.NoError(t, err)

				t.Cleanup(func() {
					assert.NoError(t, ln.Close())
				})
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			if tt.canceled {
				cancel()
			}

			err := waitForListener(ctx, addr, tt.timeout)
			if tt.err == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.err)

			if tt.notErr != nil {
				require.NotErrorIs(t, err, tt.notErr)
			}
		})
	}
}
