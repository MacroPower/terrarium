package main

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// TestRun checks the exit code and the error output of terrarium for
// each kind of error that a command returns.
func TestRun(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cmdErr     error
		wantStderr string
		want       int
	}{
		"no error": {
			want: 0,
		},
		"exit error": {
			cmdErr: &ExitError{Code: 42},
			want:   42,
		},
		"wrapped exit error": {
			cmdErr: fmt.Errorf("running command: %w", &ExitError{Code: 3}),
			want:   3,
		},
		"other error": {
			cmdErr:     errors.New("policy not found"),
			want:       1,
			wantStderr: "policy not found",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			root := &cobra.Command{
				Use: "terrarium",
				RunE: func(_ *cobra.Command, _ []string) error {
					return tt.cmdErr
				},
			}
			root.SetArgs([]string{})
			root.SetOut(&stdout)
			root.SetErr(&stderr)

			assert.Equal(t, tt.want, run(t.Context(), root))
			assert.Empty(t, stdout.String())

			if tt.wantStderr == "" {
				assert.Empty(t, stderr.String())
			} else {
				assert.Contains(t, stderr.String(), tt.wantStderr)
			}
		})
	}
}
