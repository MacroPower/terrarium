package privdrop

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCapLastCapFrom(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		content string
		want    int
		err     string
	}{
		"normal": {
			content: "40\n",
			want:    40,
		},
		"no newline": {
			content: "40",
			want:    40,
		},
		"non-numeric": {
			content: "abc\n",
			err:     "parsing cap_last_cap",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			path := filepath.Join(dir, "cap_last_cap")

			err := os.WriteFile(path, []byte(tc.content), 0o644)
			require.NoError(t, err)

			got, err := capLastCapFrom(path)

			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCapLastCapFromMissing(t *testing.T) {
	t.Parallel()

	_, err := capLastCapFrom("/nonexistent/cap_last_cap")
	require.Error(t, err)
}
