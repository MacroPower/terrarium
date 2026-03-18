package privdrop_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/privdrop"
)

func TestParseCaps(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input    string
		want     uint64
		clearAll bool
		err      string
	}{
		"empty": {
			input: "",
		},
		"clear all": {
			input:    "-all",
			clearAll: true,
		},
		"cap_net_admin": {
			input: "+cap_net_admin",
			want:  1 << 12, // CAP_NET_ADMIN
		},
		"unknown cap": {
			input: "+cap_unknown",
			err:   "unknown capability",
		},
		"bad modifier": {
			input: "cap_net_admin",
			err:   "unsupported cap modifier",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			set, clearAll, err := privdrop.ParseCaps(tc.input)

			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, set)
			assert.Equal(t, tc.clearAll, clearAll)
		})
	}
}
