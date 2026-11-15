package eventstore_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/eventstore"
)

func TestParseSince(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	tests := map[string]struct {
		want  time.Time
		value string
		err   string
	}{
		"empty sets no start": {value: "", want: time.Time{}},
		"duration is that long before now": {
			value: "90m",
			want:  now.Add(-90 * time.Minute),
		},
		"rfc 3339 time": {
			value: "2026-02-28T08:30:00Z",
			want:  time.Date(2026, 2, 28, 8, 30, 0, 0, time.UTC),
		},
		"rfc 3339 time with an offset and a fraction": {
			value: "2026-02-28T08:30:00.25+02:00",
			want:  time.Date(2026, 2, 28, 6, 30, 0, 250_000_000, time.UTC),
		},
		"date without a time": {
			value: "2026-02-28",
			err:   `"2026-02-28" is not a duration or an RFC 3339 time`,
		},
		"word": {
			value: "yesterday",
			err:   `"yesterday" is not a duration or an RFC 3339 time`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := eventstore.ParseSince(tt.value, now)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)

				return
			}

			require.NoError(t, err)
			assert.True(t, tt.want.Equal(got), "got %s, want %s", got, tt.want)
		})
	}
}

func TestParseUntil(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	tests := map[string]struct {
		want  time.Time
		value string
		err   string
	}{
		"empty is now": {value: "", want: now},
		"rfc 3339 time": {
			value: "2026-02-28T08:30:00Z",
			want:  time.Date(2026, 2, 28, 8, 30, 0, 0, time.UTC),
		},
		"duration": {
			value: "1h",
			err:   `"1h" is not an RFC 3339 time`,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := eventstore.ParseUntil(tt.value, now)
			if tt.err != "" {
				require.ErrorContains(t, err, tt.err)

				return
			}

			require.NoError(t, err)
			assert.True(t, tt.want.Equal(got), "got %s, want %s", got, tt.want)
		})
	}
}
