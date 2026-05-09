package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/eventstore"
)

// seedDB writes events to a fresh SQLite event store and returns the
// db path. The store is closed before returning so the caller can
// open it read-only.
func seedDB(t *testing.T, events []eventstore.Event) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(10*time.Millisecond))
	require.NoError(t, err)

	for _, e := range events {
		store.Emit(e)
	}

	require.Eventually(t, func() bool {
		db, err := eventstore.OpenReadOnly(path)
		if err != nil {
			return false
		}

		defer db.Close()

		var n int

		err = db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)
		if err != nil {
			return false
		}

		return n == len(events)
	}, 2*time.Second, 20*time.Millisecond)

	require.NoError(t, store.Close())

	return path
}

func TestStatsTopDenied(t *testing.T) {
	t.Parallel()

	now := time.Now()

	dbPath := seedDB(t, []eventstore.Event{
		{Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Domain: "evil.example", Reason: eventstore.ReasonBlockedMode},
		{Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Domain: "evil.example", Reason: eventstore.ReasonBlockedMode},
		{Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Domain: "rare.example", Reason: eventstore.ReasonBlockedMode},
		{Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Domain: "ok.example"},
	})

	usr := config.NewUser()
	cmd := statsCmd(usr)

	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	cmd.SetArgs([]string{
		"top",
		"--db", dbPath,
		"--denied",
		"--format", "json",
		"--limit", "10",
	})

	require.NoError(t, cmd.ExecuteContext(t.Context()))

	var rows []map[string]any

	require.NoError(t, json.Unmarshal(buf.Bytes(), &rows))
	require.GreaterOrEqual(t, len(rows), 1)

	// First row is evil.example with count 2.
	assert.Equal(t, "evil.example", rows[0]["bucket"])
	assert.EqualValues(t, 2, rows[0]["count"])
}

func TestStatsTopAllowed(t *testing.T) {
	t.Parallel()

	now := time.Now()

	dbPath := seedDB(t, []eventstore.Event{
		{Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Domain: "popular.example"},
		{Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Domain: "popular.example"},
		{Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Domain: "popular.example"},
		{Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Domain: "lesspopular.example"},
		{Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Domain: "blocked.example"},
	})

	usr := config.NewUser()
	cmd := statsCmd(usr)

	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	cmd.SetArgs([]string{
		"top",
		"--db", dbPath,
		"--allowed",
		"--format", "json",
	})

	require.NoError(t, cmd.ExecuteContext(t.Context()))

	var rows []map[string]any

	require.NoError(t, json.Unmarshal(buf.Bytes(), &rows))
	require.GreaterOrEqual(t, len(rows), 2)
	assert.Equal(t, "popular.example", rows[0]["bucket"])
	assert.EqualValues(t, 3, rows[0]["count"])
}

func TestStatsList(t *testing.T) {
	t.Parallel()

	now := time.Now()

	dbPath := seedDB(t, []eventstore.Event{
		{Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Domain: "list.example", Protocol: eventstore.ProtocolDNS},
	})

	usr := config.NewUser()
	cmd := statsCmd(usr)

	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	cmd.SetArgs([]string{
		"list",
		"--db", dbPath,
		"--format", "json",
		"--limit", "10",
	})

	require.NoError(t, cmd.ExecuteContext(t.Context()))

	var rows []map[string]any

	require.NoError(t, json.Unmarshal(buf.Bytes(), &rows))
	require.Len(t, rows, 1)

	assert.Equal(t, "dns", rows[0]["source"])
	assert.Equal(t, "allow", rows[0]["decision"])
	assert.Equal(t, "list.example", rows[0]["domain"])
}

func TestStatsTopCSV(t *testing.T) {
	t.Parallel()

	now := time.Now()

	dbPath := seedDB(t, []eventstore.Event{
		{Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Domain: "csv.example", Reason: eventstore.ReasonBlockedMode},
	})

	usr := config.NewUser()
	cmd := statsCmd(usr)

	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	cmd.SetArgs([]string{
		"top",
		"--db", dbPath,
		"--denied",
		"--format", "csv",
	})

	require.NoError(t, cmd.ExecuteContext(t.Context()))

	out := buf.String()
	assert.Contains(t, out, "domain,count\n")
	assert.Contains(t, out, "csv.example,1\n")
}

func TestStatsSummary(t *testing.T) {
	t.Parallel()

	now := time.Now()

	dbPath := seedDB(t, []eventstore.Event{
		{Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Domain: "ok.example"},
		{Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Domain: "blocked.example"},
	})

	usr := config.NewUser()
	cmd := statsCmd(usr)

	buf := &bytes.Buffer{}
	cmd.SetOut(buf)

	cmd.SetArgs([]string{
		"--db", dbPath,
		"--format", "json",
	})

	require.NoError(t, cmd.ExecuteContext(t.Context()))

	var rows []map[string]any

	require.NoError(t, json.Unmarshal(buf.Bytes(), &rows))
	require.Len(t, rows, 2)
}

func TestResolveSince(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := map[string]struct {
		input string
		want  time.Time
		err   bool
	}{
		"empty": {
			input: "",
			want:  time.Time{},
		},
		"24h ago": {
			input: "24h",
			want:  now.Add(-24 * time.Hour),
		},
		"30m ago": {
			input: "30m",
			want:  now.Add(-30 * time.Minute),
		},
		"rfc3339": {
			input: "2025-12-30T00:00:00Z",
			want:  time.Date(2025, 12, 30, 0, 0, 0, 0, time.UTC),
		},
		"invalid": {
			input: "tomorrow",
			err:   true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := resolveSince(tt.input, now)
			if tt.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
