package main

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
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

	for i := range events {
		store.Emit(events[i])
	}

	require.Eventually(t, func() bool {
		db, err := eventstore.OpenReadOnly(t.Context(), path)
		if err != nil {
			return false
		}

		defer db.Close() //nolint:errcheck // read-only handle in polling closure.

		var n int

		err = db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM events`).Scan(&n)
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
		{
			Time:     now,
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionDeny,
			Domain:   "evil.example",
			Reason:   eventstore.ReasonBlockedMode,
		},
		{
			Time:     now,
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionDeny,
			Domain:   "evil.example",
			Reason:   eventstore.ReasonBlockedMode,
		},
		{
			Time:     now,
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionDeny,
			Domain:   "rare.example",
			Reason:   eventstore.ReasonBlockedMode,
		},
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

// TestStatsList lists a firewall event that holds a destination
// address and the rule index 0, and a DNS event that holds neither.
func TestStatsList(t *testing.T) {
	t.Parallel()

	now := time.Now().Truncate(time.Second)
	stamp := now.UTC().Format(time.RFC3339)

	dbPath := seedDB(t, []eventstore.Event{
		{
			Time:     now,
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionAllow,
			Domain:   "list.example",
			Protocol: eventstore.ProtocolDNS,
		},
		{
			Time:         now,
			Source:       eventstore.SourceFirewall,
			Decision:     eventstore.DecisionAllow,
			DstIP:        netip.MustParseAddr("192.0.2.7"),
			Port:         443,
			Protocol:     eventstore.ProtocolTCP,
			Reason:       "rule=0",
			RuleIndex:    0,
			HasRuleIndex: true,
		},
	})

	run := func(t *testing.T, format string) string {
		t.Helper()

		cmd := statsCmd(config.NewUser())

		buf := &bytes.Buffer{}
		cmd.SetOut(buf)
		cmd.SetArgs([]string{"list", "--db", dbPath, "--format", format, "--limit", "10"})

		require.NoError(t, cmd.ExecuteContext(t.Context()))

		return buf.String()
	}

	t.Run("json", func(t *testing.T) {
		t.Parallel()

		var rows []map[string]any

		require.NoError(t, json.Unmarshal([]byte(run(t, "json")), &rows))
		require.Len(t, rows, 2)

		// The latest row is first.
		assert.Equal(t, "firewall", rows[0]["source"])
		assert.Equal(t, "192.0.2.7", rows[0]["dst_ip"])
		assert.InDelta(t, 0, rows[0]["rule_index"], 0)

		assert.Equal(t, "dns", rows[1]["source"])
		assert.Equal(t, "allow", rows[1]["decision"])
		assert.Equal(t, "list.example", rows[1]["domain"])
		assert.Empty(t, rows[1]["dst_ip"])
		assert.Contains(t, rows[1], "dst_ip")

		index, ok := rows[1]["rule_index"]
		assert.True(t, ok, "the row must hold the rule_index key")
		assert.Nil(t, index)
	})

	t.Run("csv", func(t *testing.T) {
		t.Parallel()

		assert.Equal(t,
			"time,source,decision,domain,dst_ip,port,protocol,method,path,status,flags,reason,rule_index\n"+
				stamp+",firewall,allow,,192.0.2.7,443,tcp,,,0,,rule=0,0\n"+
				stamp+",dns,allow,list.example,,0,dns,,,0,,,\n",
			run(t, "csv"))
	})

	t.Run("table", func(t *testing.T) {
		t.Parallel()

		lines := strings.Split(strings.TrimRight(run(t, "table"), "\n"), "\n")
		require.Len(t, lines, 3)

		assert.Equal(t, []string{
			"TIME", "SOURCE", "DECISION", "DOMAIN", "DST_IP", "PORT",
			"PROTOCOL", "METHOD", "PATH", "STATUS", "FLAGS", "REASON", "RULE_INDEX",
		}, strings.Fields(lines[0]))
		assert.Contains(t, lines[1], "192.0.2.7")
		assert.NotContains(t, lines[2], "192.0.2.7")
	})
}

func TestStatsTopCSV(t *testing.T) {
	t.Parallel()

	now := time.Now()

	dbPath := seedDB(t, []eventstore.Event{
		{
			Time:     now,
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionDeny,
			Domain:   "csv.example",
			Reason:   eventstore.ReasonBlockedMode,
		},
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

	early := time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC)
	late := time.Date(2020, 1, 3, 12, 0, 0, 0, time.UTC)

	dbPath := seedDB(t, []eventstore.Event{
		{Time: early, Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Domain: "ok.example"},
		{Time: early, Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Domain: "blocked.example"},
		{Time: late, Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Domain: "blocked.example"},
		{Time: early, Source: eventstore.SourceEnvoy, Decision: eventstore.DecisionAllow, Domain: "ok.example"},
		{Time: late, Source: eventstore.SourceEnvoy, Decision: eventstore.DecisionAllow, Domain: "ok.example"},
		{Time: late, Source: eventstore.SourceFirewall, Decision: eventstore.DecisionDeny, Domain: "blocked.example"},
	})

	type row struct {
		Source   eventstore.Source   `json:"source"`
		Decision eventstore.Decision `json:"decision"`
		Count    int64               `json:"count"`
	}

	// Every case passes --since, because the events are older than
	// the default window.
	since := []string{"--since", "2020-01-01T00:00:00Z"}

	tcs := map[string]struct {
		args []string
		want []row
	}{
		"all events": {
			want: []row{
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Count: 1},
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Count: 2},
				{Source: eventstore.SourceEnvoy, Decision: eventstore.DecisionAllow, Count: 2},
				{Source: eventstore.SourceFirewall, Decision: eventstore.DecisionDeny, Count: 1},
			},
		},
		"until bounds the window": {
			args: []string{"--until", "2020-01-02T00:00:00Z"},
			want: []row{
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Count: 1},
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Count: 1},
				{Source: eventstore.SourceEnvoy, Decision: eventstore.DecisionAllow, Count: 1},
			},
		},
		"until includes its own time": {
			args: []string{"--until", "2020-01-03T12:00:00Z", "--source", "firewall"},
			want: []row{
				{Source: eventstore.SourceFirewall, Decision: eventstore.DecisionDeny, Count: 1},
			},
		},
		"source selects one source": {
			args: []string{"--source", "dns"},
			want: []row{
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Count: 1},
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Count: 2},
			},
		},
		"source and until": {
			args: []string{"--source", "dns", "--until", "2020-01-02T00:00:00Z"},
			want: []row{
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Count: 1},
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Count: 1},
			},
		},
		"no event matches": {
			args: []string{"--source", "firewall", "--until", "2020-01-02T00:00:00Z"},
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cmd := statsCmd(config.NewUser())

			buf := &bytes.Buffer{}
			cmd.SetOut(buf)

			args := []string{"--db", dbPath, "--format", "json"}
			args = append(args, since...)
			cmd.SetArgs(append(args, tc.args...))

			require.NoError(t, cmd.ExecuteContext(t.Context()))

			var got []row

			require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestStatsLimitFlag checks which stats commands take --limit. The
// summary prints every pair of a source and a decision, so it rejects
// the flag.
func TestStatsLimitFlag(t *testing.T) {
	t.Parallel()

	now := time.Now()

	dbPath := seedDB(t, []eventstore.Event{
		{Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Domain: "blocked.example"},
	})

	// Each name is a command line. The words after the first word
	// are the arguments of the stats command.
	tcs := map[string]struct {
		err string
	}{
		"stats --limit 1":      {err: "unknown flag: --limit"},
		"stats top --limit 1":  {},
		"stats list --limit 1": {},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cmd := statsCmd(config.NewUser())
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(append(strings.Fields(name)[1:], "--db", dbPath))

			err := cmd.ExecuteContext(t.Context())
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)

				return
			}

			require.NoError(t, err)
		})
	}
}

func TestStatsMissingDB(t *testing.T) {
	t.Parallel()

	// Each name is a command line. The words after the first word
	// are the arguments of the stats command.
	tcs := map[string]struct{}{
		"stats":      {},
		"stats top":  {},
		"stats list": {},
	}

	for name := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dbPath := filepath.Join(t.TempDir(), "stats.db")

			cmd := statsCmd(config.NewUser())
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(append(strings.Fields(name)[1:], "--db", dbPath))

			err := cmd.ExecuteContext(t.Context())
			require.ErrorContains(t, err, "opening stats db")

			assert.NoFileExists(t, dbPath)
		})
	}
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
