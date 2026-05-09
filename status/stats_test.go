package status

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/eventstore"
)

// statsCfg returns a minimal config with stats enabled and the
// SQLite path pointed at dbPath.
func statsCfg(dbPath string) *config.Config {
	return &config.Config{
		Stats: &config.Stats{
			Enabled: true,
			Path:    dbPath,
		},
	}
}

// renderReportInternal runs Render against the given report.
func renderReportInternal(t *testing.T, r Report) string {
	t.Helper()

	var buf bytes.Buffer

	require.NoError(t, Render(&buf, r))

	return buf.String()
}

func TestCollectStatsDisabled(t *testing.T) {
	t.Parallel()

	got := collectStats(t.Context(), &config.Config{})
	assert.False(t, got.Enabled)
	assert.Empty(t, got.DBPath)
}

func TestCollectStatsHeartbeatPresent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)

	now := time.Now()
	require.NoError(t, store.RecordHeartbeat(t.Context(), eventstore.Heartbeat{
		RecordedAt:        now,
		NFLogKernelDrops:  3,
		NFLogParseErrors:  7,
		DNSCacheSize:      42,
		DNSCacheEvictions: 5,
	}))

	require.NoError(t, store.Close())

	got := collectStats(t.Context(), statsCfg(path))
	require.NoError(t, got.Err)

	assert.True(t, got.Enabled)
	assert.Equal(t, uint64(3), got.NFLogKernelDrops)
	assert.Equal(t, uint64(7), got.NFLogParseErrors)
	assert.Equal(t, int64(42), got.DNSCacheSize)
	assert.Equal(t, uint64(5), got.DNSCacheEvictions)
	assert.WithinDuration(t, now, got.HeartbeatRecordedAt, time.Second)
}

func TestCollectStatsHeartbeatAbsent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)
	require.NoError(t, store.Close())

	got := collectStats(t.Context(), statsCfg(path))
	require.NoError(t, got.Err)
	assert.True(t, got.Enabled)
	assert.True(t, got.HeartbeatRecordedAt.IsZero())
}

func TestRenderStatsHeartbeatStale(t *testing.T) {
	t.Parallel()

	r := Report{
		Stats: StatsSection{
			Enabled:             true,
			DBPath:              "/tmp/stats.db",
			HeartbeatRecordedAt: time.Now().Add(-5 * time.Minute),
			DNSCacheSize:        10,
			NFLogLastEvent:      time.Now().Add(-30 * time.Second),
		},
	}

	out := renderReportInternal(t, r)
	assert.Contains(t, out, "(stale)")
	// Sub-sections still render with the last known values.
	assert.Contains(t, out, "NFLOG")
	assert.Contains(t, out, "DNS CACHE")
	assert.Contains(t, out, "FIREWALL EVENTS (1h)")
}

func TestRenderStatsHeartbeatFresh(t *testing.T) {
	t.Parallel()

	r := Report{
		Stats: StatsSection{
			Enabled:             true,
			DBPath:              "/tmp/stats.db",
			HeartbeatRecordedAt: time.Now().Add(-5 * time.Second),
			DNSCacheSize:        10,
		},
	}

	out := renderReportInternal(t, r)
	assert.NotContains(t, out, "(stale)")
	assert.Contains(t, out, "NFLOG")
	assert.Contains(t, out, "DNS CACHE")
	assert.Contains(t, out, "entries:")
}

func TestRenderStatsHeartbeatNoneYet(t *testing.T) {
	t.Parallel()

	r := Report{
		Stats: StatsSection{
			Enabled: true,
			DBPath:  "/tmp/stats.db",
		},
	}

	out := renderReportInternal(t, r)
	assert.Contains(t, out, "(none yet)")
	assert.NotContains(t, out, "NFLOG")
	assert.NotContains(t, out, "DNS CACHE")
	assert.NotContains(t, out, "FIREWALL EVENTS")
}

func TestRenderStatsNullDomainRateRendering(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		rate    float64
		nullCnt int64
		events  int64
		want    string
	}{
		"zero events": {rate: 0, nullCnt: 0, events: 0, want: "0.0% (0 / 0)"},
		"all NULL":    {rate: 1.0, nullCnt: 5, events: 5, want: "100.0% (5 / 5)"},
		"none NULL":   {rate: 0.0, nullCnt: 0, events: 5, want: "0.0% (0 / 5)"},
		"mixed":       {rate: 2.0 / 3.0, nullCnt: 2, events: 3, want: "66.7% (2 / 3)"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := Report{
				Stats: StatsSection{
					Enabled:                  true,
					DBPath:                   "/tmp/stats.db",
					HeartbeatRecordedAt:      time.Now(),
					FirewallNullDomainRate1h: tc.rate,
					FirewallNullDomain1h:     tc.nullCnt,
					FirewallEvents1h:         tc.events,
				},
			}

			out := renderReportInternal(t, r)
			assert.Contains(t, out, tc.want)
		})
	}
}

func TestCollectStatsNullDomainRate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(10*time.Millisecond))
	require.NoError(t, err)

	now := time.Now()

	// 3 firewall events: 2 null-domain, 1 with a domain. All inside
	// the 1h window.
	store.Emit(eventstore.Event{
		Time: now, Source: eventstore.SourceFirewall, Decision: eventstore.DecisionDeny,
	})
	store.Emit(eventstore.Event{
		Time: now, Source: eventstore.SourceFirewall, Decision: eventstore.DecisionDeny,
	})
	store.Emit(eventstore.Event{
		Time: now, Source: eventstore.SourceFirewall, Decision: eventstore.DecisionDeny,
		Domain: "resolved.example",
	})
	// Non-firewall event must not contribute to the rate.
	store.Emit(eventstore.Event{
		Time: now, Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow,
	})

	require.NoError(t, store.Close())

	got := collectStats(t.Context(), statsCfg(path))
	require.NoError(t, got.Err)
	assert.Equal(t, int64(3), got.FirewallEvents1h)
	assert.InDelta(t, 2.0/3.0, got.FirewallNullDomainRate1h, 1e-9)
}

func TestCollectStatsNullDomainRateOutsideCutoff(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(10*time.Millisecond))
	require.NoError(t, err)

	// One inside (NULL), one outside (with domain). Only the inside
	// event should count.
	store.Emit(eventstore.Event{
		Time:     time.Now(),
		Source:   eventstore.SourceFirewall,
		Decision: eventstore.DecisionDeny,
	})
	store.Emit(eventstore.Event{
		Time:     time.Now().Add(-2 * time.Hour),
		Source:   eventstore.SourceFirewall,
		Decision: eventstore.DecisionDeny,
		Domain:   "old.example",
	})

	require.NoError(t, store.Close())

	got := collectStats(t.Context(), statsCfg(path))
	require.NoError(t, got.Err)
	assert.Equal(t, int64(1), got.FirewallEvents1h)
	assert.InDelta(t, 1.0, got.FirewallNullDomainRate1h, 1e-9)
}
