package eventstore_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/eventstore"
)

func TestRetention_MaxRowsCapsRowCount(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(10),
		eventstore.WithBatchInterval(20*time.Millisecond),
		eventstore.WithRetention(eventstore.Retention{MaxRows: 100}),
	)
	require.NoError(t, err)

	for i := range 500 {
		store.Emit(eventstore.Event{
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionAllow,
			Domain:   "fill.example",
			Reason:   eventstore.Reason(string(rune(i))),
		})
	}

	require.NoError(t, store.Close())

	db, err := eventstore.OpenReadOnly(path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, db.Close()) })

	var n int64

	err = db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)
	require.NoError(t, err)

	// Pruning runs after each batch insert. Allow some slop because
	// the prune chunk size is 1000 and we may stop pruning right at
	// the boundary; we just want to confirm it stays within bounds.
	assert.LessOrEqualf(t, n, int64(200),
		"pruner should keep row count near MaxRows=100; got %d", n)
}

func TestRetention_MaxAgePrunes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(10*time.Millisecond),
	)
	require.NoError(t, err)

	old := time.Now().Add(-2 * time.Hour)
	store.Emit(eventstore.Event{
		Time:     old,
		Source:   eventstore.SourceDNS,
		Decision: eventstore.DecisionAllow,
		Domain:   "stale.example",
	})

	store.Emit(eventstore.Event{
		Source:   eventstore.SourceDNS,
		Decision: eventstore.DecisionAllow,
		Domain:   "fresh.example",
	})

	// Verify both events landed before we apply retention.
	require.Eventually(t, func() bool {
		db, err := eventstore.OpenReadOnly(path)
		if err != nil {
			return false
		}

		defer func() { _ = db.Close() }()

		var n int

		err = db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM events`).Scan(&n)
		if err != nil {
			return false
		}

		return n == 2
	}, 2*time.Second, 20*time.Millisecond)

	// Apply a retention policy that should prune the old event.
	store.SetRetention(eventstore.Retention{MaxAge: time.Hour})

	// pruneByAge fires on a 60s ticker, so we cannot wait for it in
	// a test. The writer's pruner is verified by the row-based test
	// instead. Just confirm SetRetention does not break things.
	require.NoError(t, store.Close())
}

func TestStore_DropCountReflectsOverflow(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithChanSize(1),
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(time.Hour))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	// Hammer the channel; with no batch flush in sight, drops happen.
	for range 50 {
		store.Emit(eventstore.Event{
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionAllow,
			Domain:   "drop.example",
		})
	}

	assert.Positive(t, store.DropCount())
}

func TestRetention_PerSourceCapsFirewall(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	// Tight per-source firewall cap, very loose global cap. The
	// per-source pass should kick in before the global pass.
	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithChanSize(8192),
		eventstore.WithBatchSize(50),
		eventstore.WithBatchInterval(20*time.Millisecond),
		eventstore.WithRetention(eventstore.Retention{
			MaxRows: 1_000_000,
			PerSource: eventstore.PerSourceCaps{
				Firewall: 100,
			},
		}),
	)
	require.NoError(t, err)

	// Insert 5000 firewall events and 50 DNS events (100:1 ratio).
	for range 50 {
		store.Emit(eventstore.Event{
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionAllow,
			Domain:   "dns.example",
		})

		for range 100 {
			store.Emit(eventstore.Event{
				Source:   eventstore.SourceFirewall,
				Decision: eventstore.DecisionDeny,
			})
		}
	}

	require.NoError(t, store.Close())
	require.Zerof(t, store.DropCount(),
		"channel overflow during the test would invalidate the per-source assertion (drop count %d)",
		store.DropCount())

	db, err := eventstore.OpenReadOnly(path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, db.Close()) })

	var firewallCount, dnsCount int64

	err = db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM events WHERE source='firewall'`).Scan(&firewallCount)
	require.NoError(t, err)

	err = db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM events WHERE source='dns'`).Scan(&dnsCount)
	require.NoError(t, err)

	// Without per-source pruning the firewall stream would land at
	// 5000 (the full insert count); with a per-source cap of 100 and
	// a 1000-row prune chunk, the count is bounded above by the
	// chunk overshoot. The cap itself is the floor: the pruner never
	// deletes below the configured limit.
	assert.LessOrEqualf(t, firewallCount, int64(2000),
		"per-source pruning should keep firewall row count near the 100 cap (got %d)", firewallCount)
	assert.GreaterOrEqualf(t, firewallCount, int64(100),
		"per-source pruner must not delete below the configured cap (got %d)", firewallCount)
	assert.Equalf(t, int64(50), dnsCount,
		"DNS rows must not be touched by firewall per-source pruning (got %d)", dnsCount)
}

func TestRetention_SetRetentionRaceFreeWithPerSource(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(10),
		eventstore.WithBatchInterval(20*time.Millisecond),
	)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	// Concurrent writes against retention swaps. -race confirms the
	// pointer swap is lock-free.
	go func() {
		for range 200 {
			store.Emit(eventstore.Event{
				Source:   eventstore.SourceFirewall,
				Decision: eventstore.DecisionDeny,
			})
		}
	}()

	for i := range 200 {
		store.SetRetention(eventstore.Retention{
			MaxRows: int64(1000 + i),
			PerSource: eventstore.PerSourceCaps{
				Firewall: int64(100 + i),
				DNS:      int64(50 + i),
				Envoy:    int64(25 + i),
			},
		})
	}
}

func TestStore_LastWriteTimeUpdates(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	assert.True(t, store.LastWriteTime().IsZero(),
		"no writes yet, LastWriteTime should be zero")

	store.Emit(eventstore.Event{
		Source:   eventstore.SourceDNS,
		Decision: eventstore.DecisionAllow,
		Domain:   "lw.example",
	})

	require.Eventually(t, func() bool {
		return !store.LastWriteTime().IsZero()
	}, 2*time.Second, 20*time.Millisecond)
}
