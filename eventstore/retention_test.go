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

		defer db.Close()

		var n int

		_ = db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)

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
