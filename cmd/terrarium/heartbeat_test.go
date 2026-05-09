package main

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/dnscache"
	"go.jacobcolvin.com/terrarium/eventstore"
)

func TestStartHeartbeat_NilStoreReturnsNoop(t *testing.T) {
	t.Parallel()

	stop := startHeartbeat(t.Context(), &infra{})
	require.NotNil(t, stop)

	// Cancel must be safe to call repeatedly.
	stop()
	stop()
}

func TestStartHeartbeat_RecordsTick(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	cache := dnscache.New()
	t.Cleanup(cache.Close)

	inf := &infra{
		eventStore: store,
		dnsCache:   cache,
	}

	// Tight tick so tests do not wait the production 60s.
	stop := startHeartbeatEvery(t.Context(), inf, 20*time.Millisecond)
	t.Cleanup(stop)

	db := openReadOnlyDB(t, path)

	require.Eventually(t, func() bool {
		hb, ok, err := eventstore.LatestHeartbeat(t.Context(), db, store.InstanceID())
		if err != nil || !ok {
			return false
		}

		return !hb.RecordedAt.IsZero()
	}, 2*time.Second, 20*time.Millisecond)
}

func TestStartHeartbeat_TolerantOfNilSubsystems(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	// nflogReader nil (firewall logging disabled), dnsCache nil
	// (unrestricted-mode safety) — heartbeat must still tick.
	inf := &infra{eventStore: store}

	stop := startHeartbeatEvery(t.Context(), inf, 20*time.Millisecond)
	t.Cleanup(stop)

	db := openReadOnlyDB(t, path)

	require.Eventually(t, func() bool {
		_, ok, err := eventstore.LatestHeartbeat(t.Context(), db, store.InstanceID())
		return err == nil && ok
	}, 2*time.Second, 20*time.Millisecond)
}

func TestStartHeartbeat_CancelStops(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	cache := dnscache.New()
	t.Cleanup(cache.Close)

	inf := &infra{eventStore: store, dnsCache: cache}

	stop := startHeartbeatEvery(t.Context(), inf, 20*time.Millisecond)

	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("startHeartbeat did not stop after cancel")
	}
}

func openReadOnlyDB(t *testing.T, path string) *sql.DB {
	t.Helper()

	db, err := eventstore.OpenReadOnly(path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, db.Close()) })

	return db
}
