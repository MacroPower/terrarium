package main

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/eventstore"
)

func TestStartHeartbeat_NilStoreReturnsNoop(t *testing.T) {
	t.Parallel()

	stop := startHeartbeat(t.Context(), nil, nil)
	require.NotNil(t, stop)

	// Cancel must be safe to call repeatedly.
	stop()
	stop()
}

func TestStartHeartbeat_RecordsAtStart(t *testing.T) {
	t.Parallel()

	store, path := openHeartbeatStore(t)

	// The interval is longer than the test, so the heartbeat of the
	// start is the only one before the test ends.
	stop := startHeartbeatEvery(t.Context(), store, func(h *eventstore.Heartbeat) {
		h.DNSCacheSize = 7
	}, time.Hour)
	t.Cleanup(stop)

	r := openReader(t, path)

	require.Eventually(t, func() bool {
		_, ok, err := r.LatestHeartbeat(t.Context(), store.InstanceID())
		return err == nil && ok
	}, 2*time.Second, 20*time.Millisecond)

	hb, ok, err := r.LatestHeartbeat(t.Context(), store.InstanceID())
	require.NoError(t, err)
	require.True(t, ok)
	assert.WithinDuration(t, time.Now(), hb.RecordedAt, time.Minute)
	assert.Equal(t, int64(7), hb.DNSCacheSize)
}

func TestStartHeartbeat_RecordsTick(t *testing.T) {
	t.Parallel()

	store, path := openHeartbeatStore(t)

	// Each heartbeat holds its own number, so a number past 1 is the
	// heartbeat of a tick.
	var snapshots atomic.Int64

	// Tight tick so tests do not wait the production 60s.
	stop := startHeartbeatEvery(t.Context(), store, func(h *eventstore.Heartbeat) {
		h.DNSCacheSize = snapshots.Add(1)
	}, 20*time.Millisecond)
	t.Cleanup(stop)

	r := openReader(t, path)

	require.Eventually(t, func() bool {
		hb, ok, err := r.LatestHeartbeat(t.Context(), store.InstanceID())
		return err == nil && ok && hb.DNSCacheSize > 1
	}, 2*time.Second, 20*time.Millisecond)
}

func TestStartHeartbeat_NilCounters(t *testing.T) {
	t.Parallel()

	store, path := openHeartbeatStore(t)

	stop := startHeartbeatEvery(t.Context(), store, nil, 20*time.Millisecond)
	t.Cleanup(stop)

	r := openReader(t, path)

	require.Eventually(t, func() bool {
		_, ok, err := r.LatestHeartbeat(t.Context(), store.InstanceID())
		return err == nil && ok
	}, 2*time.Second, 20*time.Millisecond)

	hb, ok, err := r.LatestHeartbeat(t.Context(), store.InstanceID())
	require.NoError(t, err)
	require.True(t, ok)
	assert.Zero(t, hb.NFLogKernelDrops)
	assert.Zero(t, hb.NFLogParseErrors)
	assert.True(t, hb.NFLogLastEvent.IsZero())
	assert.Zero(t, hb.DNSCacheSize)
	assert.Zero(t, hb.DNSCacheEvictions)
}

func TestStartHeartbeat_CancelRecordsFinal(t *testing.T) {
	t.Parallel()

	store, path := openHeartbeatStore(t)

	var snapshots atomic.Int64

	// The interval is longer than the test, so the test sees only the
	// heartbeat of the start and the heartbeat of the stop.
	stop := startHeartbeatEvery(t.Context(), store, func(h *eventstore.Heartbeat) {
		h.DNSCacheSize = snapshots.Add(1)
	}, time.Hour)

	r := openReader(t, path)

	// The store drops a heartbeat that arrives before it wrote the
	// one before, so wait for the heartbeat of the start.
	require.Eventually(t, func() bool {
		hb, ok, err := r.LatestHeartbeat(t.Context(), store.InstanceID())
		return err == nil && ok && hb.DNSCacheSize == 1
	}, 2*time.Second, 20*time.Millisecond)

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

	require.Eventually(t, func() bool {
		hb, ok, err := r.LatestHeartbeat(t.Context(), store.InstanceID())
		return err == nil && ok && hb.DNSCacheSize == 2
	}, 2*time.Second, 20*time.Millisecond)
}

// openHeartbeatStore opens an event store in a new directory and
// returns it with the path of its database. The store closes when the
// test ends.
func openHeartbeatStore(t *testing.T) (*eventstore.Store, string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	return store, path
}

func openReader(t *testing.T, path string) *eventstore.Reader {
	t.Helper()

	r, err := eventstore.OpenReader(t.Context(), path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, r.Close()) })

	return r
}
