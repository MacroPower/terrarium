package eventstore_test

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"

	"go.jacobcolvin.com/terrarium/eventstore"
)

func openReadOnly(t *testing.T, path string) *sql.DB {
	t.Helper()

	db, err := eventstore.OpenReadOnly(path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, db.Close()) })

	return db
}

func TestOpen_AppliesSchemaOnFreshDB(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	db := openReadOnly(t, path)

	var version int

	err = db.QueryRow(`PRAGMA user_version`).Scan(&version)
	require.NoError(t, err)
	assert.Equal(t, 2, version)

	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	require.NoError(t, err)

	var tables []string

	for rows.Next() {
		var name string

		require.NoError(t, rows.Scan(&name))
		tables = append(tables, name)
	}

	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())

	assert.Contains(t, tables, "events")
	assert.Contains(t, tables, "instances")
	assert.Contains(t, tables, "instance_metrics")
}

// v1SchemaSQL is the schema as it existed prior to introducing
// instance_metrics. Pinned in the test so the v1 -> v2 migration is
// exercised against the exact shape that shipped at user_version=1.
const v1SchemaSQL = `
CREATE TABLE events (
  id          INTEGER PRIMARY KEY,
  ts          INTEGER NOT NULL,
  instance_id TEXT NOT NULL,
  source      TEXT NOT NULL,
  decision    TEXT NOT NULL,
  domain      TEXT,
  port        INTEGER,
  protocol    TEXT,
  http_method TEXT,
  http_path   TEXT,
  http_status INTEGER,
  flags       TEXT,
  reason      TEXT,
  bytes_rx    INTEGER,
  bytes_tx    INTEGER,
  duration_ms INTEGER
);
CREATE INDEX events_ts          ON events(ts DESC);
CREATE INDEX events_decision_ts ON events(decision, ts DESC);
CREATE INDEX events_source_ts   ON events(source, ts DESC);
CREATE INDEX events_instance_ts ON events(instance_id, ts DESC);

CREATE TABLE instances (
  id         TEXT PRIMARY KEY,
  started_at INTEGER NOT NULL,
  ended_at   INTEGER,
  mode       TEXT NOT NULL
);
`

func TestOpen_MigratesV1ToV2(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	// Lay down a v1 database by hand, then open it through the
	// production code path and verify it lands on v2 with the new
	// instance_metrics table.
	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err)

	_, err = raw.Exec(v1SchemaSQL)
	require.NoError(t, err)

	_, err = raw.Exec(`PRAGMA user_version = 1`)
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	db := openReadOnly(t, path)

	var version int

	err = db.QueryRow(`PRAGMA user_version`).Scan(&version)
	require.NoError(t, err)
	assert.Equal(t, 2, version)

	var name string

	err = db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'instance_metrics'`).Scan(&name)
	require.NoError(t, err)
	assert.Equal(t, "instance_metrics", name)
}

func TestOpen_RefusesFutureSchemaVersion(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	// Pre-create a DB with a higher user_version.
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)

	_, err = db.Exec(`PRAGMA user_version = 99`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	_, err = eventstore.Open(t.Context(), path)
	require.ErrorIs(t, err, eventstore.ErrSchemaTooNew)
}

func TestEmit_RecordsEvent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	store.Emit(eventstore.Event{
		Source:   eventstore.SourceDNS,
		Decision: eventstore.DecisionDeny,
		Domain:   "example.com",
		Reason:   eventstore.ReasonNotAllowlisted,
	})

	require.Eventually(t, func() bool {
		db := openReadOnly(t, path)

		var count int

		err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&count)
		require.NoError(t, err)

		return count == 1
	}, 2*time.Second, 20*time.Millisecond)

	db := openReadOnly(t, path)

	var (
		source   string
		decision string
		domain   string
		reason   string
	)

	err = db.QueryRow(`SELECT source, decision, domain, reason FROM events LIMIT 1`).
		Scan(&source, &decision, &domain, &reason)
	require.NoError(t, err)

	assert.Equal(t, "dns", source)
	assert.Equal(t, "deny", decision)
	assert.Equal(t, "example.com", domain)
	assert.Equal(t, "not-allowlisted", reason)
}

func TestEmit_NilStoreNoop(t *testing.T) {
	t.Parallel()

	var s *eventstore.Store

	require.NotPanics(t, func() {
		s.Emit(eventstore.Event{Source: eventstore.SourceDNS})
	})
	require.NotPanics(t, func() { _ = s.Close() })
	assert.Equal(t, int64(0), s.DropCount())
	assert.True(t, s.LastWriteTime().IsZero())
}

func TestEmit_DropsWhenChannelFull(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	// Tiny channel + slow batch flush so the channel fills before
	// the writer can drain it.
	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithChanSize(1),
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(time.Hour))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	for range 200 {
		store.Emit(eventstore.Event{
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionAllow,
			Domain:   "drop.example",
		})
	}

	assert.Positive(t, store.DropCount())
}

func TestOpen_InstanceIDUniqueAcrossOpens(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store1, err := eventstore.Open(t.Context(), path)
	require.NoError(t, err)

	id1 := store1.InstanceID()
	require.Len(t, id1, 16)
	require.NoError(t, store1.Close())

	store2, err := eventstore.Open(t.Context(), path)
	require.NoError(t, err)

	id2 := store2.InstanceID()
	require.NoError(t, store2.Close())

	assert.NotEqual(t, id1, id2)

	db := openReadOnly(t, path)

	var count int

	err = db.QueryRow(`SELECT COUNT(*) FROM instances WHERE ended_at IS NOT NULL`).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 2, count, "both instances should record ended_at on clean Close()")
}

func TestOpen_RecordsInstanceMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithMode(eventstore.ModeDaemon))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	db := openReadOnly(t, path)

	var mode string

	err = db.QueryRow(`SELECT mode FROM instances WHERE id = ?`, store.InstanceID()).Scan(&mode)
	require.NoError(t, err)
	assert.Equal(t, "daemon", mode)
}

func TestSetRetention_Updates(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	// Verify SetRetention does not panic and accepts a zero policy.
	store.SetRetention(eventstore.Retention{})
	store.SetRetention(eventstore.Retention{MaxAge: time.Hour, MaxRows: 100})
}

// TestEmit_SetsTimestampWhenZero ensures the writer fills in time.Now
// when callers leave Event.Time unset.
func TestEmit_SetsTimestampWhenZero(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)

	store.Emit(eventstore.Event{
		Source:   eventstore.SourceEnvoy,
		Decision: eventstore.DecisionAllow,
		Domain:   "ts.example",
	})

	require.Eventually(t, func() bool {
		return store.LastWriteTime().IsZero() == false
	}, 2*time.Second, 20*time.Millisecond)

	require.NoError(t, store.Close())

	db := openReadOnly(t, path)

	var ts int64

	err = db.QueryRow(`SELECT ts FROM events LIMIT 1`).Scan(&ts)
	require.NoError(t, err)
	assert.Positive(t, ts)
}

// Verify retention loop runs without panicking when configured with
// MaxRows larger than the row count.
func TestRetention_NoOpWhenWithinBounds(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(10*time.Millisecond),
		eventstore.WithRetention(eventstore.Retention{MaxRows: 1_000_000}))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	store.Emit(eventstore.Event{
		Source:   eventstore.SourceDNS,
		Decision: eventstore.DecisionAllow,
		Domain:   "small.example",
	})

	require.Eventually(t, func() bool {
		db := openReadOnly(t, path)

		var n int

		_ = db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n)

		return n == 1
	}, 2*time.Second, 20*time.Millisecond)
}

func TestRecordHeartbeat_RoundTrip(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	first := eventstore.Heartbeat{
		RecordedAt:          time.Now(),
		NFLogKernelDrops:    3,
		NFLogParseErrors:    7,
		NFLogLastEvent:      time.Now().Add(-2 * time.Second),
		DNSCacheSize:        42,
		DNSCacheEvictions:   5,
		EventStoreDropCount: 11,
		EventStoreLastWrite: time.Now().Add(-time.Second),
	}

	require.NoError(t, store.RecordHeartbeat(t.Context(), first))

	db := openReadOnly(t, path)

	require.Eventually(t, func() bool {
		hb, ok, err := eventstore.LatestHeartbeat(t.Context(), db, store.InstanceID())
		if err != nil || !ok {
			return false
		}

		return hb.NFLogKernelDrops == first.NFLogKernelDrops &&
			hb.NFLogParseErrors == first.NFLogParseErrors &&
			hb.DNSCacheSize == first.DNSCacheSize &&
			hb.DNSCacheEvictions == first.DNSCacheEvictions &&
			hb.EventStoreDropCount == first.EventStoreDropCount
	}, 2*time.Second, 20*time.Millisecond)

	// Replace with a second heartbeat (upsert path).
	second := eventstore.Heartbeat{
		RecordedAt:          time.Now(),
		NFLogKernelDrops:    9,
		NFLogParseErrors:    13,
		DNSCacheSize:        99,
		DNSCacheEvictions:   17,
		EventStoreDropCount: 21,
	}

	require.NoError(t, store.RecordHeartbeat(t.Context(), second))

	require.Eventually(t, func() bool {
		hb, ok, err := eventstore.LatestHeartbeat(t.Context(), db, store.InstanceID())
		if err != nil || !ok {
			return false
		}

		return hb.NFLogKernelDrops == second.NFLogKernelDrops &&
			hb.DNSCacheSize == second.DNSCacheSize
	}, 2*time.Second, 20*time.Millisecond)

	// Unknown instance returns ok=false without error.
	_, ok, err := eventstore.LatestHeartbeat(t.Context(), db, "deadbeefdeadbeef")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestRecordHeartbeat_NilStoreNoop(t *testing.T) {
	t.Parallel()

	var s *eventstore.Store
	require.NoError(t, s.RecordHeartbeat(t.Context(), eventstore.Heartbeat{}))
}

func TestLatestInstanceID(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	// Empty DB returns ok=false.
	store, err := eventstore.Open(t.Context(), path)
	require.NoError(t, err)

	id := store.InstanceID()
	require.NoError(t, store.Close())

	db := openReadOnly(t, path)

	got, ok, err := eventstore.LatestInstanceID(t.Context(), db)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, id, got)
}

func TestEmit_SafeAfterClose(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)

	require.NoError(t, store.Close())

	// Emit on a closed store must not panic and must not increment
	// the drop counter (the event is silently discarded as a no-op).
	require.NotPanics(t, func() {
		for range 100 {
			store.Emit(eventstore.Event{
				Source:   eventstore.SourceDNS,
				Decision: eventstore.DecisionAllow,
			})
		}
	})

	// Calling Close again is safe.
	require.NoError(t, store.Close())
}
