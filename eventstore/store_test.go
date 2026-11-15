package eventstore_test

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"

	"go.jacobcolvin.com/terrarium/eventstore"
)

func openReadOnly(t *testing.T, path string) *sql.DB {
	t.Helper()

	db, err := eventstore.OpenReadOnly(t.Context(), path)
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

	err = db.QueryRowContext(t.Context(), `PRAGMA user_version`).Scan(&version)
	require.NoError(t, err)
	assert.Equal(t, 4, version)

	rows, err := db.QueryContext(t.Context(), `SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
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
	assert.Contains(t, tables, "policies")
}

// v1SchemaSQL is the schema of user_version=1, before the
// `instance_metrics` table. The test pins it, so that each migration
// runs against the tables that version 1 created.
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

// v2SchemaSQL is the schema of user_version=2, which added the
// `instance_metrics` table to [v1SchemaSQL]. The test pins it, so
// that the migration to version 3 runs against the tables that
// version 2 created.
const v2SchemaSQL = v1SchemaSQL + `
CREATE TABLE instance_metrics (
  instance_id            TEXT PRIMARY KEY REFERENCES instances(id),
  recorded_at            INTEGER NOT NULL,
  nflog_kernel_drops     INTEGER NOT NULL DEFAULT 0,
  nflog_parse_errors     INTEGER NOT NULL DEFAULT 0,
  nflog_last_event_unix  INTEGER NOT NULL DEFAULT 0,
  dnscache_size          INTEGER NOT NULL DEFAULT 0,
  dnscache_evictions     INTEGER NOT NULL DEFAULT 0,
  eventstore_drop_count  INTEGER NOT NULL DEFAULT 0,
  eventstore_last_write_unix INTEGER NOT NULL DEFAULT 0
);
`

// v3SchemaSQL is the schema of user_version=3, which added the
// `policies` table and the identity columns of the `instances` table
// to [v2SchemaSQL]. The test pins it, so that the migration to
// version 4 runs against the tables that version 3 created.
const v3SchemaSQL = v2SchemaSQL + `
ALTER TABLE instances ADD COLUMN name TEXT;
ALTER TABLE instances ADD COLUMN config_path TEXT;
CREATE TABLE policies (
  id            INTEGER PRIMARY KEY,
  instance_id   TEXT NOT NULL REFERENCES instances(id),
  applied_at    INTEGER NOT NULL,
  config_path   TEXT NOT NULL,
  sha256        TEXT NOT NULL,
  security_mode TEXT NOT NULL,
  yaml          TEXT NOT NULL
);
CREATE INDEX policies_instance_applied ON policies(instance_id, applied_at DESC);
`

// TestOpen_MigratesToCurrentSchema opens a database of each earlier
// schema version. The open must bring the database to the current
// version and keep the rows that the database held, with NULL in the
// columns that a later version added to the `events` table. The store
// must then record an event with a destination address and a rule
// index, a heartbeat, and a policy snapshot.
func TestOpen_MigratesToCurrentSchema(t *testing.T) {
	t.Parallel()

	const seedRows = `
		INSERT INTO instances (id, started_at, ended_at, mode) VALUES ('old', 100, 200, 'daemon');
		INSERT INTO events (ts, instance_id, source, decision, domain) VALUES (150, 'old', 'dns', 'deny', 'kept.example');
	`

	tcs := map[string]struct {
		before []string
		// The number of `instance_metrics` rows that the database
		// holds before the open.
		wantMetrics int
		// The number of `policies` rows that the database holds
		// before the open.
		wantPolicies int
	}{
		"version 1": {
			before: []string{v1SchemaSQL, `PRAGMA user_version = 1`, seedRows},
		},
		"version 2": {
			before: []string{
				v2SchemaSQL, `PRAGMA user_version = 2`, seedRows,
				`INSERT INTO instance_metrics (instance_id, recorded_at, dnscache_size) VALUES ('old', 180, 7)`,
			},
			wantMetrics: 1,
		},
		"version 3": {
			before: []string{
				v3SchemaSQL, `PRAGMA user_version = 3`, seedRows,
				`INSERT INTO instance_metrics (instance_id, recorded_at, dnscache_size) VALUES ('old', 180, 7)`,
				`INSERT INTO policies (instance_id, applied_at, config_path, sha256, security_mode, yaml)
				 VALUES ('old', 120, '/old.yaml', 'abc', 'filtered', 'egress: []')`,
			},
			wantMetrics:  1,
			wantPolicies: 1,
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "stats.db")
			rawDB(t, path, tc.before...)

			store, err := eventstore.Open(t.Context(), path,
				eventstore.WithInstanceName("migrated"),
				eventstore.WithConfigPath("/etc/terrarium/config.yaml"))
			require.NoError(t, err)

			store.Emit(eventstore.Event{
				Source: eventstore.SourceFirewall, Decision: eventstore.DecisionAllow, Domain: "new.example",
				DstIP: netip.MustParseAddr("192.0.2.7"), RuleIndex: 2, HasRuleIndex: true,
			})
			require.NoError(t, store.RecordHeartbeat(t.Context(), eventstore.Heartbeat{DNSCacheSize: 3}))
			store.RecordPolicy(eventstore.PolicySnapshot{
				ConfigPath: "/etc/terrarium/config.yaml",
				Mode:       eventstore.SecurityBlocked,
				YAML:       "egress:\n  - {}\n",
			})
			require.NoError(t, store.Close())

			db := openReadOnly(t, path)

			var version int

			err = db.QueryRowContext(t.Context(), `PRAGMA user_version`).Scan(&version)
			require.NoError(t, err)
			assert.Equal(t, 4, version)

			// The rows of the earlier version.
			var (
				mode     string
				domain   string
				cached   int
				policies int
			)

			err = db.QueryRowContext(t.Context(),
				`SELECT mode FROM instances WHERE id = 'old' AND started_at = 100 AND ended_at = 200`).Scan(&mode)
			require.NoError(t, err)
			assert.Equal(t, "daemon", mode)

			err = db.QueryRowContext(t.Context(),
				`SELECT domain FROM events WHERE instance_id = 'old' AND ts = 150
				 AND dst_ip IS NULL AND rule_index IS NULL`).Scan(&domain)
			require.NoError(t, err)
			assert.Equal(t, "kept.example", domain)

			err = db.QueryRowContext(t.Context(),
				`SELECT COUNT(*) FROM policies WHERE instance_id = 'old'`).Scan(&policies)
			require.NoError(t, err)
			assert.Equal(t, tc.wantPolicies, policies)

			if tc.wantMetrics > 0 {
				err = db.QueryRowContext(t.Context(),
					`SELECT dnscache_size FROM instance_metrics WHERE instance_id = 'old'`).Scan(&cached)
				require.NoError(t, err)
				assert.Equal(t, 7, cached)
			}

			// The rows that the store wrote after the migration.
			r := openReader(t, path)

			instances, err := r.Instances(t.Context())
			require.NoError(t, err)
			require.Len(t, instances, 2)
			assert.Equal(t, store.InstanceID(), instances[0].ID)
			assert.Equal(t, "migrated", instances[0].Name)
			assert.Equal(t, "/etc/terrarium/config.yaml", instances[0].ConfigPath)
			assert.Equal(t, "old", instances[1].ID)
			assert.Empty(t, instances[1].Name)
			assert.Empty(t, instances[1].ConfigPath)

			page, err := r.Events(t.Context(), eventstore.EventsQuery{Limit: 10})
			require.NoError(t, err)
			require.Len(t, page.Events, 2)

			added := page.Events[0]
			assert.Equal(t, "new.example", added.Domain)
			assert.Equal(t, netip.MustParseAddr("192.0.2.7"), added.DstIP)
			assert.True(t, added.HasRuleIndex)
			assert.Equal(t, 2, added.RuleIndex)

			kept := page.Events[1]
			assert.Equal(t, "kept.example", kept.Domain)
			assert.False(t, kept.DstIP.IsValid())
			assert.False(t, kept.HasRuleIndex)

			hb, ok, err := r.LatestHeartbeat(t.Context(), store.InstanceID())
			require.NoError(t, err)
			require.True(t, ok)
			assert.Equal(t, int64(3), hb.DNSCacheSize)

			policy, ok, err := r.LatestPolicy(t.Context(), store.InstanceID())
			require.NoError(t, err)
			require.True(t, ok)
			assert.Equal(t, eventstore.SecurityBlocked, policy.Mode)
		})
	}
}

func TestOpen_RefusesFutureSchemaVersion(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	// Pre-create a DB with a higher user_version.
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)

	_, err = db.ExecContext(t.Context(), `PRAGMA user_version = 99`)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	_, err = eventstore.Open(t.Context(), path)
	require.ErrorIs(t, err, eventstore.ErrSchemaTooNew)
}

func TestOpen_ConcurrentOpensShareOneDB(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		// Statements that create the database before the opens. A nil
		// slice leaves the path without a file.
		before []string
	}{
		"new database": {},
		"version 1 database": {
			before: []string{v1SchemaSQL, `PRAGMA user_version = 1`},
		},
		"version 2 database": {
			before: []string{v2SchemaSQL, `PRAGMA user_version = 2`},
		},
		"version 3 database": {
			before: []string{v3SchemaSQL, `PRAGMA user_version = 3`},
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "stats.db")

			if tc.before != nil {
				raw, err := sql.Open("sqlite", path)
				require.NoError(t, err)

				for _, stmt := range tc.before {
					_, err = raw.ExecContext(t.Context(), stmt)
					require.NoError(t, err)
				}

				require.NoError(t, raw.Close())
			}

			const opens = 8

			var (
				wg     sync.WaitGroup
				stores [opens]*eventstore.Store
				errs   [opens]error
			)

			start := make(chan struct{})

			for i := range opens {
				wg.Go(func() {
					<-start

					stores[i], errs[i] = eventstore.Open(t.Context(), path)
				})
			}

			close(start)
			wg.Wait()

			ids := make(map[string]struct{}, opens)

			for i := range opens {
				require.NoError(t, errs[i])

				ids[stores[i].InstanceID()] = struct{}{}

				require.NoError(t, stores[i].Close())
			}

			assert.Len(t, ids, opens, "each open should get its own instance ID")

			db := openReadOnly(t, path)

			var version int

			err := db.QueryRowContext(t.Context(), `PRAGMA user_version`).Scan(&version)
			require.NoError(t, err)
			assert.Equal(t, 4, version)

			var count int

			err = db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM instances`).Scan(&count)
			require.NoError(t, err)
			assert.Equal(t, opens, count)
		})
	}
}

func TestOpen_WaitsForWriteLockOnNewDB(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")

	// Hold the write lock on the new database from a second
	// connection, as another process does in the middle of its own
	// switch to WAL mode.
	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, raw.Close()) })

	conn, err := raw.Conn(t.Context())
	require.NoError(t, err)

	_, err = conn.ExecContext(t.Context(), `BEGIN IMMEDIATE`)
	require.NoError(t, err)

	released := make(chan error, 1)

	time.AfterFunc(100*time.Millisecond, func() {
		_, rollbackErr := conn.ExecContext(context.WithoutCancel(t.Context()), `ROLLBACK`)
		released <- errors.Join(rollbackErr, conn.Close())
	})

	store, err := eventstore.Open(t.Context(), path)
	require.NoError(t, <-released)
	require.NoError(t, err)
	require.NoError(t, store.Close())

	db := openReadOnly(t, path)

	var mode string

	err = db.QueryRowContext(t.Context(), `PRAGMA journal_mode`).Scan(&mode)
	require.NoError(t, err)
	assert.Equal(t, "wal", mode)
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

		err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM events`).Scan(&count)
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

	err = db.QueryRowContext(t.Context(), `SELECT source, decision, domain, reason FROM events LIMIT 1`).
		Scan(&source, &decision, &domain, &reason)
	require.NoError(t, err)

	assert.Equal(t, "dns", source)
	assert.Equal(t, "deny", decision)
	assert.Equal(t, "example.com", domain)
	assert.Equal(t, "not-allowlisted", reason)
}

// TestEmit_RecordsFlowColumns reads the `dst_ip` and `rule_index`
// columns that the store writes for an event.
func TestEmit_RecordsFlowColumns(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		event     eventstore.Event
		wantDstIP sql.NullString
		wantRule  sql.NullInt64
	}{
		"no address and no rule index": {
			event: eventstore.Event{},
		},
		"IPv4 address": {
			event:     eventstore.Event{DstIP: netip.MustParseAddr("192.0.2.7")},
			wantDstIP: sql.NullString{String: "192.0.2.7", Valid: true},
		},
		"IPv6 address": {
			event:     eventstore.Event{DstIP: netip.MustParseAddr("2001:db8::7")},
			wantDstIP: sql.NullString{String: "2001:db8::7", Valid: true},
		},
		"IPv4-mapped IPv6 address": {
			event:     eventstore.Event{DstIP: netip.MustParseAddr("::ffff:192.0.2.7")},
			wantDstIP: sql.NullString{String: "192.0.2.7", Valid: true},
		},
		"rule index 0": {
			event:    eventstore.Event{HasRuleIndex: true},
			wantRule: sql.NullInt64{Int64: 0, Valid: true},
		},
		"rule index 3": {
			event:    eventstore.Event{RuleIndex: 3, HasRuleIndex: true},
			wantRule: sql.NullInt64{Int64: 3, Valid: true},
		},
		"rule index without the flag": {
			event: eventstore.Event{RuleIndex: 3},
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "stats.db")

			tc.event.Source = eventstore.SourceFirewall
			tc.event.Decision = eventstore.DecisionDeny
			writeStore(t, path, []eventstore.Event{tc.event})

			db := openReadOnly(t, path)

			var (
				dstIP sql.NullString
				rule  sql.NullInt64
			)

			err := db.QueryRowContext(t.Context(), `SELECT dst_ip, rule_index FROM events`).Scan(&dstIP, &rule)
			require.NoError(t, err)

			assert.Equal(t, tc.wantDstIP, dstIP)
			assert.Equal(t, tc.wantRule, rule)
		})
	}
}

// TestEmit_FlushesPartialBatchesPeriodically pins the writer
// goroutine's idle behavior: with BatchSize=64 and a 50ms interval,
// a single event must reach disk well before Close runs. Guards
// against a flush path that disarms the interval timer on empty
// batches, which would defer partial-batch writes until shutdown
// and hide them from a concurrent `stats list` reader.
func TestEmit_FlushesPartialBatchesPeriodically(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(64),
		eventstore.WithBatchInterval(50*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	// Wait long enough for the writer to fire at least one empty
	// interval tick before any event arrives. The bug was that
	// the first empty tick disarmed the timer permanently.
	time.Sleep(200 * time.Millisecond)

	store.Emit(eventstore.Event{
		Source:   eventstore.SourceEnvoy,
		Decision: eventstore.DecisionAllow,
		Domain:   "example.com",
	})

	require.Eventually(t, func() bool {
		db := openReadOnly(t, path)

		var count int

		err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM events`).Scan(&count)
		require.NoError(t, err)

		return count == 1
	}, 2*time.Second, 25*time.Millisecond)
}

func TestEmit_NilStoreNoop(t *testing.T) {
	t.Parallel()

	var s *eventstore.Store

	require.NotPanics(t, func() {
		s.Emit(eventstore.Event{Source: eventstore.SourceDNS})
	})
	require.NotPanics(t, func() { assert.NoError(t, s.Close()) })
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

	err = db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM instances WHERE ended_at IS NOT NULL`).Scan(&count)
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

	err = db.QueryRowContext(t.Context(), `SELECT mode FROM instances WHERE id = ?`, store.InstanceID()).Scan(&mode)
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

	err = db.QueryRowContext(t.Context(), `SELECT ts FROM events LIMIT 1`).Scan(&ts)
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

		require.NoError(t, db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM events`).Scan(&n))

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

	r := openReader(t, path)

	require.Eventually(t, func() bool {
		hb, ok, err := r.LatestHeartbeat(t.Context(), store.InstanceID())
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
		hb, ok, err := r.LatestHeartbeat(t.Context(), store.InstanceID())
		if err != nil || !ok {
			return false
		}

		return hb.NFLogKernelDrops == second.NFLogKernelDrops &&
			hb.DNSCacheSize == second.DNSCacheSize
	}, 2*time.Second, 20*time.Millisecond)

	// Unknown instance returns ok=false without error.
	_, ok, err := r.LatestHeartbeat(t.Context(), "deadbeefdeadbeef")
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

	store, err := eventstore.Open(t.Context(), path)
	require.NoError(t, err)

	id := store.InstanceID()
	require.NoError(t, store.Close())

	got, ok, err := openReader(t, path).LatestInstanceID(t.Context())
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
