package eventstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"modernc.org/sqlite"

	sqlite3 "modernc.org/sqlite/lib"
)

// schemaVersion is the current `PRAGMA user_version` written by [Open].
// Bumping this requires a migration step in [migrationSQL].
const schemaVersion = 4

// policyChanSize is the number of policy snapshots that wait for the
// writer goroutine. A process records one snapshot at its start and
// one for each reload, so the channel fills only when the writer
// stalls.
const policyChanSize = 16

// pruneChunkSize caps the per-call DELETE size for both the global
// and per-source pruners. Bounded chunks keep WAL fsync cost off the
// writer's hot path; the next batch tick drains any remaining excess.
const pruneChunkSize int64 = 1000

// busyTimeout is how long a connection waits for the lock of another
// connection before SQLite returns SQLITE_BUSY. [writerDSNSuffix] and
// [readOnlyDSNQuery] set the same value in milliseconds.
const busyTimeout = 2 * time.Second

// walRetryInterval is the pause between two attempts of
// [enableWAL] to switch the journal mode.
const walRetryInterval = 10 * time.Millisecond

// writerDSNSuffix is the query string appended to the SQLite path by
// [Open]. `_txlock=immediate` makes each transaction take the write
// lock when it begins. The transaction then waits for another writer
// under the busy timeout, and it never reads a state that the other
// writer is about to change.
const writerDSNSuffix = "?_pragma=busy_timeout(2000)&_pragma=synchronous(NORMAL)&_txlock=immediate"

// readOnlyDSNQuery is the query string of the URI that [readOnlyDSN]
// returns. SQLite reads `mode=rw`, so it opens an existing file and
// does not create a missing one. The driver reads `_pragma`. It sets
// `query_only` on each new connection, so each statement that changes
// a table, an index, or the schema fails with `attempt to write a
// readonly database` until a statement turns `query_only` off.
// The pragma does not stop a change of `journal_mode`, a checkpoint,
// or an `ATTACH`, and each of these still writes files.
//
// The query does not set `mode=ro`. A connection that SQLite opens for
// reads only cannot remove the `-wal` and `-shm` files of the database
// when it closes. The files then stay after the last connection
// closes, and the next [Open] fails when another user owns them.
const readOnlyDSNQuery = "?mode=rw&_pragma=query_only(1)&_pragma=busy_timeout(2000)"

// readOnlyDSN returns the data source name that [OpenReadOnly] opens
// for the SQLite file at path. The name is a `file:` URI. For a name
// in another form, the driver removes the query string before SQLite
// reads the name. SQLite then never reads `mode=rw`, so it creates a
// missing file.
//
// The URI escapes the characters of path that end the path of a URI,
// such as `?` and `#`. The URI of an absolute path holds an empty
// authority. Without the authority, SQLite reads the first element of
// a path that starts with `//` as a host. The URI of a relative path
// starts with `./`, so that SQLite reads the empty path and the name
// `:memory:` as paths of files. Without the `./`, SQLite opens a
// temporary database for the empty path and an in-memory database for
// `:memory:`.
func readOnlyDSN(path string) string {
	prefix := "file:./"
	if filepath.IsAbs(path) {
		prefix = "file://"
	}

	return prefix + (&url.URL{Path: path}).EscapedPath() + readOnlyDSNQuery
}

// OpenReadOnly opens the SQLite event store at path for reads only.
// No writer goroutine, no schema apply, no instance row. It gives raw
// SQL access to a database written by a separate [*Store] in the
// daemon. Use [OpenReader] for the typed queries. The caller owns
// closing the returned [*sql.DB].
//
// A path that holds no file returns an error, and OpenReadOnly does
// not create the file. Each connection of the returned [*sql.DB] sets
// the pragma `query_only`. Each statement that changes a table, an
// index, or the schema then fails until the caller turns the pragma
// off. The pragma does not stop `PRAGMA journal_mode`, a checkpoint,
// or `ATTACH`. The store keeps a write-ahead log, so a query creates
// the `-shm` and `-wal` files beside the database when they are
// missing. When the returned [*sql.DB] closes the last connection to
// the database, SQLite removes both files, but only when the caller
// can write the database file. SQLite opens a file that the caller
// cannot write for reads only, and that connection leaves both files
// behind.
func OpenReadOnly(ctx context.Context, path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", readOnlyDSN(path))
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}

	err = db.PingContext(ctx)
	if err != nil {
		closeDBIgnoringErr(db)

		return nil, fmt.Errorf("opening db: %w", err)
	}

	return db, nil
}

// closeDBIgnoringErr closes db on an open/setup failure path where the
// original error is already being returned and a close error would
// only mask it.
func closeDBIgnoringErr(db *sql.DB) {
	_ = db.Close() //nolint:errcheck // abandoning open on error; original error is returned.
}

// ErrSchemaTooNew is returned when the database file's `user_version`
// pragma exceeds the version this binary knows how to read. [Open]
// refuses to open rather than risk corrupting future schema, and
// [OpenReader] refuses to read a schema that it does not know.
var ErrSchemaTooNew = errors.New("eventstore: db schema is newer than supported")

// instanceMetricsTableSQL creates the `instance_metrics` table. Used
// by the v0 fresh-schema path (concatenated into [schemaSQL]) and the
// v1 -> v2 migration in [migrationSQL]; one source of truth keeps the
// two paths in sync.
const instanceMetricsTableSQL = `
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

// policiesTableSQL creates the `policies` table, which holds one row
// for each policy snapshot, and its index. The fresh schema in
// [schemaSQL] and the migration from version 2 in [migrationSQL] both
// use it, so the two paths create the same table.
const policiesTableSQL = `
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

// instanceIdentitySQL adds the `name` and `config_path` columns to the
// `instances` table of a version 2 database.
const instanceIdentitySQL = `
ALTER TABLE instances ADD COLUMN name TEXT;
ALTER TABLE instances ADD COLUMN config_path TEXT;
`

// eventFlowSQL adds the `dst_ip` and `rule_index` columns to the
// `events` table of a version 3 database. The rows that the database
// holds keep NULL in both columns.
const eventFlowSQL = `
ALTER TABLE events ADD COLUMN dst_ip TEXT;
ALTER TABLE events ADD COLUMN rule_index INTEGER;
`

// migrationSQL returns the statements that bring a database of schema
// version from to the next version. [migrate] applies the steps in
// order, so a database of each earlier version reaches
// [schemaVersion]. The steps add tables and columns and never rewrite
// a row.
func migrationSQL(from int) string {
	switch from {
	case 1:
		return instanceMetricsTableSQL
	case 2:
		return instanceIdentitySQL + policiesTableSQL
	case 3:
		return eventFlowSQL
	default:
		return ""
	}
}

// schemaSQL creates the tables of [schemaVersion] in one step.
// [migrate] applies it to a fresh database (user_version=0). A
// database of an earlier version reaches the same tables through
// [migrationSQL].
var schemaSQL = `
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
  duration_ms INTEGER,
  dst_ip      TEXT,
  rule_index  INTEGER
);
CREATE INDEX events_ts          ON events(ts DESC);
CREATE INDEX events_decision_ts ON events(decision, ts DESC);
CREATE INDEX events_source_ts   ON events(source, ts DESC);
CREATE INDEX events_instance_ts ON events(instance_id, ts DESC);

CREATE TABLE instances (
  id          TEXT PRIMARY KEY,
  started_at  INTEGER NOT NULL,
  ended_at    INTEGER,
  mode        TEXT NOT NULL,
  name        TEXT,
  config_path TEXT
);
` + instanceMetricsTableSQL + policiesTableSQL

// Store owns a SQLite database and a writer goroutine that drains
// events from a buffered channel into batched inserts. Producers call
// [Store.Emit]; the data plane is never blocked. The process that
// applies a policy calls [Store.RecordPolicy], which does not block
// either. A nil receiver is safe. [Store.Emit], [Store.RecordPolicy],
// and [Store.Close] are no-ops in that case.
//
// Create instances with [Open].
type Store struct {
	// Read by the writer goroutine and replaced via SetRetention so
	// reload can swap the policy without races.
	retention atomic.Pointer[Retention]

	db          *sql.DB
	insertStmt  *sql.Stmt
	ch          chan Event
	heartbeatCh chan Heartbeat
	policyCh    chan PolicySnapshot
	done        chan struct{}
	logger      *slog.Logger
	instanceID  string
	opts        storeOptions

	// Counts events dropped because the channel was full.
	dropCount atomic.Int64

	// Records the most recent successful batch commit, in unix
	// microseconds.
	lastWriteUnix atomic.Int64

	// The in-memory event row count. Seeded from
	// COUNT(*) at [Open], then incremented after each batch insert
	// and decremented after each retention DELETE on the writer
	// goroutine. Row-based pruning reads it instead of scanning the
	// table every batch.
	rowCount atomic.Int64

	// Partitions of [rowCount] by [Source] for [Retention.PerSource]
	// caps.
	firewallRowCount atomic.Int64
	dnsRowCount      atomic.Int64
	envoyRowCount    atomic.Int64

	// Serializes [Close] against [Emit]. Emit takes the
	// read lock so concurrent producers do not block each other.
	// Close takes the write lock and sets closed before closing the
	// channel. After Close, Emit returns without sending, which
	// avoids a panic on send-to-closed-channel. [Store.RecordPolicy]
	// and [Store.RecordHeartbeat] take the read lock for the same
	// reason, so the writer goroutine reads each value that they
	// sent before it returns.
	closeMu sync.RWMutex
	closed  bool
}

// Open opens or creates the SQLite event store at path. The schema is
// applied on a fresh database; a database with a newer schema returns
// [ErrSchemaTooNew]. The returned [*Store] starts a background writer
// goroutine that runs until [Store.Close].
//
// Several processes can open one path at the same time, including a
// path that does not exist yet. Each Open waits for the locks of the
// other processes, and one of them creates the schema.
//
// On open the store inserts an `instances` row tagged with a fresh
// 16-hex-character instance ID. The row also holds the mode of
// [WithMode], the name of [WithInstanceName], and the path of
// [WithConfigPath]. The matching `ended_at` UPDATE runs during a
// clean [Store.Close]; crashes leave `ended_at` NULL.
func Open(ctx context.Context, path string, opts ...Option) (*Store, error) {
	o := defaultStoreOptions()
	for _, opt := range opts {
		opt(&o)
	}

	err := os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		return nil, fmt.Errorf("creating db directory: %w", err)
	}

	db, err := sql.Open("sqlite", path+writerDSNSuffix)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}

	// WAL allows concurrent readers alongside a single writer. Pin
	// to one open connection so the writer goroutine has exclusive
	// ownership and we do not race on busy-timeout retries.
	db.SetMaxOpenConns(1)

	err = enableWAL(ctx, db)
	if err != nil {
		closeDBIgnoringErr(db)

		return nil, err
	}

	s := &Store{
		db:          db,
		ch:          make(chan Event, o.chanSize),
		heartbeatCh: make(chan Heartbeat, 1),
		policyCh:    make(chan PolicySnapshot, policyChanSize),
		done:        make(chan struct{}),
		logger:      o.logger,
		opts:        o,
	}
	s.retention.Store(&o.retention)

	err = s.applySchema(ctx)
	if err != nil {
		closeDBIgnoringErr(db)

		return nil, err
	}

	s.instanceID, err = mintInstanceID()
	if err != nil {
		closeDBIgnoringErr(db)

		return nil, fmt.Errorf("minting instance id: %w", err)
	}

	_, err = db.ExecContext(ctx,
		`INSERT INTO instances (id, started_at, mode, name, config_path) VALUES (?, ?, ?, ?, ?)`,
		s.instanceID, time.Now().UnixMicro(), string(o.mode),
		nullableString(o.instanceName), nullableString(o.configPath),
	)
	if err != nil {
		closeDBIgnoringErr(db)

		return nil, fmt.Errorf("recording instance: %w", err)
	}

	s.insertStmt, err = db.PrepareContext(ctx, insertEventSQL)
	if err != nil {
		closeDBIgnoringErr(db)

		return nil, fmt.Errorf("preparing insert: %w", err)
	}

	err = s.seedRowCounts(ctx)
	if err != nil {
		_ = s.insertStmt.Close() //nolint:errcheck // abandoning open on error; original error is returned.

		closeDBIgnoringErr(db)

		return nil, fmt.Errorf("counting rows: %w", err)
	}

	if o.uid >= 0 {
		err = chownDBFiles(path, o.uid)
		if err != nil {
			s.logger.WarnContext(ctx, "chowning db files", slog.Any("err", err))
		}
	}

	// The writer goroutine outlives Open's caller context, so it
	// derives its own per-operation timeouts from context.Background()
	// rather than inheriting ctx.
	go s.run() //nolint:contextcheck // writer goroutine owns its lifetime, see insertBatch.

	return s, nil
}

// insertEventSQL is prepared once by [Open] and reused for every batch
// insert via [sql.Tx.StmtContext]; it sits on the hot path.
const insertEventSQL = `
INSERT INTO events (
	ts, instance_id, source, decision, domain, port, protocol,
	http_method, http_path, http_status, flags, reason,
	bytes_rx, bytes_tx, duration_ms, dst_ip, rule_index
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

// enableWAL switches the database behind db to the write-ahead log
// (WAL) journal mode. SQLite stores the mode in the database file, so
// the switch changes the file only on a database that is not in WAL
// mode yet.
//
// SQLite does not wait under the busy timeout when the switch finds
// the lock of another connection that is making the same switch. It
// returns SQLITE_BUSY at once instead. For that reason, enableWAL
// repeats the switch every [walRetryInterval] until it succeeds,
// until [busyTimeout] has passed, or until ctx ends.
func enableWAL(ctx context.Context, db *sql.DB) error {
	deadline := time.Now().Add(busyTimeout)

	for {
		_, err := db.ExecContext(ctx, `PRAGMA journal_mode = WAL`)
		if err == nil {
			return nil
		}

		if !isBusy(err) || !time.Now().Before(deadline) {
			return fmt.Errorf("enabling WAL: %w", err)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("enabling WAL: %w", ctx.Err())
		case <-time.After(walRetryInterval):
		}
	}
}

// isBusy reports whether err is the SQLITE_BUSY result of SQLite or
// one of its extended codes.
func isBusy(err error) bool {
	var serr *sqlite.Error

	// The low byte of an extended result code is the primary code.
	return errors.As(err, &serr) && serr.Code()&0xff == sqlite3.SQLITE_BUSY
}

// applySchema reads the user_version pragma and applies any pending
// migrations. A version 0 (fresh) database lands on [schemaVersion] in
// one step via [schemaSQL]. A database of an earlier version migrates
// forward through each step of [migrationSQL] and keeps its rows.
// Version 2 adds the `instance_metrics` table. Version 3 adds the
// `policies` table and the `name` and `config_path` columns of the
// `instances` table. Version 4 adds the `dst_ip` and `rule_index`
// columns of the `events` table. Future versions refuse to open with
// [ErrSchemaTooNew].
//
// The read of the version, the DDL, and the `PRAGMA user_version`
// write run in one transaction that holds the write lock from its
// start. When several processes open one database at the same time,
// one of them migrates it and the others then read the new version.
// A crash in the middle of a migration leaves the database unchanged.
func (s *Store) applySchema(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning schema tx: %w", err)
	}

	err = migrate(ctx, tx)
	if err != nil {
		rollbackErr := tx.Rollback()
		if rollbackErr != nil {
			return fmt.Errorf("%w (rollback: %w)", err, rollbackErr)
		}

		return err
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("committing schema tx: %w", err)
	}

	return nil
}

// migrate brings the database of tx to [schemaVersion]. See
// [Store.applySchema] for the steps.
func migrate(ctx context.Context, tx *sql.Tx) error {
	var version int

	err := tx.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version)
	if err != nil {
		return fmt.Errorf("reading user_version: %w", err)
	}

	switch {
	case version == schemaVersion:
		return nil

	case version > schemaVersion:
		return fmt.Errorf("%w: db version %d > supported %d",
			ErrSchemaTooNew, version, schemaVersion)

	case version < 0:
		return fmt.Errorf("eventstore: unexpected user_version %d", version)

	case version == 0:
		_, err = tx.ExecContext(ctx, schemaSQL)
		if err != nil {
			return fmt.Errorf("applying schema: %w", err)
		}

	default:
		for v := version; v < schemaVersion; v++ {
			_, err = tx.ExecContext(ctx, migrationSQL(v))
			if err != nil {
				return fmt.Errorf("migrating to schema %d: %w", v+1, err)
			}
		}
	}

	_, err = tx.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion))
	if err != nil {
		return fmt.Errorf("setting user_version: %w", err)
	}

	return nil
}

// InstanceID returns the 16-hex-character ID assigned to this open
// of the store. Stable for the lifetime of the [*Store].
func (s *Store) InstanceID() string {
	if s == nil {
		return ""
	}

	return s.instanceID
}

// DropCount returns the running total of events dropped because the
// writer channel was full. A nil receiver returns 0.
func (s *Store) DropCount() int64 {
	if s == nil {
		return 0
	}

	return s.dropCount.Load()
}

// LastWriteTime returns the wall-clock time of the most recent
// successful batch commit, or the zero time when no batch has
// committed yet. A nil receiver returns the zero time.
func (s *Store) LastWriteTime() time.Time {
	if s == nil {
		return time.Time{}
	}

	usec := s.lastWriteUnix.Load()
	if usec == 0 {
		return time.Time{}
	}

	return time.UnixMicro(usec)
}

// Heartbeat is a periodic snapshot of daemon-internal counters that
// the daemon writes to the `instance_metrics` table. The
// `terrarium status` CLI reads it through [Reader.LatestHeartbeat] to
// surface ingestion health it cannot observe through the
// process boundary.
type Heartbeat struct {
	// RecordedAt is the wall-clock time the snapshot was taken.
	RecordedAt time.Time

	// NFLogLastEvent is the wall-clock time of the most recent
	// firewall event the nflog reader emitted, or the zero time
	// when none has been emitted yet.
	NFLogLastEvent time.Time

	// EventStoreLastWrite mirrors [Store.LastWriteTime].
	EventStoreLastWrite time.Time

	// NFLogKernelDrops is the cumulative count of nflog seq gaps
	// observed (kernel-side drops).
	NFLogKernelDrops uint64

	// NFLogParseErrors is the cumulative count of malformed nflog
	// packets and undecodable prefixes.
	NFLogParseErrors uint64

	// DNSCacheEvictions is the cumulative count of qname-level FIFO
	// and IP-level LRU evictions in the reverse cache.
	DNSCacheEvictions uint64

	// DNSCacheSize is the current entry count in the reverse cache.
	DNSCacheSize int64

	// EventStoreDropCount mirrors [Store.DropCount].
	EventStoreDropCount int64
}

// HeartbeatInterval is the production cadence at which the daemon
// snapshots a [Heartbeat] into the `instance_metrics` table.
// Consumers gauging heartbeat-row staleness (e.g. `terrarium status`)
// reference this constant so a daemon-side change cannot drift from
// the staleness threshold readers compare against.
const HeartbeatInterval = 60 * time.Second

// RecordHeartbeat sends h to the writer goroutine for upsert into the
// `instance_metrics` table. The send is non-blocking with a 1-buffer
// channel: if the writer is busy and a previous heartbeat is still
// pending, the new value is dropped so a hot tick never stalls the
// caller. A nil receiver is a no-op.
func (s *Store) RecordHeartbeat(_ context.Context, h Heartbeat) error {
	if s == nil {
		return nil
	}

	if h.RecordedAt.IsZero() {
		h.RecordedAt = time.Now()
	}

	s.closeMu.RLock()
	defer s.closeMu.RUnlock()

	if s.closed {
		return nil
	}

	select {
	case s.heartbeatCh <- h:
	default:
	}

	return nil
}

// SetRetention atomically replaces the retention policy. The new
// value takes effect on the writer goroutine's next batch.
func (s *Store) SetRetention(r Retention) {
	if s == nil {
		return
	}

	s.retention.Store(&r)
}

// Emit performs a non-blocking send of e onto the writer channel. If
// the channel is full the event is dropped and a counter is bumped
// (see [Store.DropCount]). A nil receiver discards the event silently
// so callers do not have to check stats-enabled. Calling Emit after
// [Store.Close] is safe; the event is dropped without bumping the
// counter.
func (s *Store) Emit(e Event) {
	if s == nil {
		return
	}

	if e.Time.IsZero() {
		e.Time = time.Now()
	}

	s.closeMu.RLock()
	defer s.closeMu.RUnlock()

	if s.closed {
		return
	}

	select {
	case s.ch <- e:
	default:
		// Data plane never blocks on stats ingestion; drop and
		// warn once via DropCount.
		old := s.dropCount.Add(1)
		if old == 1 {
			s.logger.Warn("eventstore writer channel full, dropping events")
		}
	}
}

// Close stops the writer goroutine, flushes outstanding events, marks
// this instance row as ended, and closes the underlying database. A
// nil receiver is a no-op. Calling Close more than once is safe; only
// the first call closes the channel.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}

	s.closeMu.Lock()

	if s.closed {
		s.closeMu.Unlock()
		<-s.done

		return nil
	}

	s.closed = true
	close(s.ch)
	s.closeMu.Unlock()

	<-s.done

	if s.insertStmt != nil {
		err := s.insertStmt.Close()
		if err != nil {
			s.logger.Warn("closing prepared insert", slog.Any("err", err))
		}
	}

	_, err := s.db.ExecContext(context.Background(),
		`UPDATE instances SET ended_at = ? WHERE id = ?`,
		time.Now().UnixMicro(), s.instanceID,
	)
	if err != nil {
		s.logger.Warn("recording instance end", slog.Any("err", err))
	}

	err = s.db.Close()
	if err != nil {
		return fmt.Errorf("closing db: %w", err)
	}

	return nil
}

// run is the writer goroutine entry point. Retention runs inline
// here so writes and pruning share a single serialized owner of
// the on-disk store.
func (s *Store) run() {
	defer close(s.done)

	// Ticker, not Timer: flush returns early on an empty batch and
	// never re-arms, so a Timer would disarm permanently on the
	// first idle tick and partial batches would only flush at Close.
	flushTicker := time.NewTicker(s.opts.batchInterval)
	defer flushTicker.Stop()

	pruneTicker := time.NewTicker(s.opts.pruneInterval)
	defer pruneTicker.Stop()

	batch := make([]Event, 0, s.opts.batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}

		err := s.insertBatch(batch)
		if err != nil {
			s.logger.Warn("eventstore batch insert", slog.Any("err", err))
			s.dropCount.Add(int64(len(batch)))
		} else {
			s.lastWriteUnix.Store(time.Now().UnixMicro())
			s.rowCount.Add(int64(len(batch)))
			s.addPerSourceCounts(batch, +1)
			s.pruneByRowsAfterInsert()
		}

		batch = batch[:0]
	}

	for {
		select {
		case e, ok := <-s.ch:
			if !ok {
				flush()
				s.drainHeartbeats()
				s.drainPolicies()

				return
			}

			batch = append(batch, e)
			if len(batch) >= s.opts.batchSize {
				flush()
			}

		case <-flushTicker.C:
			flush()

		case <-pruneTicker.C:
			s.pruneByAge()
			s.prunePoliciesByAge()

		case h := <-s.heartbeatCh:
			s.upsertHeartbeat(h)

		case p := <-s.policyCh:
			s.insertPolicy(p)
		}
	}
}

// drainHeartbeats consumes any pending heartbeat snapshot before
// the writer goroutine returns. The channel is buffer-1, so this
// loop runs at most once per close. Exists so a final shutdown
// snapshot lands in the database before the connection closes.
func (s *Store) drainHeartbeats() {
	for {
		select {
		case h := <-s.heartbeatCh:
			s.upsertHeartbeat(h)
		default:
			return
		}
	}
}

// upsertHeartbeat writes h into the `instance_metrics` table using
// the writer goroutine's connection. Upsert keyed on instance_id so
// each daemon has at most one row.
func (s *Store) upsertHeartbeat(h Heartbeat) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO instance_metrics (
			instance_id, recorded_at,
			nflog_kernel_drops, nflog_parse_errors, nflog_last_event_unix,
			dnscache_size, dnscache_evictions,
			eventstore_drop_count, eventstore_last_write_unix
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(instance_id) DO UPDATE SET
			recorded_at               = excluded.recorded_at,
			nflog_kernel_drops        = excluded.nflog_kernel_drops,
			nflog_parse_errors        = excluded.nflog_parse_errors,
			nflog_last_event_unix     = excluded.nflog_last_event_unix,
			dnscache_size             = excluded.dnscache_size,
			dnscache_evictions        = excluded.dnscache_evictions,
			eventstore_drop_count     = excluded.eventstore_drop_count,
			eventstore_last_write_unix = excluded.eventstore_last_write_unix
	`,
		s.instanceID,
		h.RecordedAt.UnixMicro(),
		int64(h.NFLogKernelDrops), //nolint:gosec // counters fit comfortably in int64.
		int64(h.NFLogParseErrors), //nolint:gosec // counters fit comfortably in int64.
		unixMicroOrZero(h.NFLogLastEvent),
		h.DNSCacheSize,
		int64(h.DNSCacheEvictions), //nolint:gosec // counters fit comfortably in int64.
		h.EventStoreDropCount,
		unixMicroOrZero(h.EventStoreLastWrite),
	)
	if err != nil {
		s.logger.Warn("eventstore heartbeat upsert", slog.Any("err", err))
	}
}

// unixMicroOrZero returns t.UnixMicro() or 0 for the zero time. The
// caller-side equivalent of `IF unix == 0` decoding in
// [Reader.LatestHeartbeat]; matches the column DEFAULT 0.
func unixMicroOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}

	return t.UnixMicro()
}

// insertBatch writes one transaction's worth of events using the
// prepared statement bound to the [*Store] at [Open] time.
func (s *Store) insertBatch(batch []Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning tx: %w", err)
	}

	stmt := tx.StmtContext(ctx, s.insertStmt)

	for i := range batch {
		e := &batch[i]

		_, err = stmt.ExecContext(ctx,
			e.Time.UnixMicro(),
			s.instanceID,
			string(e.Source),
			string(e.Decision),
			nullableString(e.Domain),
			nullableInt(int64(e.Port)),
			nullableString(string(e.Protocol)),
			nullableString(e.HTTPMethod),
			nullableString(e.HTTPPath),
			nullableInt(int64(e.HTTPStatus)),
			nullableString(e.Flags),
			nullableString(string(e.Reason)),
			nullableInt(e.BytesRx),
			nullableInt(e.BytesTx),
			nullableInt(e.DurationMS),
			nullableAddr(e.DstIP),
			sql.NullInt64{Int64: int64(e.RuleIndex), Valid: e.HasRuleIndex},
		)
		if err != nil {
			_ = tx.Rollback() //nolint:errcheck // commit path owns the error; rollback is best-effort.

			return fmt.Errorf("inserting event: %w", err)
		}
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("committing batch: %w", err)
	}

	return nil
}

// pruneByRowsAfterInsert runs on the writer goroutine after each
// successful batch. When the in-memory row count exceeds MaxRows it
// deletes one chunk of the oldest rows; subsequent batch flushes drain
// the rest. Capping to one chunk per call keeps any single prune
// cycle's WAL fsync cost off the writer's hot path. Reading
// [Store.rowCount] avoids a `SELECT COUNT(*)` per batch.
//
// After the global pass, a per-source pass enforces
// [Retention.PerSource] caps so a chatty source (typically firewall)
// cannot evict events from quieter sources. Both passes use
// `DELETE ... RETURNING source` so the per-source counters stay in
// lockstep with [Store.rowCount].
func (s *Store) pruneByRowsAfterInsert() {
	r := s.retention.Load()
	if r == nil {
		return
	}

	if r.MaxRows > 0 {
		excess := s.rowCount.Load() - r.MaxRows
		if excess > 0 {
			s.deleteOldestGlobal(min(excess, pruneChunkSize))
		}
	}

	s.pruneByPerSource(r.PerSource)
}

// pruneByPerSource enforces per-source caps. For each source whose
// counter exceeds its cap, deletes one chunk of the oldest rows for
// that source. The next batch tick drains the rest.
func (s *Store) pruneByPerSource(caps PerSourceCaps) {
	if caps == (PerSourceCaps{}) {
		return
	}

	s.pruneSourceIfOver(SourceFirewall, caps.Firewall, &s.firewallRowCount)
	s.pruneSourceIfOver(SourceDNS, caps.DNS, &s.dnsRowCount)
	s.pruneSourceIfOver(SourceEnvoy, caps.Envoy, &s.envoyRowCount)
}

// pruneSourceIfOver deletes one chunk of oldest rows for source when
// its counter exceeds limit. A non-positive limit leaves the source
// uncapped and the function is a no-op.
func (s *Store) pruneSourceIfOver(source Source, limit int64, count *atomic.Int64) {
	if limit <= 0 {
		return
	}

	excess := count.Load() - limit
	if excess <= 0 {
		return
	}

	s.deleteOldestBySource(source, min(excess, pruneChunkSize))
}

// pruneByAge runs on the ticker of [WithPruneInterval]. It probes for
// any expired row before issuing the DELETE so the common case of "no
// rows past MaxAge" skips a write transaction (and its WAL fsync). When a
// match exists, it deletes a single chunk per tick so the writer is
// never starved. The DELETE returns each pruned row's source so the
// per-source counters stay aligned with [Store.rowCount].
func (s *Store) pruneByAge() {
	r := s.retention.Load()
	if r == nil || r.MaxAge <= 0 || s.rowCount.Load() == 0 {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cutoff := time.Now().Add(-r.MaxAge).UnixMicro()

	var hasExpired int

	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM events WHERE ts < ? LIMIT 1`, cutoff,
	).Scan(&hasExpired)
	if errors.Is(err, sql.ErrNoRows) {
		return
	}

	if err != nil {
		s.logger.Debug("retention: probing for expired rows", slog.Any("err", err))

		return
	}

	rows, err := s.db.QueryContext(ctx,
		`DELETE FROM events WHERE id IN (
			SELECT id FROM events WHERE ts < ? ORDER BY ts ASC LIMIT ?
		) RETURNING source`,
		cutoff, pruneChunkSize,
	)
	if err != nil {
		s.logger.Debug("retention: pruning by age", slog.Any("err", err))

		return
	}

	s.applyDeletedRows(rows)
}

// deleteOldestGlobal deletes the chunk-many oldest rows across all
// sources, decrementing both [rowCount] and the matching per-source
// counter for each returned row.
func (s *Store) deleteOldestGlobal(chunk int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`DELETE FROM events WHERE id IN (
			SELECT id FROM events ORDER BY ts ASC LIMIT ?
		) RETURNING source`,
		chunk,
	)
	if err != nil {
		s.logger.Debug("retention: pruning by rows", slog.Any("err", err))

		return
	}

	s.applyDeletedRows(rows)
}

// deleteOldestBySource deletes the chunk-many oldest rows for a single
// source, decrementing both [rowCount] and the matching per-source
// counter.
func (s *Store) deleteOldestBySource(source Source, chunk int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := s.db.QueryContext(ctx,
		`DELETE FROM events WHERE id IN (
			SELECT id FROM events WHERE source = ? ORDER BY id ASC LIMIT ?
		) RETURNING source`,
		string(source), chunk,
	)
	if err != nil {
		s.logger.Debug("retention: pruning by per-source rows",
			slog.String("source", string(source)),
			slog.Any("err", err),
		)

		return
	}

	s.applyDeletedRows(rows)
}

// sourceCounter returns the per-source row counter for source, or
// nil for unknown sources. Single point of mapping from the public
// [Source] enum onto the [Store]'s internal counters.
func (s *Store) sourceCounter(source Source) *atomic.Int64 {
	switch source {
	case SourceFirewall:
		return &s.firewallRowCount
	case SourceDNS:
		return &s.dnsRowCount
	case SourceEnvoy:
		return &s.envoyRowCount
	}

	return nil
}

// applyDeletedRows iterates over the source values of a DELETE ...
// RETURNING source result and decrements the matching counters.
// Closes rows on return.
func (s *Store) applyDeletedRows(rows *sql.Rows) {
	defer func() { _ = rows.Close() }() //nolint:errcheck // read path; row scan errors surface separately.

	var total int64

	for rows.Next() {
		var source string

		err := rows.Scan(&source)
		if err != nil {
			s.logger.Debug("retention: scanning pruned row source", slog.Any("err", err))

			continue
		}

		total++

		if c := s.sourceCounter(Source(source)); c != nil {
			c.Add(-1)
		}
	}

	err := rows.Err()
	if err != nil {
		s.logger.Debug("retention: iterating pruned rows", slog.Any("err", err))
	}

	if total > 0 {
		s.rowCount.Add(-total)
	}
}

// addPerSourceCounts increments (delta=+1) or decrements (delta=-1)
// the per-source counters for every event in batch. Tallies locally
// first so each counter takes one atomic op per batch instead of one
// per event.
func (s *Store) addPerSourceCounts(batch []Event, delta int64) {
	var firewall, dns, envoy int64

	for i := range batch {
		switch batch[i].Source {
		case SourceFirewall:
			firewall++
		case SourceDNS:
			dns++
		case SourceEnvoy:
			envoy++
		}
	}

	if firewall > 0 {
		s.firewallRowCount.Add(delta * firewall)
	}

	if dns > 0 {
		s.dnsRowCount.Add(delta * dns)
	}

	if envoy > 0 {
		s.envoyRowCount.Add(delta * envoy)
	}
}

// seedRowCounts populates the global and per-source row counters from
// SQLite's current state. Called at [Open]; all four counters start at
// zero before this returns successfully.
func (s *Store) seedRowCounts(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT source, COUNT(*) FROM events GROUP BY source`)
	if err != nil {
		return fmt.Errorf("querying row counts by source: %w", err)
	}

	defer func() { _ = rows.Close() }() //nolint:errcheck // read path; row scan errors surface separately.

	var total int64

	for rows.Next() {
		var (
			source string
			count  int64
		)

		err := rows.Scan(&source, &count)
		if err != nil {
			return fmt.Errorf("scanning row count: %w", err)
		}

		total += count

		if c := s.sourceCounter(Source(source)); c != nil {
			c.Store(count)
		}
	}

	err = rows.Err()
	if err != nil {
		return fmt.Errorf("iterating row counts: %w", err)
	}

	s.rowCount.Store(total)

	return nil
}

// mintInstanceID generates a 16-hex-character ID from 8 random bytes.
func mintInstanceID() (string, error) {
	var b [8]byte

	_, err := rand.Read(b[:])
	if err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}

	return hex.EncodeToString(b[:]), nil
}

// chownDBFiles chowns the SQLite db plus its WAL/SHM siblings. Missing
// -wal/-shm files are tolerated because they only appear after the
// first write.
func chownDBFiles(path string, uid int) error {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		err := os.Chown(p, uid, uid)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("chown %s: %w", p, err)
		}
	}

	return nil
}

// nullableString returns a [sql.NullString] so empty strings round-trip
// as SQL NULL rather than empty TEXT.
func nullableString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// nullableAddr returns the text of addr as a [sql.NullString], so the
// zero [netip.Addr] round-trips as SQL NULL. It writes an IPv4-mapped
// IPv6 address as the IPv4 address, so each destination has one
// text.
func nullableAddr(addr netip.Addr) sql.NullString {
	if !addr.IsValid() {
		return sql.NullString{}
	}

	return sql.NullString{String: addr.Unmap().String(), Valid: true}
}

// nullableInt returns a [sql.NullInt64] so zero values round-trip as
// SQL NULL rather than 0.
func nullableInt(n int64) sql.NullInt64 {
	return sql.NullInt64{Int64: n, Valid: n != 0}
}
