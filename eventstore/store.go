package eventstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// schemaVersion is the current `PRAGMA user_version` written by [Open].
// Bumping this requires a migration step in [Store.applySchema].
const schemaVersion = 2

// pruneChunkSize caps the per-call DELETE size for both the global
// and per-source pruners. Bounded chunks keep WAL fsync cost off the
// writer's hot path; the next batch tick drains any remaining excess.
const pruneChunkSize int64 = 1000

// readOnlyDSNSuffix is the query string appended to the SQLite path by
// [OpenReadOnly].
const readOnlyDSNSuffix = "?mode=ro&_pragma=busy_timeout(2000)"

// OpenReadOnly opens the SQLite event store at path for reads only.
// No writer goroutine, no schema apply, no instance row. The `stats`
// CLI and `status` renderer use it to read a database written by a
// separate [*Store] in the daemon. The caller owns closing the
// returned [*sql.DB].
func OpenReadOnly(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+readOnlyDSNSuffix)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}

	err = db.Ping()
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("opening db: %w", err)
	}

	return db, nil
}

// ErrSchemaTooNew is returned when the database file's `user_version`
// pragma exceeds the version this binary knows how to read. The store
// refuses to open rather than risk corrupting future schema.
var ErrSchemaTooNew = errors.New("eventstore: db schema is newer than supported")

// instanceMetricsTableSQL creates the `instance_metrics` table. Used
// by the v0 fresh-schema path (concatenated into [schemaSQL]) and the
// v1 -> v2 migration; one source of truth keeps the two paths in sync.
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

// schemaSQL is applied once on a fresh database (user_version=0).
// Subsequent versions add ALTER statements branched on user_version.
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
` + instanceMetricsTableSQL

// Store owns a SQLite database and a writer goroutine that drains
// events from a buffered channel into batched inserts. Producers call
// [Store.Emit]; the data plane is never blocked. A nil receiver is
// safe; both [Store.Emit] and [Store.Close] are no-ops in that case.
//
// Create instances with [Open].
type Store struct {
	db          *sql.DB
	insertStmt  *sql.Stmt
	ch          chan Event
	heartbeatCh chan Heartbeat
	done        chan struct{}
	logger      *slog.Logger
	instanceID  string
	opts        storeOptions

	// retention is read by the writer goroutine. Replaced via
	// SetRetention so reload can swap the policy without races.
	retention atomic.Pointer[Retention]

	// dropCount counts events dropped because the channel was full.
	dropCount atomic.Int64

	// lastWriteUnix records the most recent successful batch
	// commit, in unix microseconds.
	lastWriteUnix atomic.Int64

	// rowCount is the in-memory event row count. Seeded from
	// COUNT(*) at [Open], then incremented after each batch insert
	// and decremented after each retention DELETE on the writer
	// goroutine. Row-based pruning reads it instead of scanning the
	// table every batch.
	rowCount atomic.Int64

	// firewallRowCount, dnsRowCount, envoyRowCount partition
	// [rowCount] by [Source] for [Retention.PerSource] caps.
	firewallRowCount atomic.Int64
	dnsRowCount      atomic.Int64
	envoyRowCount    atomic.Int64

	// closeMu serializes [Close] against [Emit]. Emit takes the
	// read lock so concurrent producers do not block each other.
	// Close takes the write lock and sets closed before closing the
	// channel. After Close, Emit returns without sending, which
	// avoids a panic on send-to-closed-channel.
	closeMu sync.RWMutex
	closed  bool
}

// Open opens or creates the SQLite event store at path. The schema is
// applied on a fresh database; a database with a newer schema returns
// [ErrSchemaTooNew]. The returned [*Store] starts a background writer
// goroutine that runs until [Store.Close].
//
// On open the store inserts an `instances` row tagged with a fresh
// 16-hex-character instance ID. The matching `ended_at` UPDATE runs
// during a clean [Store.Close]; crashes leave `ended_at` NULL.
func Open(ctx context.Context, path string, opts ...Option) (*Store, error) {
	o := defaultStoreOptions()
	for _, opt := range opts {
		opt(&o)
	}

	err := os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		return nil, fmt.Errorf("creating db directory: %w", err)
	}

	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(2000)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}

	// WAL allows concurrent readers alongside a single writer. Pin
	// to one open connection so the writer goroutine has exclusive
	// ownership and we do not race on busy-timeout retries.
	db.SetMaxOpenConns(1)

	s := &Store{
		db:          db,
		ch:          make(chan Event, o.chanSize),
		heartbeatCh: make(chan Heartbeat, 1),
		done:        make(chan struct{}),
		logger:      o.logger,
		opts:        o,
	}
	s.retention.Store(&o.retention)

	err = s.applySchema(ctx)
	if err != nil {
		_ = db.Close()
		return nil, err
	}

	s.instanceID, err = mintInstanceID()
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("minting instance id: %w", err)
	}

	_, err = db.ExecContext(ctx,
		`INSERT INTO instances (id, started_at, mode) VALUES (?, ?, ?)`,
		s.instanceID, time.Now().UnixMicro(), string(o.mode),
	)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("recording instance: %w", err)
	}

	s.insertStmt, err = db.PrepareContext(ctx, insertEventSQL)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("preparing insert: %w", err)
	}

	err = s.seedRowCounts(ctx)
	if err != nil {
		_ = s.insertStmt.Close()
		_ = db.Close()

		return nil, fmt.Errorf("counting rows: %w", err)
	}

	if o.uid >= 0 {
		err = chownDBFiles(path, o.uid)
		if err != nil {
			s.logger.Warn("chowning db files", slog.Any("err", err))
		}
	}

	go s.run()

	return s, nil
}

// insertEventSQL is prepared once by [Open] and reused for every batch
// insert via [sql.Tx.StmtContext]; it sits on the hot path.
const insertEventSQL = `
INSERT INTO events (
	ts, instance_id, source, decision, domain, port, protocol,
	http_method, http_path, http_status, flags, reason,
	bytes_rx, bytes_tx, duration_ms
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

// applySchema reads the user_version pragma and applies any pending
// migrations. A version 0 (fresh) database lands on [schemaVersion] in
// one step via [schemaSQL]; version 1 databases migrate forward to
// version 2 by creating the `instance_metrics` table. Future versions
// refuse to open with [ErrSchemaTooNew].
//
// Each migration step is a DDL exec followed by a `PRAGMA
// user_version` write. The two statements are not bundled in a
// transaction; a crash between them leaves the database with the new
// schema and the old version, which the next open will retry.
func (s *Store) applySchema(ctx context.Context) error {
	var version int

	err := s.db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version)
	if err != nil {
		return fmt.Errorf("reading user_version: %w", err)
	}

	switch {
	case version == 0:
		_, err = s.db.ExecContext(ctx, schemaSQL)
		if err != nil {
			return fmt.Errorf("applying schema: %w", err)
		}

		_, err = s.db.ExecContext(ctx, fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion))
		if err != nil {
			return fmt.Errorf("setting user_version: %w", err)
		}

		return nil

	case version == 1:
		_, err = s.db.ExecContext(ctx, instanceMetricsTableSQL)
		if err != nil {
			return fmt.Errorf("migrating to schema 2: %w", err)
		}

		_, err = s.db.ExecContext(ctx, `PRAGMA user_version = 2`)
		if err != nil {
			return fmt.Errorf("setting user_version: %w", err)
		}

		return nil

	case version == schemaVersion:
		return nil

	case version > schemaVersion:
		return fmt.Errorf("%w: db version %d > supported %d",
			ErrSchemaTooNew, version, schemaVersion)

	default:
		return fmt.Errorf("eventstore: unexpected user_version %d", version)
	}
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
// `terrarium status` CLI reads it through [LatestHeartbeat] to
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

// LatestHeartbeat reads the most recent `instance_metrics` row for
// instanceID. Returns ok=false on a fresh database or when no
// heartbeat has been written for the given instance. db must be a
// handle opened by [OpenReadOnly] or [Open]. Used by the
// `terrarium status` CLI which holds a read-only handle.
func LatestHeartbeat(ctx context.Context, db *sql.DB, instanceID string) (Heartbeat, bool, error) {
	if instanceID == "" {
		return Heartbeat{}, false, nil
	}

	var (
		recordedAt, nflogLast, esLast       int64
		kernelDrops, parseErrors, evictions int64
		dnsCacheSize, dropCount             int64
	)

	err := db.QueryRowContext(ctx, `
		SELECT recorded_at,
		       nflog_kernel_drops,
		       nflog_parse_errors,
		       nflog_last_event_unix,
		       dnscache_size,
		       dnscache_evictions,
		       eventstore_drop_count,
		       eventstore_last_write_unix
		FROM instance_metrics
		WHERE instance_id = ?
	`, instanceID).Scan(
		&recordedAt, &kernelDrops, &parseErrors, &nflogLast,
		&dnsCacheSize, &evictions, &dropCount, &esLast,
	)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return Heartbeat{}, false, nil
	case err != nil:
		return Heartbeat{}, false, fmt.Errorf("reading heartbeat: %w", err)
	}

	h := Heartbeat{
		RecordedAt:          time.UnixMicro(recordedAt),
		NFLogKernelDrops:    uint64(kernelDrops), //nolint:gosec // counter persisted as int64; never negative.
		NFLogParseErrors:    uint64(parseErrors), //nolint:gosec // counter persisted as int64; never negative.
		DNSCacheSize:        dnsCacheSize,
		DNSCacheEvictions:   uint64(evictions), //nolint:gosec // counter persisted as int64; never negative.
		EventStoreDropCount: dropCount,
	}

	if nflogLast != 0 {
		h.NFLogLastEvent = time.UnixMicro(nflogLast)
	}

	if esLast != 0 {
		h.EventStoreLastWrite = time.UnixMicro(esLast)
	}

	return h, true, nil
}

// LatestInstanceID returns the most recent in-progress instance ID,
// falling back to the most recent overall instance when no run is in
// progress. Returns ok=false when the `instances` table is empty.
// db must be a handle opened by [OpenReadOnly] or [Open].
func LatestInstanceID(ctx context.Context, db *sql.DB) (string, bool, error) {
	var id string

	err := db.QueryRowContext(ctx,
		`SELECT id FROM instances
		 ORDER BY (ended_at IS NULL) DESC, started_at DESC
		 LIMIT 1`,
	).Scan(&id)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("querying instances: %w", err)
	}

	return id, true, nil
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

	return s.db.Close()
}

// run is the writer goroutine entry point. It batches up to
// opts.batchSize events or waits opts.batchInterval before flushing.
// Retention runs inline on the same goroutine.
func (s *Store) run() {
	defer close(s.done)

	timer := time.NewTimer(s.opts.batchInterval)
	defer timer.Stop()

	pruneTicker := time.NewTicker(60 * time.Second)
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

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		timer.Reset(s.opts.batchInterval)
	}

	for {
		select {
		case e, ok := <-s.ch:
			if !ok {
				flush()
				s.drainHeartbeats()

				return
			}

			batch = append(batch, e)
			if len(batch) >= s.opts.batchSize {
				flush()
			}

		case <-timer.C:
			flush()

		case <-pruneTicker.C:
			s.pruneByAge()

		case h := <-s.heartbeatCh:
			s.upsertHeartbeat(h)
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
// [LatestHeartbeat]; matches the column DEFAULT 0.
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
		)
		if err != nil {
			_ = tx.Rollback()
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

// pruneByAge runs on a 60s ticker. It probes for any expired row
// before issuing the DELETE so the common case of "no rows past
// MaxAge" skips a write transaction (and its WAL fsync). When a
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
	defer func() { _ = rows.Close() }()

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

	defer func() { _ = rows.Close() }()

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
		return "", err
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

// nullableInt returns a [sql.NullInt64] so zero values round-trip as
// SQL NULL rather than 0.
func nullableInt(n int64) sql.NullInt64 {
	return sql.NullInt64{Int64: n, Valid: n != 0}
}
