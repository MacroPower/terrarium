package eventstore

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The schema versions that created the tables that a [Reader] reads.
// A database at an earlier version does not hold the table.
const (
	// EventsSchemaVersion created the `events` and `instances` tables.
	eventsSchemaVersion = 1

	// InstanceMetricsSchemaVersion created the `instance_metrics`
	// table.
	instanceMetricsSchemaVersion = 2

	// PoliciesSchemaVersion created the `policies` table and the
	// `name` and `config_path` columns of the `instances` table.
	policiesSchemaVersion = 3
)

// DomainColumn is the SQL expression of the lowercase `domain` column
// of an event without one trailing dot.
const domainColumn = "lower(CASE WHEN domain LIKE '%.' " +
	"THEN substr(domain, 1, length(domain) - 1) ELSE domain END)"

// The windows of the counts in [Health].
const (
	healthEventsWindow   = 24 * time.Hour
	healthFirewallWindow = time.Hour
)

var (
	// ErrInvalidCursor is the error of [Reader.Events] for an
	// [EventsQuery.Cursor] that does not decode to a row ID.
	ErrInvalidCursor = errors.New("eventstore: invalid cursor")

	// ErrUnknownTopBy is the error of [Reader.Top] for a [TopQuery.By]
	// that is not one of the [TopBy] values.
	ErrUnknownTopBy = errors.New("eventstore: unknown top grouping")

	// LikeEscaper escapes the characters that LIKE reads as
	// wildcards, for a pattern with the escape character `\`.
	likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
)

// Reader reads the event store that a [Store] writes, usually from
// another process. It runs only queries, so it never creates or
// migrates the schema, and it never adds an instance row. A Reader is
// safe for concurrent use.
//
// A Reader reads the schema version one time, in [OpenReader]. It
// accepts each version that [Open] migrates from. On a database
// whose version lacks the table of a method, that method returns an
// empty result. A Reader that stays open while a [Store] migrates
// the database keeps the version that it read.
//
// Create instances with [OpenReader].
type Reader struct {
	db      *sql.DB
	version int
}

// OpenReader creates a new [Reader] on the SQLite event store at path.
// A database with a schema newer than this package supports returns
// [ErrSchemaTooNew]. The caller must call [Reader.Close].
func OpenReader(ctx context.Context, path string) (*Reader, error) {
	db, err := OpenReadOnly(ctx, path)
	if err != nil {
		return nil, err
	}

	var version int

	err = db.QueryRowContext(ctx, `PRAGMA user_version`).Scan(&version)
	if err != nil {
		closeDBIgnoringErr(db)

		return nil, fmt.Errorf("reading user_version: %w", err)
	}

	switch {
	case version > schemaVersion:
		closeDBIgnoringErr(db)

		return nil, fmt.Errorf("%w: db version %d > supported %d",
			ErrSchemaTooNew, version, schemaVersion)

	case version < 0:
		closeDBIgnoringErr(db)

		return nil, fmt.Errorf("eventstore: unexpected user_version %d", version)
	}

	return &Reader{db: db, version: version}, nil
}

// Close closes the database. A nil receiver is a no-op.
func (r *Reader) Close() error {
	if r == nil {
		return nil
	}

	err := r.db.Close()
	if err != nil {
		return fmt.Errorf("closing db: %w", err)
	}

	return nil
}

// Filter selects the events that a [Reader] method reads. Each zero
// field selects every event, so the zero Filter selects all events.
type Filter struct {
	// Since is the earliest event time, inclusive.
	Since time.Time

	// Until is the latest event time, inclusive.
	Until time.Time

	// Source selects the events of one subsystem.
	Source Source

	// Decision selects the events with one policy outcome.
	Decision Decision

	// Instance selects the events of one instance ID. See
	// [Reader.LatestInstanceID] for the ID of the latest run.
	Instance string

	// Domain selects the events of one domain name and of its
	// subdomains. The match ignores the case of ASCII letters. It
	// also ignores one trailing dot, both of Domain and of the
	// domain of each event, so the name matches the firewall
	// events, which hold the fully qualified name that the DNS
	// proxy resolved.
	Domain string
}

// conditions returns the terms that limit a query on the `events`
// table to the events that f selects.
func (f Filter) conditions() *conditions {
	c := &conditions{}

	if !f.Since.IsZero() {
		c.add("ts >= ?", f.Since.UnixMicro())
	}

	if !f.Until.IsZero() {
		c.add("ts <= ?", f.Until.UnixMicro())
	}

	if f.Source != "" {
		c.add("source = ?", string(f.Source))
	}

	if f.Decision != "" {
		c.add("decision = ?", string(f.Decision))
	}

	if f.Instance != "" {
		c.add("instance_id = ?", f.Instance)
	}

	name := strings.TrimSuffix(f.Domain, ".")
	if name != "" {
		c.add("("+domainColumn+" = lower(?) OR "+domainColumn+" LIKE lower(?) ESCAPE '\\')",
			name, "%."+likeEscaper.Replace(name))
	}

	return c
}

// conditions collects the terms of a SQL WHERE clause and the
// arguments of their placeholders.
type conditions struct {
	terms []string
	args  []any
}

// add appends one term and the arguments of its placeholders.
func (c *conditions) add(term string, args ...any) {
	c.terms = append(c.terms, term)
	c.args = append(c.args, args...)
}

// where returns the WHERE clause that joins the terms with AND. It
// returns the empty string when c holds no term.
func (c *conditions) where() string {
	if len(c.terms) == 0 {
		return ""
	}

	return "WHERE " + strings.Join(c.terms, " AND ")
}

// SummaryRow is the number of events with one [Source] and one
// [Decision].
type SummaryRow struct {
	// Source is the subsystem that produced the events.
	Source Source

	// Decision is the policy outcome of the events.
	Decision Decision

	// Count is the number of events.
	Count int64
}

// Summary counts the events that f selects by source and decision.
// It orders the rows by source, then by decision.
func (r *Reader) Summary(ctx context.Context, f Filter) ([]SummaryRow, error) {
	if r.version < eventsSchemaVersion {
		return nil, nil
	}

	c := f.conditions()

	//nolint:gosec // G202: the clause holds only constant terms, and values use ? placeholders.
	rows, err := r.db.QueryContext(ctx, `
		SELECT source, decision, COUNT(*)
		FROM events
		`+c.where()+`
		GROUP BY source, decision
		ORDER BY source, decision
	`, c.args...)
	if err != nil {
		return nil, fmt.Errorf("querying summary: %w", err)
	}

	defer rows.Close() //nolint:errcheck // read-only.

	var out []SummaryRow

	for rows.Next() {
		var s SummaryRow

		err = rows.Scan(&s.Source, &s.Decision, &s.Count)
		if err != nil {
			return nil, fmt.Errorf("scanning summary row: %w", err)
		}

		out = append(out, s)
	}

	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("iterating summary: %w", err)
	}

	return out, nil
}

// TopBy names the value that [Reader.Top] groups events by.
type TopBy string

// TopBy values.
const (
	// TopByDomain groups by [Event.Domain].
	TopByDomain TopBy = "domain"

	// TopBySNI groups the [ProtocolTCP] events by [Event.Domain].
	// For Envoy TCP events, Domain holds the TLS server name, or
	// the upstream cluster or address when the connection had
	// none. Firewall TCP events hold the name that the DNS proxy
	// resolved. Set [Filter.Source] to [SourceEnvoy] to count only
	// the proxied connections.
	TopBySNI TopBy = "sni"

	// TopByPath groups by [Event.HTTPPath] without its query
	// string.
	TopByPath TopBy = "path"
)

// TopQuery selects the buckets that [Reader.Top] returns.
type TopQuery struct {
	// By is the value to group by. The empty value groups by
	// [TopByDomain].
	By TopBy

	// Filter selects the events to count.
	Filter Filter

	// Limit is the maximum number of buckets. Zero returns no
	// bucket, and a negative value returns every bucket.
	Limit int
}

// TopRow is one bucket of [Reader.Top].
type TopRow struct {
	// Bucket is the value that the events of the bucket share.
	Bucket string

	// Count is the number of events in the bucket.
	Count int64
}

// Top groups the events that q selects into buckets and returns the
// buckets with the most events first. It skips the events that do
// not hold the value of [TopQuery.By]. An unknown [TopQuery.By]
// returns [ErrUnknownTopBy].
func (r *Reader) Top(ctx context.Context, q TopQuery) ([]TopRow, error) {
	c := q.Filter.conditions()

	var bucket string

	switch q.By {
	case "", TopByDomain:
		bucket = "domain"

		c.add("domain IS NOT NULL")

	case TopBySNI:
		bucket = "domain"

		c.add("domain IS NOT NULL")
		c.add("protocol = ?", string(ProtocolTCP))

	case TopByPath:
		// A session token or a cache-buster in the query string
		// puts each request in its own bucket. The expression
		// drops the query string before grouping.
		bucket = "CASE WHEN instr(http_path, '?') > 0 " +
			"THEN substr(http_path, 1, instr(http_path, '?') - 1) " +
			"ELSE http_path END"

		c.add("http_path IS NOT NULL")

	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownTopBy, string(q.By))
	}

	if r.version < eventsSchemaVersion {
		return nil, nil
	}

	//nolint:gosec // G202: the query joins only constant expressions and terms, and values use ? placeholders.
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+bucket+` AS bucket, COUNT(*) AS n
		FROM events
		`+c.where()+`
		GROUP BY bucket
		ORDER BY n DESC
		LIMIT ?
	`, append(c.args, q.Limit)...)
	if err != nil {
		return nil, fmt.Errorf("querying top: %w", err)
	}

	defer rows.Close() //nolint:errcheck // read-only.

	var out []TopRow

	for rows.Next() {
		var t TopRow

		err = rows.Scan(&t.Bucket, &t.Count)
		if err != nil {
			return nil, fmt.Errorf("scanning top row: %w", err)
		}

		out = append(out, t)
	}

	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("iterating top: %w", err)
	}

	return out, nil
}

// StoredEvent is one row of the `events` table.
type StoredEvent struct {
	// InstanceID is the ID of the instance that recorded the event.
	InstanceID string

	// Event holds the recorded values. A column that the row
	// leaves unset reads as the zero value of its field.
	Event

	// ID is the row ID. A later row has a larger ID.
	ID int64
}

// EventsQuery selects the rows that [Reader.Events] returns.
type EventsQuery struct {
	// Cursor is the [EventsPage.NextCursor] of an earlier call
	// with the same Filter. The call then returns the rows that
	// follow that page. The empty value starts at the latest row.
	Cursor string

	// Filter selects the events to return.
	Filter Filter

	// Limit is the maximum number of rows. Zero returns no row,
	// and a negative value returns every row.
	Limit int
}

// EventsPage is one page of [Reader.Events].
type EventsPage struct {
	// NextCursor is the [EventsQuery.Cursor] of the next page. It
	// is empty when the page holds fewer rows than
	// [EventsQuery.Limit], or when the limit is not positive.
	NextCursor string

	// Events holds the rows, latest first.
	Events []StoredEvent
}

// Events returns the events that q selects, latest first. An
// [EventsQuery.Cursor] that does not decode to a row ID gives
// [ErrInvalidCursor].
func (r *Reader) Events(ctx context.Context, q EventsQuery) (EventsPage, error) {
	c := q.Filter.conditions()

	if q.Cursor != "" {
		id, err := decodeCursor(q.Cursor)
		if err != nil {
			return EventsPage{}, err
		}

		c.add("id < ?", id)
	}

	if r.version < eventsSchemaVersion {
		return EventsPage{}, nil
	}

	//nolint:gosec // G202: the clause holds only constant terms, and values use ? placeholders.
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, ts, instance_id, source, decision,
		       COALESCE(domain,''), COALESCE(port,0), COALESCE(protocol,''),
		       COALESCE(http_method,''), COALESCE(http_path,''),
		       COALESCE(http_status,0), COALESCE(flags,''), COALESCE(reason,''),
		       COALESCE(bytes_rx,0), COALESCE(bytes_tx,0), COALESCE(duration_ms,0)
		FROM events
		`+c.where()+`
		ORDER BY id DESC
		LIMIT ?
	`, append(c.args, q.Limit)...)
	if err != nil {
		return EventsPage{}, fmt.Errorf("querying events: %w", err)
	}

	defer rows.Close() //nolint:errcheck // read-only.

	var page EventsPage

	for rows.Next() {
		var (
			e  StoredEvent
			ts int64
		)

		err = rows.Scan(&e.ID, &ts, &e.InstanceID, &e.Source, &e.Decision,
			&e.Domain, &e.Port, &e.Protocol,
			&e.HTTPMethod, &e.HTTPPath,
			&e.HTTPStatus, &e.Flags, &e.Reason,
			&e.BytesRx, &e.BytesTx, &e.DurationMS)
		if err != nil {
			return EventsPage{}, fmt.Errorf("scanning event row: %w", err)
		}

		e.Time = time.UnixMicro(ts)
		page.Events = append(page.Events, e)
	}

	err = rows.Err()
	if err != nil {
		return EventsPage{}, fmt.Errorf("iterating events: %w", err)
	}

	if q.Limit > 0 && len(page.Events) >= q.Limit {
		page.NextCursor = encodeCursor(page.Events[len(page.Events)-1].ID)
	}

	return page, nil
}

// encodeCursor returns the cursor that continues after the row with
// the given ID.
func encodeCursor(id int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(id, 10)))
}

// decodeCursor returns the row ID that [encodeCursor] wrote into c.
func decodeCursor(c string) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidCursor, err)
	}

	id, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrInvalidCursor, err)
	}

	return id, nil
}

// Instance is one row of the `instances` table, which holds one row
// for each [Open] of the store.
type Instance struct {
	// StartedAt is the time of the [Open].
	StartedAt time.Time

	// EndedAt is the time of the [Store.Close]. It is the zero
	// time when the instance is running, or when its process
	// stopped without a Close.
	EndedAt time.Time

	// ID is the instance ID. See [Store.InstanceID].
	ID string

	// Mode is the terrarium mode that opened the store.
	Mode Mode

	// Name is the name of [WithInstanceName]. `terrarium proxy`
	// records its bind address and port, such as 127.0.0.1-8080.
	// It is empty when the process recorded no name.
	Name string

	// ConfigPath is the path of [WithConfigPath], which is the
	// config file of the process. It is empty when the process
	// recorded no path.
	ConfigPath string
}

// Instances returns every instance, with the latest start first. On a
// database of a schema version before 3, each [Instance] has an empty
// Name and an empty ConfigPath.
func (r *Reader) Instances(ctx context.Context) ([]Instance, error) {
	if r.version < eventsSchemaVersion {
		return nil, nil
	}

	// The schema versions before 3 do not hold the two columns.
	identity := `'', ''`
	if r.version >= policiesSchemaVersion {
		identity = `COALESCE(name,''), COALESCE(config_path,'')`
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT id, started_at, COALESCE(ended_at,0), mode, `+identity+`
		FROM instances
		ORDER BY started_at DESC, rowid DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("querying instances: %w", err)
	}

	defer rows.Close() //nolint:errcheck // read-only.

	var out []Instance

	for rows.Next() {
		var (
			in             Instance
			started, ended int64
		)

		err = rows.Scan(&in.ID, &started, &ended, &in.Mode, &in.Name, &in.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("scanning instance row: %w", err)
		}

		in.StartedAt = time.UnixMicro(started)

		if ended != 0 {
			in.EndedAt = time.UnixMicro(ended)
		}

		out = append(out, in)
	}

	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("iterating instances: %w", err)
	}

	return out, nil
}

// LatestInstanceID returns the ID of the running instance with the
// latest start. When no instance is running, it returns the ID of
// the instance with the latest start. It returns ok=false when the
// store holds no instance.
func (r *Reader) LatestInstanceID(ctx context.Context) (string, bool, error) {
	if r.version < eventsSchemaVersion {
		return "", false, nil
	}

	var id string

	err := r.db.QueryRowContext(ctx,
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

// LatestHeartbeat returns the latest [Heartbeat] that the instance
// with the given ID recorded. It returns ok=false when the instance
// recorded no heartbeat, and for the empty instance ID.
func (r *Reader) LatestHeartbeat(ctx context.Context, instanceID string) (Heartbeat, bool, error) {
	if instanceID == "" || r.version < instanceMetricsSchemaVersion {
		return Heartbeat{}, false, nil
	}

	var (
		recordedAt, nflogLast, esLast       int64
		kernelDrops, parseErrors, evictions int64
		dnsCacheSize, dropCount             int64
	)

	err := r.db.QueryRowContext(ctx, `
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

// PolicyInfo describes one row of the `policies` table without the
// policy document. The table holds one row for each
// [Store.RecordPolicy].
type PolicyInfo struct {
	// AppliedAt is the time at which the instance finished applying
	// the policy.
	AppliedAt time.Time

	// InstanceID is the ID of the instance that applied the policy.
	InstanceID string

	// ConfigPath is the path of the config file that held the
	// policy.
	ConfigPath string

	// SHA256 is the SHA-256 of the stored policy document, in
	// lowercase hexadecimal digits. Two snapshots with the same
	// value hold the same document.
	SHA256 string

	// Mode is the security mode of the policy.
	Mode SecurityMode

	// ID is the row ID. A later row has a larger ID.
	ID int64
}

// StoredPolicy is one row of the `policies` table.
type StoredPolicy struct {
	// YAML is the policy document that [Store.RecordPolicy] stored.
	YAML string

	PolicyInfo
}

// policyColumns lists the columns that [scanPolicy] reads.
const policyColumns = `id, instance_id, applied_at, config_path, sha256, security_mode, yaml`

// scanPolicy reads one row of [policyColumns]. It returns ok=false
// when the query selected no row.
func scanPolicy(row *sql.Row) (StoredPolicy, bool, error) {
	var (
		p         StoredPolicy
		appliedAt int64
	)

	err := row.Scan(&p.ID, &p.InstanceID, &appliedAt, &p.ConfigPath, &p.SHA256, &p.Mode, &p.YAML)

	switch {
	case errors.Is(err, sql.ErrNoRows):
		return StoredPolicy{}, false, nil
	case err != nil:
		return StoredPolicy{}, false, fmt.Errorf("reading policy snapshot: %w", err)
	}

	p.AppliedAt = time.UnixMicro(appliedAt)

	return p, true, nil
}

// LatestPolicy returns the latest policy snapshot of the instance
// with the given ID, which is the policy that a running instance
// enforces. It returns ok=false when the store holds no snapshot of
// the instance, and for the empty instance ID.
func (r *Reader) LatestPolicy(ctx context.Context, instanceID string) (StoredPolicy, bool, error) {
	if instanceID == "" || r.version < policiesSchemaVersion {
		return StoredPolicy{}, false, nil
	}

	return scanPolicy(r.db.QueryRowContext(ctx, `
		SELECT `+policyColumns+`
		FROM policies
		WHERE instance_id = ?
		ORDER BY applied_at DESC, id DESC
		LIMIT 1
	`, instanceID))
}

// PolicyAt returns the policy snapshot that was in force for the
// instance with the given ID at time t. That snapshot is the latest
// one that the instance applied at t or earlier. Pass the time of an
// event and the instance ID of the event to read the policy that
// decided the event.
//
// PolicyAt returns ok=false when the instance applied its first
// snapshot after t, and for the empty instance ID. An instance can
// record an event before the snapshot of its first policy, in the
// time between the start of the process and the end of its setup.
// [Reader.Policies] returns that snapshot as the earliest one of the
// instance.
//
// A process records a snapshot after every part of it runs the
// policy, but the parts switch to a new policy one at a time. During
// a reload, the firewall rules and the DNS proxy switch before the
// process records the snapshot. A firewall or DNS event in that time
// can come from the new policy, but PolicyAt returns the previous
// snapshot for it.
func (r *Reader) PolicyAt(ctx context.Context, instanceID string, t time.Time) (StoredPolicy, bool, error) {
	if instanceID == "" || r.version < policiesSchemaVersion {
		return StoredPolicy{}, false, nil
	}

	return scanPolicy(r.db.QueryRowContext(ctx, `
		SELECT `+policyColumns+`
		FROM policies
		WHERE instance_id = ? AND applied_at <= ?
		ORDER BY applied_at DESC, id DESC
		LIMIT 1
	`, instanceID, t.UnixMicro()))
}

// Policies returns the policy snapshots of the instance with the
// given ID without their documents, with the latest snapshot first.
// The empty instance ID selects the snapshots of every instance. Read
// the document of a snapshot with [Reader.LatestPolicy] or with
// [Reader.PolicyAt].
func (r *Reader) Policies(ctx context.Context, instanceID string) ([]PolicyInfo, error) {
	if r.version < policiesSchemaVersion {
		return nil, nil
	}

	c := &conditions{}
	if instanceID != "" {
		c.add("instance_id = ?", instanceID)
	}

	//nolint:gosec // G202: the clause holds only constant terms, and values use ? placeholders.
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, instance_id, applied_at, config_path, sha256, security_mode
		FROM policies
		`+c.where()+`
		ORDER BY applied_at DESC, id DESC
	`, c.args...)
	if err != nil {
		return nil, fmt.Errorf("querying policy snapshots: %w", err)
	}

	defer rows.Close() //nolint:errcheck // read-only.

	var out []PolicyInfo

	for rows.Next() {
		var (
			p         PolicyInfo
			appliedAt int64
		)

		err = rows.Scan(&p.ID, &p.InstanceID, &appliedAt, &p.ConfigPath, &p.SHA256, &p.Mode)
		if err != nil {
			return nil, fmt.Errorf("scanning policy snapshot row: %w", err)
		}

		p.AppliedAt = time.UnixMicro(appliedAt)

		out = append(out, p)
	}

	err = rows.Err()
	if err != nil {
		return nil, fmt.Errorf("iterating policy snapshots: %w", err)
	}

	return out, nil
}

// Health is a summary of how well the store ingests events.
type Health struct {
	// LastEvent is the time of the latest event of any instance.
	// It is the zero time when the store holds no event.
	LastEvent time.Time

	// Heartbeat is the latest heartbeat of the instance. It is the
	// zero value when HasHeartbeat is false.
	Heartbeat Heartbeat

	// Events24h is the number of events of any instance in the
	// last 24 hours.
	Events24h int64

	// FirewallEvents1h is the number of [SourceFirewall] events of
	// any instance in the last hour.
	FirewallEvents1h int64

	// FirewallNullDomain1h is the number of the events in
	// FirewallEvents1h that hold no domain.
	FirewallNullDomain1h int64

	// HasHeartbeat reports whether the instance recorded a
	// heartbeat.
	HasHeartbeat bool
}

// Health returns the [Health] of the store. It reads the heartbeat
// of the instance with the given ID, as [Reader.LatestHeartbeat]
// does. The counts and the time of the latest event cover every
// instance.
func (r *Reader) Health(ctx context.Context, instanceID string) (Health, error) {
	var h Health

	if r.version < eventsSchemaVersion {
		return h, nil
	}

	now := time.Now()

	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events WHERE ts >= ?`,
		now.Add(-healthEventsWindow).UnixMicro(),
	).Scan(&h.Events24h)
	if err != nil {
		return Health{}, fmt.Errorf("counting events: %w", err)
	}

	var lastEvent sql.NullInt64

	err = r.db.QueryRowContext(ctx, `SELECT MAX(ts) FROM events`).Scan(&lastEvent)
	if err != nil {
		return Health{}, fmt.Errorf("reading last event: %w", err)
	}

	if lastEvent.Valid {
		h.LastEvent = time.UnixMicro(lastEvent.Int64)
	}

	h.Heartbeat, h.HasHeartbeat, err = r.LatestHeartbeat(ctx, instanceID)
	if err != nil {
		return Health{}, err
	}

	// SUM returns NULL when no firewall event is in the window.
	var nullDomain sql.NullInt64

	err = r.db.QueryRowContext(ctx, `
		SELECT
		  SUM(CASE WHEN domain IS NULL THEN 1 ELSE 0 END),
		  COUNT(*)
		FROM events
		WHERE source = ? AND ts >= ?
	`, string(SourceFirewall), now.Add(-healthFirewallWindow).UnixMicro(),
	).Scan(&nullDomain, &h.FirewallEvents1h)
	if err != nil {
		return Health{}, fmt.Errorf("counting firewall events: %w", err)
	}

	h.FirewallNullDomain1h = nullDomain.Int64

	return h, nil
}
