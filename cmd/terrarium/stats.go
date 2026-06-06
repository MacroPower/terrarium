package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/eventstore"
	"go.jacobcolvin.com/terrarium/status"
)

// outputFormat identifies how stats results are rendered to the
// terminal.
type outputFormat string

// outputFormat values.
const (
	formatTable outputFormat = "table"
	formatJSON  outputFormat = "json"
	formatCSV   outputFormat = "csv"
)

// Group-by values shared by flag defaults, validation, and query
// building in `stats top`.
const (
	groupByDomain = "domain"
	groupByPath   = "path"
)

// instanceFilterClause is appended to stats queries to scope results
// to a single instance ID.
const instanceFilterClause = " AND instance_id = ?"

// parseFormat validates s as an [outputFormat]. Empty input maps to
// the table default.
func parseFormat(s string) (outputFormat, error) {
	switch outputFormat(s) {
	case "", formatTable:
		return formatTable, nil
	case formatJSON:
		return formatJSON, nil
	case formatCSV:
		return formatCSV, nil
	default:
		return "", fmt.Errorf("unsupported --format %q (expected: table, json, csv)", s)
	}
}

// parseSource validates s as an [eventstore.Source]. Empty input
// maps to the empty source (no filter).
func parseSource(s string) (eventstore.Source, error) {
	switch eventstore.Source(s) {
	case "":
		return "", nil
	case eventstore.SourceDNS:
		return eventstore.SourceDNS, nil
	case eventstore.SourceEnvoy:
		return eventstore.SourceEnvoy, nil
	case eventstore.SourceFirewall:
		return eventstore.SourceFirewall, nil
	default:
		return "", fmt.Errorf("unsupported --source %q (expected: dns, envoy, firewall)", s)
	}
}

// statsFlags holds the shared flags surfaced on every `terrarium stats`
// subcommand.
type statsFlags struct {
	since    string
	until    string
	source   string
	instance string
	format   string
	dbPath   string
	limit    int
}

// register attaches the shared flags to cmd.
func (f *statsFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.since, "since", "24h",
		"start of the time window (Go duration ago, e.g. 1h, 24h, or RFC3339)")
	cmd.Flags().StringVar(&f.until, "until", "",
		"end of the time window (RFC3339; defaults to now)")
	cmd.Flags().IntVar(&f.limit, "limit", 20, "maximum rows returned")
	cmd.Flags().StringVar(&f.source, "source", "",
		"filter by event source (dns, envoy, firewall)")
	cmd.Flags().StringVar(&f.instance, "instance", "",
		"filter by instance id (defaults to most-recent run)")
	cmd.Flags().StringVar(&f.format, "format", "table",
		"output format: table, json, csv")
	cmd.Flags().StringVar(&f.dbPath, "db", "",
		"path to stats db (default: $XDG_DATA_HOME/terrarium/stats.db)")
}

// resolved bundles the parsed/validated form of [statsFlags] used by
// every handler. resolveFlags pulls everything that must succeed
// before opening the DB into one place.
type resolvedFlags struct {
	since  time.Time
	until  time.Time
	source eventstore.Source
	format outputFormat
}

// resolveFlags parses the --since, --until, --source, and --format
// values together so the per-subcommand handlers stay focused on
// query construction.
func resolveFlags(f *statsFlags, now time.Time) (resolvedFlags, error) {
	since, err := resolveSince(f.since, now)
	if err != nil {
		return resolvedFlags{}, err
	}

	until, err := resolveUntil(f.until, now)
	if err != nil {
		return resolvedFlags{}, err
	}

	source, err := parseSource(f.source)
	if err != nil {
		return resolvedFlags{}, err
	}

	format, err := parseFormat(f.format)
	if err != nil {
		return resolvedFlags{}, err
	}

	return resolvedFlags{since: since, until: until, source: source, format: format}, nil
}

// resolveSince accepts either a Go-style duration ("24h", "30m",
// "168h") read as "ago" relative to now, or an RFC3339 timestamp.
func resolveSince(value string, now time.Time) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}

	d, err := time.ParseDuration(value)
	if err == nil {
		return now.Add(-d), nil
	}

	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing --since %q: %w", value, err)
	}

	return t, nil
}

// resolveUntil accepts an RFC3339 timestamp; an empty value means now.
func resolveUntil(value string, now time.Time) (time.Time, error) {
	if value == "" {
		return now, nil
	}

	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing --until %q: %w", value, err)
	}

	return t, nil
}

// dbPathOrDefault picks the DB file path with the same precedence
// the daemon writes through: explicit --db, then the YAML
// stats.path, then the XDG default.
func dbPathOrDefault(ctx context.Context, usr *config.User, override string) string {
	if override != "" {
		return override
	}

	def := config.StatsDBDefault()

	cfg, err := status.LoadConfig(ctx, usr.ConfigPath)
	if err != nil || cfg == nil {
		return def
	}

	return cfg.StatsPath(def)
}

// openStatsDB opens a read-only SQLite handle on the given path.
func openStatsDB(ctx context.Context, path string) (*sql.DB, error) {
	db, err := eventstore.OpenReadOnly(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("opening stats db %q: %w", path, err)
	}

	return db, nil
}

// resolveInstance returns the instance ID to filter on. Empty input
// means the most recent in-progress run, falling back to the most
// recent overall row when no run is in progress. Defers to
// [eventstore.LatestInstanceID] so the stats CLI and the status
// renderer agree on which instance is "latest".
func resolveInstance(ctx context.Context, db *sql.DB, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}

	id, _, err := eventstore.LatestInstanceID(ctx, db)
	if err != nil {
		return "", err
	}

	return id, nil
}

// statsCmd is the parent of every `terrarium stats <sub>` command.
func statsCmd(usr *config.User) *cobra.Command {
	var f statsFlags

	cmd := &cobra.Command{
		Use:   "stats",
		Short: "Inspect captured egress decisions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatsSummary(cmd.Context(), cmd.OutOrStdout(), usr, &f)
		},
	}

	f.register(cmd)

	cmd.AddCommand(statsTopCmd(usr))
	cmd.AddCommand(statsListCmd(usr))

	return cmd
}

// statsTopCmd implements `terrarium stats top`: top-N domains by
// allow/deny decision count over the chosen window.
func statsTopCmd(usr *config.User) *cobra.Command {
	var (
		f       statsFlags
		denied  bool
		allowed bool
		groupBy string
	)

	cmd := &cobra.Command{
		Use:   "top", //nolint:goconst // the other occurrences are test inputs.
		Short: "Top-N domains by event count (denied by default)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			decision := eventstore.DecisionDeny

			switch {
			case allowed && denied:
				return fmt.Errorf("--allowed and --denied are mutually exclusive")
			case allowed:
				decision = eventstore.DecisionAllow
			}

			return runStatsTop(cmd.Context(), cmd.OutOrStdout(), usr, &f, decision, groupBy)
		},
	}

	f.register(cmd)
	cmd.Flags().BoolVar(&denied, "denied", false, "show top denied domains (default)")
	cmd.Flags().BoolVar(&allowed, "allowed", false, "show top allowed domains")
	cmd.Flags().StringVar(&groupBy, "by", groupByDomain,
		"group by: domain, sni, path")

	return cmd
}

// statsListCmd implements `terrarium stats list`: raw events.
func statsListCmd(usr *config.User) *cobra.Command {
	var (
		f      statsFlags
		cursor string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List raw events",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatsList(cmd.Context(), cmd.OutOrStdout(), usr, &f, cursor)
		},
	}

	f.register(cmd)
	cmd.Flags().StringVar(&cursor, "cursor", "",
		"opaque pagination cursor returned by a previous run")

	return cmd
}

// topRow is one bucket of `terrarium stats top` output.
type topRow struct {
	Bucket string `json:"bucket"`
	Count  int    `json:"count"`
}

// listRow is one event in `terrarium stats list` output.
type listRow struct {
	Time       string `json:"time"`
	Source     string `json:"source"`
	Decision   string `json:"decision"`
	Domain     string `json:"domain"`
	Protocol   string `json:"protocol"`
	HTTPMethod string `json:"http_method"`
	HTTPPath   string `json:"http_path"`
	Flags      string `json:"flags"`
	Reason     string `json:"reason"`
	NextCursor string `json:"next_cursor,omitempty"`
	Port       int    `json:"port"`
	HTTPStatus int    `json:"http_status"`
}

// encodeCursor returns an opaque base64 token derived from a row id.
func encodeCursor(id int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(id, 10)))
}

// decodeCursor reverses [encodeCursor].
func decodeCursor(c string) (int64, error) {
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, fmt.Errorf("decoding cursor: %w", err)
	}

	id, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing cursor: %w", err)
	}

	return id, nil
}

// runStatsTop runs the SQL aggregation behind `terrarium stats top`.
func runStatsTop(
	ctx context.Context, out io.Writer, usr *config.User,
	f *statsFlags, decision eventstore.Decision, groupBy string,
) error {
	rf, err := resolveFlags(f, time.Now())
	if err != nil {
		return err
	}

	column, err := groupColumn(groupBy)
	if err != nil {
		return err
	}

	dbPath := dbPathOrDefault(ctx, usr, f.dbPath)

	db, err := openStatsDB(ctx, dbPath)
	if err != nil {
		return err
	}

	defer db.Close() //nolint:errcheck // read-only.

	instance, err := resolveInstance(ctx, db, f.instance)
	if err != nil {
		return err
	}

	args := []any{
		string(decision),
		rf.since.UnixMicro(),
		rf.until.UnixMicro(),
	}

	sourceClause := ""
	if rf.source != "" {
		sourceClause = " AND source = ?"

		args = append(args, string(rf.source))
	}

	instanceClause := ""
	if instance != "" {
		instanceClause = instanceFilterClause

		args = append(args, instance)
	}

	// `--by sni` and `--by domain` both bucket on the `domain`
	// column (TCP entries store SNI there). Constrain `sni` to TCP
	// events so the bucket actually reflects SNI, not authority.
	groupClause := ""
	if groupBy == "sni" {
		groupClause = " AND protocol = ?"

		args = append(args, string(eventstore.ProtocolTCP))
	}

	args = append(args, f.limit)

	groupExpr := column
	if groupBy == groupByPath {
		// Session tokens and cache-busters in query strings would
		// blow out cardinality; strip them before grouping.
		groupExpr = "CASE WHEN instr(http_path, '?') > 0 " +
			"THEN substr(http_path, 1, instr(http_path, '?') - 1) " +
			"ELSE http_path END"
	}

	//nolint:gosec // G201: only internal column names and constant clauses are interpolated; user values use ? placeholders.
	query := fmt.Sprintf(`
		SELECT %s AS bucket, COUNT(*) AS n
		FROM events
		WHERE decision = ?
		  AND ts >= ?
		  AND ts <= ?
		  AND %s IS NOT NULL%s%s%s
		GROUP BY bucket
		ORDER BY n DESC
		LIMIT ?
	`, groupExpr, column, sourceClause, instanceClause, groupClause)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("querying top: %w", err)
	}

	defer rows.Close() //nolint:errcheck // read-only.

	var (
		results []topRow
		csvRows [][]string
	)

	for rows.Next() {
		var r topRow

		var bucket sql.NullString

		err = rows.Scan(&bucket, &r.Count)
		if err != nil {
			return fmt.Errorf("scanning top row: %w", err)
		}

		r.Bucket = bucket.String
		results = append(results, r)
		csvRows = append(csvRows, []string{r.Bucket, strconv.Itoa(r.Count)})
	}

	err = rows.Err()
	if err != nil {
		return fmt.Errorf("iterating top: %w", err)
	}

	return renderRows(out, rf.format, results, []string{groupBy, "count"}, csvRows)
}

// groupColumn maps a --by flag to the events column name. Returns
// the canonical column for the bucket (the SELECT expression may
// add post-processing).
func groupColumn(by string) (string, error) {
	switch by {
	case "", groupByDomain:
		return groupByDomain, nil
	case "sni":
		return groupByDomain, nil
	case groupByPath:
		return "http_path", nil
	default:
		return "", fmt.Errorf("unsupported --by value %q (expected: domain, sni, path)", by)
	}
}

// runStatsList prints the raw event rows over the chosen window.
// When non-empty, cursor is the opaque base64-encoded id returned
// by a prior call; rows with id < cursor are returned (the list is
// ordered ts DESC).
func runStatsList(
	ctx context.Context, out io.Writer, usr *config.User,
	f *statsFlags, cursor string,
) error {
	rf, err := resolveFlags(f, time.Now())
	if err != nil {
		return err
	}

	dbPath := dbPathOrDefault(ctx, usr, f.dbPath)

	db, err := openStatsDB(ctx, dbPath)
	if err != nil {
		return err
	}

	defer db.Close() //nolint:errcheck // read-only.

	instance, err := resolveInstance(ctx, db, f.instance)
	if err != nil {
		return err
	}

	args := []any{rf.since.UnixMicro(), rf.until.UnixMicro()}
	sourceClause := ""

	if rf.source != "" {
		sourceClause = " AND source = ?"

		args = append(args, string(rf.source))
	}

	instanceClause := ""
	if instance != "" {
		instanceClause = instanceFilterClause

		args = append(args, instance)
	}

	cursorClause := ""

	if cursor != "" {
		id, err := decodeCursor(cursor)
		if err != nil {
			return err
		}

		cursorClause = " AND id < ?"

		args = append(args, id)
	}

	args = append(args, f.limit)

	query := fmt.Sprintf(`
		SELECT id, ts, source, decision, COALESCE(domain,''), COALESCE(port,0),
		       COALESCE(protocol,''), COALESCE(http_method,''),
		       COALESCE(http_path,''), COALESCE(http_status,0),
		       COALESCE(flags,''), COALESCE(reason,'')
		FROM events
		WHERE ts >= ? AND ts <= ?%s%s%s
		ORDER BY id DESC
		LIMIT ?
	`, sourceClause, instanceClause, cursorClause)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("querying events: %w", err)
	}

	defer rows.Close() //nolint:errcheck // read-only.

	var (
		results []listRow
		csvRows [][]string
		lastID  int64
	)

	for rows.Next() {
		var (
			id, ts int64
			r      listRow
		)

		err = rows.Scan(&id, &ts, &r.Source, &r.Decision, &r.Domain, &r.Port,
			&r.Protocol, &r.HTTPMethod, &r.HTTPPath, &r.HTTPStatus,
			&r.Flags, &r.Reason)
		if err != nil {
			return fmt.Errorf("scanning event row: %w", err)
		}

		r.Time = time.UnixMicro(ts).UTC().Format(time.RFC3339)
		results = append(results, r)
		csvRows = append(csvRows, []string{
			r.Time, r.Source, r.Decision, r.Domain,
			strconv.Itoa(r.Port), r.Protocol,
			r.HTTPMethod, r.HTTPPath,
			strconv.Itoa(r.HTTPStatus),
			r.Flags, r.Reason,
		})
		lastID = id
	}

	err = rows.Err()
	if err != nil {
		return fmt.Errorf("iterating events: %w", err)
	}

	if f.limit > 0 && len(results) >= f.limit {
		results[len(results)-1].NextCursor = encodeCursor(lastID)
	}

	headers := []string{
		"time", "source", "decision", "domain", "port",
		"protocol", "method", "path", "status", "flags", "reason",
	}

	return renderRows(out, rf.format, results, headers, csvRows)
}

// runStatsSummary prints a compact 24-hour summary. Used when the
// user types `terrarium stats` with no subcommand.
func runStatsSummary(
	ctx context.Context, out io.Writer, usr *config.User, f *statsFlags,
) error {
	rf, err := resolveFlags(f, time.Now())
	if err != nil {
		return err
	}

	dbPath := dbPathOrDefault(ctx, usr, f.dbPath)

	db, err := openStatsDB(ctx, dbPath)
	if err != nil {
		return err
	}

	defer db.Close() //nolint:errcheck // read-only.

	instance, err := resolveInstance(ctx, db, f.instance)
	if err != nil {
		return err
	}

	type summary struct {
		Source   string `json:"source"`
		Decision string `json:"decision"`
		Count    int    `json:"count"`
	}

	args := []any{rf.since.UnixMicro()}

	instanceClause := ""
	if instance != "" {
		instanceClause = instanceFilterClause

		args = append(args, instance)
	}

	rows, err := db.QueryContext(ctx, fmt.Sprintf(`
		SELECT source, decision, COUNT(*)
		FROM events
		WHERE ts >= ?%s
		GROUP BY source, decision
		ORDER BY source, decision
	`, instanceClause), args...)
	if err != nil {
		return fmt.Errorf("querying summary: %w", err)
	}

	defer rows.Close() //nolint:errcheck // read-only.

	var (
		entries []summary
		csvRows [][]string
	)

	for rows.Next() {
		var s summary

		err = rows.Scan(&s.Source, &s.Decision, &s.Count)
		if err != nil {
			return fmt.Errorf("scanning summary row: %w", err)
		}

		entries = append(entries, s)
		csvRows = append(csvRows, []string{s.Source, s.Decision, strconv.Itoa(s.Count)})
	}

	err = rows.Err()
	if err != nil {
		return fmt.Errorf("iterating summary: %w", err)
	}

	return renderRows(out, rf.format, entries, []string{"source", "decision", "count"}, csvRows)
}

// renderRows dispatches structured/csvRows to the format-specific
// writer. JSON encodes structured (so field names and types come from
// the caller's JSON-tagged struct); CSV writes lowercase headers and
// rows; the table renderer uppercases headers and column-aligns rows
// through [status.NewTabwriter].
func renderRows(out io.Writer, format outputFormat, structured any, headers []string, csvRows [][]string) error {
	switch format {
	case formatJSON:
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")

		return enc.Encode(structured)

	case formatCSV:
		w := csv.NewWriter(out)

		err := w.Write(headers)
		if err != nil {
			return err
		}

		err = w.WriteAll(csvRows)
		if err != nil {
			return err
		}

		return w.Error()

	default:
		tw := status.NewTabwriter(out)

		upper := make([]string, len(headers))
		for i, h := range headers {
			upper[i] = strings.ToUpper(h)
		}

		_, err := fmt.Fprintln(tw, strings.Join(upper, "\t"))
		if err != nil {
			return fmt.Errorf("writing header row: %w", err)
		}

		for _, row := range csvRows {
			_, err = fmt.Fprintln(tw, strings.Join(row, "\t"))
			if err != nil {
				return fmt.Errorf("writing row: %w", err)
			}
		}

		return tw.Flush()
	}
}
