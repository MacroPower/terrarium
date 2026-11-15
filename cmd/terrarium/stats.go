package main

import (
	"context"
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
// every handler. [resolveFlags] pulls everything that must succeed
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

// openStatsReader opens a reader on the event store at the given
// path.
func openStatsReader(ctx context.Context, path string) (*eventstore.Reader, error) {
	r, err := eventstore.OpenReader(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("opening stats db %q: %w", path, err)
	}

	return r, nil
}

// resolveInstance returns the instance ID to filter on. Empty input
// means the most recent in-progress run, falling back to the most
// recent overall row when no run is in progress. Defers to
// [eventstore.Reader.LatestInstanceID] so the stats CLI and the
// status renderer agree on which instance is "latest".
func resolveInstance(ctx context.Context, r *eventstore.Reader, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}

	id, _, err := r.LatestInstanceID(ctx)
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
	cmd.Flags().StringVar(&groupBy, "by", string(eventstore.TopByDomain),
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
	Count  int64  `json:"count"`
}

// listRow is one event in `terrarium stats list` output.
type listRow struct {
	Time     string `json:"time"`
	Source   string `json:"source"`
	Decision string `json:"decision"`
	Domain   string `json:"domain"`
	// DstIP is the destination address of the flow. It is empty for
	// an event without one. See [eventstore.Event.DstIP].
	DstIP      string `json:"dst_ip"`
	Protocol   string `json:"protocol"`
	HTTPMethod string `json:"http_method"`
	HTTPPath   string `json:"http_path"`
	Flags      string `json:"flags"`
	Reason     string `json:"reason"`
	// RuleIndex is the index of the rule that decided the event, in
	// the `egress` list of the policy that was in force at the time
	// of the event. It is nil, and null in JSON, for an event
	// without a rule index. See [eventstore.Event.RuleIndex].
	RuleIndex  *int   `json:"rule_index"`
	NextCursor string `json:"next_cursor,omitempty"`
	Port       int    `json:"port"`
	HTTPStatus int    `json:"http_status"`
}

// runStatsTop prints the buckets behind `terrarium stats top`.
func runStatsTop(
	ctx context.Context, out io.Writer, usr *config.User,
	f *statsFlags, decision eventstore.Decision, groupBy string,
) error {
	rf, err := resolveFlags(f, time.Now())
	if err != nil {
		return err
	}

	by, err := parseGroupBy(groupBy)
	if err != nil {
		return err
	}

	dbPath := dbPathOrDefault(ctx, usr, f.dbPath)

	r, err := openStatsReader(ctx, dbPath)
	if err != nil {
		return err
	}

	defer r.Close() //nolint:errcheck // read-only.

	instance, err := resolveInstance(ctx, r, f.instance)
	if err != nil {
		return err
	}

	buckets, err := r.Top(ctx, eventstore.TopQuery{
		By: by,
		Filter: eventstore.Filter{
			Since:    rf.since,
			Until:    rf.until,
			Source:   rf.source,
			Decision: decision,
			Instance: instance,
		},
		Limit: f.limit,
	})
	if err != nil {
		return err
	}

	var (
		results []topRow
		csvRows [][]string
	)

	for _, b := range buckets {
		results = append(results, topRow{Bucket: b.Bucket, Count: b.Count})
		csvRows = append(csvRows, []string{b.Bucket, strconv.FormatInt(b.Count, 10)})
	}

	return renderRows(out, rf.format, results, []string{groupBy, "count"}, csvRows)
}

// parseGroupBy validates the --by flag as an [eventstore.TopBy].
// Empty input maps to the domain default.
func parseGroupBy(by string) (eventstore.TopBy, error) {
	switch eventstore.TopBy(by) {
	case "", eventstore.TopByDomain:
		return eventstore.TopByDomain, nil
	case eventstore.TopBySNI:
		return eventstore.TopBySNI, nil
	case eventstore.TopByPath:
		return eventstore.TopByPath, nil
	default:
		return "", fmt.Errorf("unsupported --by value %q (expected: domain, sni, path)", by)
	}
}

// runStatsList prints the raw event rows over the chosen window,
// latest first. When non-empty, cursor is the opaque token that a
// prior call printed as `next_cursor`. The command then prints the
// rows that follow the rows of that call.
//
// Each row holds the destination address and the rule index of its
// event. Both are empty in the CSV and in the table for an event
// without them. In JSON, `dst_ip` is then the empty string and
// `rule_index` is null.
func runStatsList(
	ctx context.Context, out io.Writer, usr *config.User,
	f *statsFlags, cursor string,
) error {
	rf, err := resolveFlags(f, time.Now())
	if err != nil {
		return err
	}

	dbPath := dbPathOrDefault(ctx, usr, f.dbPath)

	r, err := openStatsReader(ctx, dbPath)
	if err != nil {
		return err
	}

	defer r.Close() //nolint:errcheck // read-only.

	instance, err := resolveInstance(ctx, r, f.instance)
	if err != nil {
		return err
	}

	page, err := r.Events(ctx, eventstore.EventsQuery{
		Cursor: cursor,
		Filter: eventstore.Filter{
			Since:    rf.since,
			Until:    rf.until,
			Source:   rf.source,
			Instance: instance,
		},
		Limit: f.limit,
	})
	if err != nil {
		return err
	}

	var (
		results []listRow
		csvRows [][]string
	)

	for i := range page.Events {
		e := &page.Events[i]

		row := listRow{
			Time:       e.Time.UTC().Format(time.RFC3339),
			Source:     string(e.Source),
			Decision:   string(e.Decision),
			Domain:     e.Domain,
			Protocol:   string(e.Protocol),
			HTTPMethod: e.HTTPMethod,
			HTTPPath:   e.HTTPPath,
			Flags:      e.Flags,
			Reason:     string(e.Reason),
			Port:       e.Port,
			HTTPStatus: e.HTTPStatus,
		}

		// The CSV and the table leave the cell of an unset
		// destination address or rule index empty.
		var ruleIndex string

		if e.DstIP.IsValid() {
			row.DstIP = e.DstIP.String()
		}

		if e.HasRuleIndex {
			row.RuleIndex = &e.RuleIndex
			ruleIndex = strconv.Itoa(e.RuleIndex)
		}

		results = append(results, row)
		csvRows = append(csvRows, []string{
			row.Time, row.Source, row.Decision, row.Domain, row.DstIP,
			strconv.Itoa(row.Port), row.Protocol,
			row.HTTPMethod, row.HTTPPath,
			strconv.Itoa(row.HTTPStatus),
			row.Flags, row.Reason, ruleIndex,
		})
	}

	if page.NextCursor != "" {
		results[len(results)-1].NextCursor = page.NextCursor
	}

	headers := []string{
		"time", "source", "decision", "domain", "dst_ip", "port",
		"protocol", "method", "path", "status", "flags", "reason",
		"rule_index",
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

	r, err := openStatsReader(ctx, dbPath)
	if err != nil {
		return err
	}

	defer r.Close() //nolint:errcheck // read-only.

	instance, err := resolveInstance(ctx, r, f.instance)
	if err != nil {
		return err
	}

	type summary struct {
		Source   string `json:"source"`
		Decision string `json:"decision"`
		Count    int64  `json:"count"`
	}

	counts, err := r.Summary(ctx, eventstore.Filter{
		Since:    rf.since,
		Instance: instance,
	})
	if err != nil {
		return err
	}

	var (
		entries []summary
		csvRows [][]string
	)

	for _, c := range counts {
		s := summary{
			Source:   string(c.Source),
			Decision: string(c.Decision),
			Count:    c.Count,
		}

		entries = append(entries, s)
		csvRows = append(csvRows, []string{s.Source, s.Decision, strconv.FormatInt(s.Count, 10)})
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
