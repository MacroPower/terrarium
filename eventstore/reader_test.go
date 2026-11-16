package eventstore_test

import (
	"database/sql"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/eventstore"
)

// fixtureBase is the time of the first fixture event.
var fixtureBase = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// fixtureEvents returns the events of the first fixture instance.
// Each event holds a unique [eventstore.Event.Reason], which the
// tests use to name the event, and event N is at [fixtureBase] plus
// N minutes.
func fixtureEvents() []eventstore.Event {
	events := []eventstore.Event{
		{
			Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny,
			Domain: "evil.example", Protocol: eventstore.ProtocolDNS, Reason: "e0",
		},
		{
			Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny,
			Domain: "Sub.Evil.Example", Protocol: eventstore.ProtocolDNS, Reason: "e1",
		},
		{
			Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny,
			Domain: "notevil.example", Protocol: eventstore.ProtocolDNS, Reason: "e2",
		},
		{
			Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow,
			Domain: "evil.example.org", Protocol: eventstore.ProtocolDNS, Reason: "e3",
		},
		{
			Source: eventstore.SourceEnvoy, Decision: eventstore.DecisionAllow,
			Domain: "api.example", Port: 443, Protocol: eventstore.ProtocolHTTP,
			HTTPMethod: "GET", HTTPPath: "/v1/items?token=1", HTTPStatus: 200, Reason: "e4",
		},
		{
			Source: eventstore.SourceEnvoy, Decision: eventstore.DecisionAllow,
			Domain: "api.example", Port: 443, Protocol: eventstore.ProtocolHTTP,
			HTTPMethod: "GET", HTTPPath: "/v1/items?token=2", HTTPStatus: 200, Reason: "e5",
		},
		{
			Source: eventstore.SourceEnvoy, Decision: eventstore.DecisionAllow,
			Domain: "api.example", Port: 443, Protocol: eventstore.ProtocolHTTP,
			HTTPMethod: "GET", HTTPPath: "/health", HTTPStatus: 200, Reason: "e6",
		},
		{
			Source: eventstore.SourceEnvoy, Decision: eventstore.DecisionDeny,
			Domain: "sni.example", Port: 443, Protocol: eventstore.ProtocolTCP, Reason: "e7",
		},
		{
			Source: eventstore.SourceFirewall, Decision: eventstore.DecisionDeny,
			Port: 22, Protocol: eventstore.ProtocolTCP, Reason: "e8",
		},
		{
			Source: eventstore.SourceDNS, Decision: eventstore.DecisionError,
			Domain: "a_b.example", Protocol: eventstore.ProtocolDNS, Reason: "e9",
		},
		{
			Source: eventstore.SourceDNS, Decision: eventstore.DecisionError,
			Domain: "x.axb.example", Protocol: eventstore.ProtocolDNS, Reason: "e10",
		},
	}

	for i := range events {
		events[i].Time = fixtureBase.Add(time.Duration(i) * time.Minute)
	}

	return events
}

// writeStore opens the store at path, emits events, and closes the
// store, which writes each event. It returns the instance ID.
func writeStore(t *testing.T, path string, events []eventstore.Event, opts ...eventstore.Option) string {
	t.Helper()

	store, err := eventstore.Open(t.Context(), path, opts...)
	require.NoError(t, err)

	for i := range events {
		store.Emit(events[i])
	}

	require.NoError(t, store.Close())
	require.Zero(t, store.DropCount())

	return store.InstanceID()
}

// fixture holds a [eventstore.Reader] on a database with two
// instances. The first instance holds [fixtureEvents], and the
// second instance holds one event with the reason "late".
type fixture struct {
	reader *eventstore.Reader
	first  string
	second string
}

func newFixture(t *testing.T) fixture {
	t.Helper()

	path := filepath.Join(t.TempDir(), "stats.db")

	first := writeStore(t, path, fixtureEvents(), eventstore.WithMode(eventstore.ModeInit))
	second := writeStore(t, path, []eventstore.Event{{
		Time:   fixtureBase.Add(time.Hour),
		Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny,
		Domain: "late.example", Protocol: eventstore.ProtocolDNS, Reason: "late",
	}}, eventstore.WithMode(eventstore.ModeDaemon))

	return fixture{reader: openReader(t, path), first: first, second: second}
}

func openReader(t *testing.T, path string) *eventstore.Reader {
	t.Helper()

	r, err := eventstore.OpenReader(t.Context(), path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, r.Close()) })

	return r
}

// rawDB creates a database at path with the given statements, without
// the production schema path.
func rawDB(t *testing.T, path string, stmts ...string) {
	t.Helper()

	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err)

	for _, stmt := range stmts {
		_, err = raw.ExecContext(t.Context(), stmt)
		require.NoError(t, err)
	}

	require.NoError(t, raw.Close())
}

// reasons returns the reason of each event, in order.
func reasons(events []eventstore.StoredEvent) []string {
	var out []string

	for i := range events {
		out = append(out, string(events[i].Reason))
	}

	return out
}

func TestOpenReader(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		err error
		// dir is a directory under the temporary directory that
		// the test does not create.
		dir string
		// stmts create the database.
		stmts []string
		fails bool
	}{
		"current schema": {
			stmts: []string{
				v3SchemaSQL,
				`ALTER TABLE events ADD COLUMN dst_ip TEXT`,
				`ALTER TABLE events ADD COLUMN rule_index INTEGER`,
				`PRAGMA user_version = 4`,
			},
		},
		"schema version 3": {
			stmts: []string{v3SchemaSQL, `PRAGMA user_version = 3`},
		},
		"schema version 2": {
			stmts: []string{v2SchemaSQL, `PRAGMA user_version = 2`},
		},
		"schema version 1": {
			stmts: []string{v1SchemaSQL, `PRAGMA user_version = 1`},
		},
		"no schema": {
			stmts: []string{`PRAGMA user_version = 0`},
		},
		"newer schema": {
			stmts: []string{`PRAGMA user_version = 99`},
			err:   eventstore.ErrSchemaTooNew,
		},
		"negative version": {
			stmts: []string{`PRAGMA user_version = -1`},
			fails: true,
		},
		"missing file": {
			fails: true,
		},
		"missing directory": {
			dir:   "missing",
			fails: true,
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), tc.dir, "stats.db")

			if tc.stmts != nil {
				rawDB(t, path, tc.stmts...)
			}

			r, err := eventstore.OpenReader(t.Context(), path)

			if tc.stmts == nil {
				assert.NoFileExists(t, path)
			}

			switch {
			case tc.err != nil:
				require.ErrorIs(t, err, tc.err)
				assert.Nil(t, r)

			case tc.fails:
				require.Error(t, err)
				require.NotErrorIs(t, err, eventstore.ErrSchemaTooNew)
				assert.Nil(t, r)

			default:
				require.NoError(t, err)
				require.NoError(t, r.Close())
			}
		})
	}
}

func TestReader_CloseNil(t *testing.T) {
	t.Parallel()

	var r *eventstore.Reader

	require.NoError(t, r.Close())
}

func TestReader_Summary(t *testing.T) {
	t.Parallel()

	f := newFixture(t)

	tcs := map[string]struct {
		filter eventstore.Filter
		want   []eventstore.SummaryRow
	}{
		"all events": {
			want: []eventstore.SummaryRow{
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Count: 1},
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Count: 4},
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionError, Count: 2},
				{Source: eventstore.SourceEnvoy, Decision: eventstore.DecisionAllow, Count: 3},
				{Source: eventstore.SourceEnvoy, Decision: eventstore.DecisionDeny, Count: 1},
				{Source: eventstore.SourceFirewall, Decision: eventstore.DecisionDeny, Count: 1},
			},
		},
		"one instance": {
			filter: eventstore.Filter{Instance: f.second},
			want: []eventstore.SummaryRow{
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Count: 1},
			},
		},
		"since is inclusive": {
			filter: eventstore.Filter{Since: fixtureBase.Add(8 * time.Minute), Instance: f.first},
			want: []eventstore.SummaryRow{
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionError, Count: 2},
				{Source: eventstore.SourceFirewall, Decision: eventstore.DecisionDeny, Count: 1},
			},
		},
		"until is inclusive": {
			filter: eventstore.Filter{Until: fixtureBase.Add(3 * time.Minute)},
			want: []eventstore.SummaryRow{
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Count: 1},
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Count: 3},
			},
		},
		"source and decision": {
			filter: eventstore.Filter{Source: eventstore.SourceEnvoy, Decision: eventstore.DecisionAllow},
			want: []eventstore.SummaryRow{
				{Source: eventstore.SourceEnvoy, Decision: eventstore.DecisionAllow, Count: 3},
			},
		},
		"domain": {
			filter: eventstore.Filter{Domain: "evil.example"},
			want: []eventstore.SummaryRow{
				{Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Count: 2},
			},
		},
		"no match": {
			filter: eventstore.Filter{Instance: "deadbeefdeadbeef"},
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := f.reader.Summary(t.Context(), tc.filter)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestReader_Top(t *testing.T) {
	t.Parallel()

	f := newFixture(t)

	tcs := map[string]struct {
		err   error
		query eventstore.TopQuery
		want  []eventstore.TopRow
	}{
		"zero By groups by domain": {
			query: eventstore.TopQuery{
				Filter: eventstore.Filter{Decision: eventstore.DecisionAllow},
				Limit:  10,
			},
			want: []eventstore.TopRow{
				{Bucket: "api.example", Count: 3},
				{Bucket: "evil.example.org", Count: 1},
			},
		},
		"domain skips events without a domain": {
			query: eventstore.TopQuery{
				By:     eventstore.TopByDomain,
				Filter: eventstore.Filter{Source: eventstore.SourceFirewall},
				Limit:  10,
			},
		},
		"sni reads only tcp events": {
			query: eventstore.TopQuery{By: eventstore.TopBySNI, Limit: 10},
			want:  []eventstore.TopRow{{Bucket: "sni.example", Count: 1}},
		},
		"path drops the query string": {
			query: eventstore.TopQuery{By: eventstore.TopByPath, Limit: 10},
			want: []eventstore.TopRow{
				{Bucket: "/v1/items", Count: 2},
				{Bucket: "/health", Count: 1},
			},
		},
		"limit": {
			query: eventstore.TopQuery{By: eventstore.TopByPath, Limit: 1},
			want:  []eventstore.TopRow{{Bucket: "/v1/items", Count: 2}},
		},
		"zero limit": {
			query: eventstore.TopQuery{By: eventstore.TopByPath},
		},
		"negative limit": {
			query: eventstore.TopQuery{By: eventstore.TopByPath, Limit: -1},
			want: []eventstore.TopRow{
				{Bucket: "/v1/items", Count: 2},
				{Bucket: "/health", Count: 1},
			},
		},
		"instance": {
			query: eventstore.TopQuery{
				Filter: eventstore.Filter{Instance: f.second},
				Limit:  10,
			},
			want: []eventstore.TopRow{{Bucket: "late.example", Count: 1}},
		},
		"time window": {
			query: eventstore.TopQuery{
				Filter: eventstore.Filter{
					Since: fixtureBase.Add(5 * time.Minute),
					Until: fixtureBase.Add(7 * time.Minute),
				},
				Limit: 10,
			},
			want: []eventstore.TopRow{
				{Bucket: "api.example", Count: 2},
				{Bucket: "sni.example", Count: 1},
			},
		},
		"unknown By": {
			query: eventstore.TopQuery{By: "port", Limit: 10},
			err:   eventstore.ErrUnknownTopBy,
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := f.reader.Top(t.Context(), tc.query)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestReader_Events_Filters(t *testing.T) {
	t.Parallel()

	f := newFixture(t)

	tcs := map[string]struct {
		filter eventstore.Filter
		want   []string
	}{
		"all events, latest first": {
			want: []string{"late", "e10", "e9", "e8", "e7", "e6", "e5", "e4", "e3", "e2", "e1", "e0"},
		},
		"instance": {
			filter: eventstore.Filter{Instance: f.second},
			want:   []string{"late"},
		},
		"since is inclusive": {
			filter: eventstore.Filter{Since: fixtureBase.Add(9 * time.Minute)},
			want:   []string{"late", "e10", "e9"},
		},
		"until is inclusive": {
			filter: eventstore.Filter{Until: fixtureBase.Add(time.Minute)},
			want:   []string{"e1", "e0"},
		},
		"source": {
			filter: eventstore.Filter{Source: eventstore.SourceEnvoy},
			want:   []string{"e7", "e6", "e5", "e4"},
		},
		"decision": {
			filter: eventstore.Filter{Decision: eventstore.DecisionError},
			want:   []string{"e10", "e9"},
		},
		"decision and source": {
			filter: eventstore.Filter{
				Decision: eventstore.DecisionDeny,
				Source:   eventstore.SourceEnvoy,
			},
			want: []string{"e7"},
		},
		"domain matches the name and its subdomains": {
			filter: eventstore.Filter{Domain: "evil.example"},
			want:   []string{"e1", "e0"},
		},
		"domain ignores case and a trailing dot": {
			filter: eventstore.Filter{Domain: "EVIL.Example."},
			want:   []string{"e1", "e0"},
		},
		"domain matches a subdomain exactly": {
			filter: eventstore.Filter{Domain: "sub.evil.example"},
			want:   []string{"e1"},
		},
		"domain does not match a longer suffix": {
			filter: eventstore.Filter{Domain: "example"},
			want:   []string{"late", "e10", "e9", "e7", "e6", "e5", "e4", "e2", "e1", "e0"},
		},
		"domain takes an underscore literally": {
			filter: eventstore.Filter{Domain: "a_b.example"},
			want:   []string{"e9"},
		},
		"domain takes a percent sign literally": {
			filter: eventstore.Filter{Domain: "%.example"},
		},
		"domain skips events without a domain": {
			filter: eventstore.Filter{Domain: "example", Source: eventstore.SourceFirewall},
		},
		"every filter": {
			filter: eventstore.Filter{
				Since:    fixtureBase,
				Until:    fixtureBase.Add(2 * time.Minute),
				Source:   eventstore.SourceDNS,
				Decision: eventstore.DecisionDeny,
				Instance: f.first,
				Domain:   "evil.example",
			},
			want: []string{"e1", "e0"},
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := f.reader.Events(t.Context(), eventstore.EventsQuery{
				Filter: tc.filter,
				Limit:  -1,
			})
			require.NoError(t, err)
			assert.Equal(t, tc.want, reasons(got.Events))
			assert.Empty(t, got.NextCursor)
		})
	}
}

func TestReader_DomainTrailingDot(t *testing.T) {
	t.Parallel()

	// The firewall events hold the fully qualified name that the DNS
	// proxy resolved, and the DNS events hold the name without the
	// trailing dot.
	events := []eventstore.Event{
		{
			Source: eventstore.SourceFirewall, Decision: eventstore.DecisionAllow,
			Domain: "evil.example.", Port: 443, Protocol: eventstore.ProtocolTCP, Reason: "fw0",
		},
		{
			Source: eventstore.SourceFirewall, Decision: eventstore.DecisionAllow,
			Domain: "sub.evil.example.", Port: 443, Protocol: eventstore.ProtocolTCP, Reason: "fw1",
		},
		{
			Source: eventstore.SourceFirewall, Decision: eventstore.DecisionAllow,
			Domain: "notevil.example.", Port: 443, Protocol: eventstore.ProtocolTCP, Reason: "fw2",
		},
		{
			Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow,
			Domain: "evil.example", Protocol: eventstore.ProtocolDNS, Reason: "dns0",
		},
	}

	for i := range events {
		events[i].Time = fixtureBase.Add(time.Duration(i) * time.Minute)
	}

	path := filepath.Join(t.TempDir(), "stats.db")
	writeStore(t, path, events)

	r := openReader(t, path)

	tcs := map[string]struct {
		domain string
		want   []string
	}{
		"name without a dot": {
			domain: "evil.example",
			want:   []string{"dns0", "fw1", "fw0"},
		},
		"name with a dot": {
			domain: "evil.example.",
			want:   []string{"dns0", "fw1", "fw0"},
		},
		"subdomain": {
			domain: "sub.evil.example",
			want:   []string{"fw1"},
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			filter := eventstore.Filter{Domain: tc.domain}

			page, err := r.Events(t.Context(), eventstore.EventsQuery{Filter: filter, Limit: -1})
			require.NoError(t, err)
			assert.Equal(t, tc.want, reasons(page.Events))

			summary, err := r.Summary(t.Context(), filter)
			require.NoError(t, err)

			var total int64

			for _, s := range summary {
				total += s.Count
			}

			assert.Equal(t, int64(len(tc.want)), total)
		})
	}
}

func TestReader_Events_Fields(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")

	full := eventstore.Event{
		Time:       fixtureBase,
		Domain:     "api.example",
		Source:     eventstore.SourceEnvoy,
		Decision:   eventstore.DecisionDeny,
		Protocol:   eventstore.ProtocolHTTP,
		HTTPMethod: "POST",
		HTTPPath:   "/v1/admin?x=1",
		Flags:      "UAEX",
		Reason:     "rbac",
		Port:       8443,
		HTTPStatus: 403,
		BytesRx:    11,
		BytesTx:    22,
		DurationMS: 33,
		DstIP:      netip.MustParseAddr("2001:db8::7"),
		// Index 0 is the first rule, so it must not read as unset.
		RuleIndex:    0,
		HasRuleIndex: true,
	}
	sparse := eventstore.Event{
		Time:     fixtureBase.Add(time.Second),
		Source:   eventstore.SourceFirewall,
		Decision: eventstore.DecisionDeny,
	}
	indexed := eventstore.Event{
		Time:         fixtureBase.Add(2 * time.Second),
		Source:       eventstore.SourceFirewall,
		Decision:     eventstore.DecisionAllow,
		DstIP:        netip.MustParseAddr("192.0.2.7"),
		RuleIndex:    5,
		HasRuleIndex: true,
	}

	instance := writeStore(t, path, []eventstore.Event{full, sparse, indexed})

	got, err := openReader(t, path).Events(t.Context(), eventstore.EventsQuery{Limit: 10})
	require.NoError(t, err)
	require.Len(t, got.Events, 3)

	for i, want := range []eventstore.Event{indexed, sparse, full} {
		e := got.Events[i]

		assert.Equal(t, instance, e.InstanceID)
		assert.True(t, want.Time.Equal(e.Time), "time: want %s, got %s", want.Time, e.Time)

		// The stored time is equal, but it holds another location.
		e.Time = want.Time
		assert.Equal(t, want, e.Event)
	}

	assert.Greater(t, got.Events[0].ID, got.Events[1].ID)
}

// TestReader_Events_InvalidDstIP reads a row whose `dst_ip` column
// holds text that is not an IP address. The store never writes such a
// row.
func TestReader_Events_InvalidDstIP(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	instance := writeStore(t, path, nil)

	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err)

	_, err = raw.ExecContext(
		t.Context(),
		`INSERT INTO events (ts, instance_id, source, decision, dst_ip) VALUES (1, ?, 'firewall', 'deny', 'not-an-address')`,
		instance,
	)
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	_, err = openReader(t, path).Events(t.Context(), eventstore.EventsQuery{Limit: 10})
	require.ErrorContains(t, err, "parsing the destination address of event")
}

func TestReader_Events_Pages(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	filter := eventstore.Filter{Source: eventstore.SourceDNS}

	var (
		pages  [][]string
		cursor string
	)

	for {
		page, err := f.reader.Events(t.Context(), eventstore.EventsQuery{
			Filter: filter,
			Cursor: cursor,
			Limit:  3,
		})
		require.NoError(t, err)

		pages = append(pages, reasons(page.Events))

		if page.NextCursor == "" {
			break
		}

		cursor = page.NextCursor

		require.Less(t, len(pages), 10, "the cursor does not advance")
	}

	assert.Equal(t, [][]string{
		{"late", "e10", "e9"},
		{"e3", "e2", "e1"},
		{"e0"},
	}, pages)
}

func TestReader_Events_FullLastPageHasCursor(t *testing.T) {
	t.Parallel()

	f := newFixture(t)

	page, err := f.reader.Events(t.Context(), eventstore.EventsQuery{
		Filter: eventstore.Filter{Decision: eventstore.DecisionError},
		Limit:  2,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"e10", "e9"}, reasons(page.Events))
	require.NotEmpty(t, page.NextCursor)

	next, err := f.reader.Events(t.Context(), eventstore.EventsQuery{
		Filter: eventstore.Filter{Decision: eventstore.DecisionError},
		Cursor: page.NextCursor,
		Limit:  2,
	})
	require.NoError(t, err)
	assert.Empty(t, next.Events)
	assert.Empty(t, next.NextCursor)
}

func TestReader_Events_Limits(t *testing.T) {
	t.Parallel()

	f := newFixture(t)

	tcs := map[string]struct {
		limit      int
		want       int
		wantCursor bool
	}{
		"zero returns no row":          {limit: 0, want: 0},
		"negative returns every row":   {limit: -1, want: 12},
		"positive caps the rows":       {limit: 5, want: 5, wantCursor: true},
		"more than the rows available": {limit: 50, want: 12},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			page, err := f.reader.Events(t.Context(), eventstore.EventsQuery{Limit: tc.limit})
			require.NoError(t, err)
			assert.Len(t, page.Events, tc.want)
			assert.Equal(t, tc.wantCursor, page.NextCursor != "")
		})
	}
}

func TestReader_Events_InvalidCursor(t *testing.T) {
	t.Parallel()

	f := newFixture(t)

	tcs := map[string]struct {
		cursor string
	}{
		"not base64":   {cursor: "!!!"},
		"not a number": {cursor: "YWJj"},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := f.reader.Events(t.Context(), eventstore.EventsQuery{
				Cursor: tc.cursor,
				Limit:  10,
			})
			require.ErrorIs(t, err, eventstore.ErrInvalidCursor)
		})
	}
}

func TestReader_Instances(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")

	before := time.Now().Add(-time.Second)
	ended := writeStore(t, path, nil, eventstore.WithMode(eventstore.ModeProxy))

	running, err := eventstore.Open(t.Context(), path, eventstore.WithMode(eventstore.ModeDaemon))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, running.Close()) })

	after := time.Now().Add(time.Second)

	got, err := openReader(t, path).Instances(t.Context())
	require.NoError(t, err)
	require.Len(t, got, 2)

	assert.Equal(t, running.InstanceID(), got[0].ID)
	assert.Equal(t, eventstore.ModeDaemon, got[0].Mode)
	assert.True(t, got[0].EndedAt.IsZero())

	assert.Equal(t, ended, got[1].ID)
	assert.Equal(t, eventstore.ModeProxy, got[1].Mode)
	assert.False(t, got[1].EndedAt.Before(got[1].StartedAt))
	assert.False(t, got[1].EndedAt.After(after))

	for _, in := range got {
		assert.False(t, in.StartedAt.Before(before))
		assert.False(t, in.StartedAt.After(after))
	}

	assert.False(t, got[0].StartedAt.Before(got[1].StartedAt))
}

func TestReader_DefaultInstanceID(t *testing.T) {
	t.Parallel()

	const schema = v1SchemaSQL + `PRAGMA user_version = 1;`

	tcs := map[string]struct {
		rows   string
		want   string
		wantOK bool
	}{
		"no instance": {},
		"latest start wins among ended instances": {
			rows: `INSERT INTO instances (id, started_at, ended_at, mode) VALUES
				('old', 100, 150, 'init'), ('new', 200, 250, 'init');`,
			want:   "new",
			wantOK: true,
		},
		"a later ended instance wins over an instance without an end": {
			rows: `INSERT INTO instances (id, started_at, ended_at, mode) VALUES
				('crashed', 100, NULL, 'init'), ('ended', 200, 250, 'init');`,
			want:   "ended",
			wantOK: true,
		},
		"a later instance without an end wins over an ended instance": {
			rows: `INSERT INTO instances (id, started_at, ended_at, mode) VALUES
				('ended', 100, 150, 'init'), ('running', 200, NULL, 'init');`,
			want:   "running",
			wantOK: true,
		},
		"latest start wins among instances without an end": {
			rows: `INSERT INTO instances (id, started_at, ended_at, mode) VALUES
				('old', 100, NULL, 'init'), ('new', 200, NULL, 'init');`,
			want:   "new",
			wantOK: true,
		},
		"the later row wins among instances with the same start": {
			rows: `INSERT INTO instances (id, started_at, ended_at, mode) VALUES
				('b', 100, NULL, 'init'), ('a', 100, 150, 'init');`,
			want:   "a",
			wantOK: true,
		},
		"a daemon wins over a later proxy": {
			rows: `INSERT INTO instances (id, started_at, ended_at, mode) VALUES
				('daemon', 100, NULL, 'daemon'), ('proxy', 200, NULL, 'proxy');`,
			want:   "daemon",
			wantOK: true,
		},
		"an init run wins over a later proxy": {
			rows: `INSERT INTO instances (id, started_at, ended_at, mode) VALUES
				('init', 100, NULL, 'init'), ('proxy', 200, NULL, 'proxy');`,
			want:   "init",
			wantOK: true,
		},
		"an ended daemon wins over a later proxy without an end": {
			rows: `INSERT INTO instances (id, started_at, ended_at, mode) VALUES
				('daemon', 100, 150, 'daemon'), ('proxy', 200, NULL, 'proxy');`,
			want:   "daemon",
			wantOK: true,
		},
		"a daemon wins over an earlier proxy": {
			rows: `INSERT INTO instances (id, started_at, ended_at, mode) VALUES
				('proxy', 100, NULL, 'proxy'), ('daemon', 200, NULL, 'daemon');`,
			want:   "daemon",
			wantOK: true,
		},
		"latest start wins among init and daemon runs between proxies": {
			rows: `INSERT INTO instances (id, started_at, ended_at, mode) VALUES
				('init', 100, 150, 'init'), ('proxy1', 200, 250, 'proxy'),
				('daemon', 300, 350, 'daemon'), ('proxy2', 400, NULL, 'proxy');`,
			want:   "daemon",
			wantOK: true,
		},
		"a later init run wins over a daemon": {
			rows: `INSERT INTO instances (id, started_at, ended_at, mode) VALUES
				('daemon', 100, NULL, 'daemon'), ('init', 200, NULL, 'init'),
				('proxy', 300, NULL, 'proxy');`,
			want:   "init",
			wantOK: true,
		},
		"the later row wins among init and daemon runs with the same start": {
			rows: `INSERT INTO instances (id, started_at, ended_at, mode) VALUES
				('daemon', 100, NULL, 'daemon'), ('proxy', 100, NULL, 'proxy'),
				('init', 100, NULL, 'init'), ('proxy2', 100, NULL, 'proxy');`,
			want:   "init",
			wantOK: true,
		},
		// The store holds no init or daemon run.
		"latest start wins among proxies": {
			rows: `INSERT INTO instances (id, started_at, ended_at, mode) VALUES
				('old', 100, NULL, 'proxy'), ('new', 200, 250, 'proxy');`,
			want:   "new",
			wantOK: true,
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "stats.db")
			rawDB(t, path, schema, tc.rows)

			got, ok, err := openReader(t, path).DefaultInstanceID(t.Context())
			require.NoError(t, err)
			assert.Equal(t, tc.wantOK, ok)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestReader_DefaultInstanceIDByMode starts one run of each mode and
// then a proxy. The earlier run stays the default when its mode has a
// firewall.
func TestReader_DefaultInstanceIDByMode(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		mode eventstore.Mode
		want bool
	}{
		"init":   {mode: eventstore.ModeInit, want: true},
		"daemon": {mode: eventstore.ModeDaemon, want: true},
		"proxy":  {mode: eventstore.ModeProxy, want: false},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, tc.mode.HasFirewall())

			path := filepath.Join(t.TempDir(), "stats.db")

			earlier := writeStore(t, path, nil, eventstore.WithMode(tc.mode))
			proxy := writeStore(t, path, nil, eventstore.WithMode(eventstore.ModeProxy))

			want := proxy
			if tc.want {
				want = earlier
			}

			got, ok, err := openReader(t, path).DefaultInstanceID(t.Context())
			require.NoError(t, err)
			assert.True(t, ok)
			assert.Equal(t, want, got)
		})
	}
}

func TestReader_DefaultInstanceIDAfterRunWithoutEnd(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")

	// A store that stays open records no end, as a process does
	// that stops without a Close.
	unended, err := eventstore.Open(t.Context(), path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, unended.Close()) })

	later := writeStore(t, path, nil)

	got, ok, err := openReader(t, path).DefaultInstanceID(t.Context())
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, later, got)
}

func TestReader_Health(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	now := time.Now()

	store, err := eventstore.Open(t.Context(), path)
	require.NoError(t, err)

	events := []eventstore.Event{
		// Outside the 24-hour window.
		{Time: now.Add(-25 * time.Hour), Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow},
		// Inside the 24-hour window, outside the 1-hour window.
		{Time: now.Add(-2 * time.Hour), Source: eventstore.SourceFirewall, Decision: eventstore.DecisionDeny},
		// Inside the 1-hour window.
		{Time: now.Add(-30 * time.Minute), Source: eventstore.SourceFirewall, Decision: eventstore.DecisionDeny},
		{Time: now.Add(-20 * time.Minute), Source: eventstore.SourceFirewall, Decision: eventstore.DecisionDeny},
		{
			Time: now.Add(-10 * time.Minute), Source: eventstore.SourceFirewall,
			Decision: eventstore.DecisionAllow, Domain: "resolved.example",
		},
		// A domain-less event of another source does not count as
		// a firewall event.
		{Time: now.Add(-5 * time.Minute), Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow},
	}

	for i := range events {
		store.Emit(events[i])
	}

	require.NoError(t, store.RecordHeartbeat(t.Context(), eventstore.Heartbeat{
		RecordedAt:       now,
		NFLogKernelDrops: 3,
		DNSCacheSize:     42,
	}))
	require.NoError(t, store.Close())

	r := openReader(t, path)

	tcs := map[string]struct {
		instance      string
		wantHeartbeat bool
	}{
		"instance with a heartbeat":    {instance: store.InstanceID(), wantHeartbeat: true},
		"instance without a heartbeat": {instance: "deadbeefdeadbeef"},
		"no instance":                  {},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := r.Health(t.Context(), tc.instance)
			require.NoError(t, err)

			assert.Equal(t, int64(5), got.Events24h)
			assert.Equal(t, int64(3), got.FirewallEvents1h)
			assert.Equal(t, int64(2), got.FirewallNullDomain1h)
			assert.WithinDuration(t, now.Add(-5*time.Minute), got.LastEvent, time.Millisecond)

			assert.Equal(t, tc.wantHeartbeat, got.HasHeartbeat)

			if !tc.wantHeartbeat {
				assert.Zero(t, got.Heartbeat)

				return
			}

			assert.WithinDuration(t, now, got.Heartbeat.RecordedAt, time.Millisecond)
			assert.Equal(t, uint64(3), got.Heartbeat.NFLogKernelDrops)
			assert.Equal(t, int64(42), got.Heartbeat.DNSCacheSize)
		})
	}
}

func TestReader_Health_EmptyStore(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	id := writeStore(t, path, nil)

	got, err := openReader(t, path).Health(t.Context(), id)
	require.NoError(t, err)
	assert.Zero(t, got)
}

// TestReader_SchemaVersion1 reads a database that holds the schema of
// version 1, which has no `instance_metrics` table.
func TestReader_SchemaVersion1(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	recent := time.Now().Add(-time.Minute).UnixMicro()

	rawDB(t, path,
		v1SchemaSQL,
		`PRAGMA user_version = 1`,
		`INSERT INTO instances (id, started_at, ended_at, mode) VALUES ('v1instance', 100, NULL, 'init')`,
	)

	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err)

	_, err = raw.ExecContext(t.Context(), `
		INSERT INTO events (ts, instance_id, source, decision, domain, protocol, http_path) VALUES
			(?, 'v1instance', 'dns', 'deny', 'evil.example', 'dns', NULL),
			(?, 'v1instance', 'envoy', 'allow', 'api.example', 'http', '/v1/items?a=1'),
			(?, 'v1instance', 'firewall', 'deny', NULL, 'tcp', NULL)
	`, recent, recent+1, recent+2)
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	r := openReader(t, path)

	id, ok, err := r.DefaultInstanceID(t.Context())
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "v1instance", id)

	instances, err := r.Instances(t.Context())
	require.NoError(t, err)
	require.Len(t, instances, 1)
	assert.Equal(t, "v1instance", instances[0].ID)
	assert.Equal(t, eventstore.ModeInit, instances[0].Mode)
	assert.True(t, instances[0].EndedAt.IsZero())

	summary, err := r.Summary(t.Context(), eventstore.Filter{Instance: id})
	require.NoError(t, err)
	assert.Equal(t, []eventstore.SummaryRow{
		{Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Count: 1},
		{Source: eventstore.SourceEnvoy, Decision: eventstore.DecisionAllow, Count: 1},
		{Source: eventstore.SourceFirewall, Decision: eventstore.DecisionDeny, Count: 1},
	}, summary)

	top, err := r.Top(t.Context(), eventstore.TopQuery{By: eventstore.TopByPath, Limit: 10})
	require.NoError(t, err)
	assert.Equal(t, []eventstore.TopRow{{Bucket: "/v1/items", Count: 1}}, top)

	page, err := r.Events(t.Context(), eventstore.EventsQuery{
		Filter: eventstore.Filter{Decision: eventstore.DecisionDeny},
		Limit:  10,
	})
	require.NoError(t, err)
	require.Len(t, page.Events, 2)
	assert.Equal(t, eventstore.SourceFirewall, page.Events[0].Source)
	assert.Equal(t, "evil.example", page.Events[1].Domain)

	// Version 1 has no column for the destination address or for the
	// rule index.
	for i := range page.Events {
		assert.False(t, page.Events[i].DstIP.IsValid())
		assert.False(t, page.Events[i].HasRuleIndex)
	}

	// Version 1 has no table for heartbeats.
	_, ok, err = r.LatestHeartbeat(t.Context(), id)
	require.NoError(t, err)
	assert.False(t, ok)

	// Version 1 has no table for policy snapshots.
	_, ok, err = r.LatestPolicy(t.Context(), id)
	require.NoError(t, err)
	assert.False(t, ok)

	_, ok, err = r.PolicyAt(t.Context(), id, time.Now())
	require.NoError(t, err)
	assert.False(t, ok)

	policies, err := r.Policies(t.Context(), id)
	require.NoError(t, err)
	assert.Empty(t, policies)

	health, err := r.Health(t.Context(), id)
	require.NoError(t, err)
	assert.False(t, health.HasHeartbeat)
	assert.Equal(t, int64(3), health.Events24h)
	assert.Equal(t, int64(1), health.FirewallEvents1h)
	assert.Equal(t, int64(1), health.FirewallNullDomain1h)
	assert.Equal(t, recent+2, health.LastEvent.UnixMicro())
}

// TestReader_NoSchema reads a database file that no [eventstore.Open]
// gave a schema yet, so it holds no table.
func TestReader_NoSchema(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	rawDB(t, path, `PRAGMA user_version = 0`)

	r := openReader(t, path)

	id, ok, err := r.DefaultInstanceID(t.Context())
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Empty(t, id)

	instances, err := r.Instances(t.Context())
	require.NoError(t, err)
	assert.Empty(t, instances)

	summary, err := r.Summary(t.Context(), eventstore.Filter{})
	require.NoError(t, err)
	assert.Empty(t, summary)

	top, err := r.Top(t.Context(), eventstore.TopQuery{Limit: 10})
	require.NoError(t, err)
	assert.Empty(t, top)

	page, err := r.Events(t.Context(), eventstore.EventsQuery{Limit: 10})
	require.NoError(t, err)
	assert.Zero(t, page)

	_, ok, err = r.LatestHeartbeat(t.Context(), "deadbeefdeadbeef")
	require.NoError(t, err)
	assert.False(t, ok)

	health, err := r.Health(t.Context(), "deadbeefdeadbeef")
	require.NoError(t, err)
	assert.Zero(t, health)

	_, ok, err = r.LatestPolicy(t.Context(), "deadbeefdeadbeef")
	require.NoError(t, err)
	assert.False(t, ok)

	_, ok, err = r.PolicyAt(t.Context(), "deadbeefdeadbeef", time.Now())
	require.NoError(t, err)
	assert.False(t, ok)

	policies, err := r.Policies(t.Context(), "")
	require.NoError(t, err)
	assert.Empty(t, policies)

	// The reader still checks the arguments on a database without tables.
	_, err = r.Top(t.Context(), eventstore.TopQuery{By: "port"})
	require.ErrorIs(t, err, eventstore.ErrUnknownTopBy)

	_, err = r.Events(t.Context(), eventstore.EventsQuery{Cursor: "!!!"})
	require.ErrorIs(t, err, eventstore.ErrInvalidCursor)
}
