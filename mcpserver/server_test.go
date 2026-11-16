package mcpserver_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/eventstore"
	"go.jacobcolvin.com/terrarium/mcpserver"
)

// toolNames holds the name of every tool of the server.
var toolNames = []string{
	"get_health",
	"get_policy",
	"list_events",
	"list_instances",
	"list_policies",
	"summarize_events",
	"top_events",
}

// locateAt returns a [mcpserver.LocateFunc] that returns path.
func locateAt(path string) mcpserver.LocateFunc {
	return func(context.Context) (string, error) {
		return path, nil
	}
}

// connect serves a [mcpserver.Server] on an in-memory transport and
// returns the session of a client of that server.
func connect(t *testing.T, locate mcpserver.LocateFunc) *mcp.ClientSession {
	t.Helper()

	serverSide, clientSide := mcp.NewInMemoryTransports()
	srv := mcpserver.New(locate, mcpserver.WithVersion("1.2.3"))

	ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	done := make(chan error, 1)

	go func() {
		done <- srv.Run(ctx, serverSide)
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)

	session, err := client.Connect(ctx, clientSide, nil)
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, session.Close())
		assert.NoError(t, <-done)
		cancel()
	})

	return session
}

// call calls the tool with the given name and decodes its structured
// result into Out. It fails the test when the tool returns an error.
func call[Out any](t *testing.T, session *mcp.ClientSession, name string, args map[string]any) Out {
	t.Helper()

	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	require.NoError(t, err)
	require.False(t, res.IsError, "tool %s returned the error %s", name, text(t, res))
	require.NotNil(t, res.StructuredContent, "tool %s returned no structured content", name)

	raw, err := json.Marshal(res.StructuredContent)
	require.NoError(t, err)

	// The text content holds the same JSON document, for a client
	// that does not read structured content.
	assert.JSONEq(t, string(raw), text(t, res))

	var out Out

	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&out))

	return out
}

// callError calls the tool with the given name and returns the
// message of its tool error. It fails the test when the call succeeds
// or when it breaks the session.
func callError(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()

	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	require.NoError(t, err)
	require.True(t, res.IsError, "tool %s returned no error", name)
	assert.Nil(t, res.StructuredContent)

	return text(t, res)
}

// text returns the text content of a tool result.
func text(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()

	require.Len(t, res.Content, 1)

	content, ok := res.Content[0].(*mcp.TextContent)
	require.True(t, ok, "content is %T", res.Content[0])

	return content.Text
}

// openStore opens the event store at path. The store writes each
// event in its own batch, and the test closes it at its end.
func openStore(t *testing.T, path string, opts ...eventstore.Option) *eventstore.Store {
	t.Helper()

	opts = append([]eventstore.Option{
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(10 * time.Millisecond),
	}, opts...)

	store, err := eventstore.Open(context.WithoutCancel(t.Context()), path, opts...)
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, store.Close())
	})

	return store
}

// emit writes the events to the store and waits until the database at
// path holds total events.
func emit(t *testing.T, store *eventstore.Store, path string, total int64, events ...eventstore.Event) {
	t.Helper()

	for i := range events {
		store.Emit(events[i])
	}

	require.Eventually(t, func() bool {
		r, err := eventstore.OpenReader(t.Context(), path)
		if err != nil {
			return false
		}

		defer r.Close() //nolint:errcheck // read-only handle in polling closure.

		rows, err := r.Summary(t.Context(), eventstore.Filter{})
		if err != nil {
			return false
		}

		var n int64

		for _, row := range rows {
			n += row.Count
		}

		return n == total
	}, 5*time.Second, 10*time.Millisecond)
}

// heartbeat records h for the store and waits until the database at
// path holds it.
func heartbeat(t *testing.T, store *eventstore.Store, path string, h eventstore.Heartbeat) {
	t.Helper()

	require.NoError(t, store.RecordHeartbeat(t.Context(), h))

	require.Eventually(t, func() bool {
		r, err := eventstore.OpenReader(t.Context(), path)
		if err != nil {
			return false
		}

		defer r.Close() //nolint:errcheck // read-only handle in polling closure.

		got, ok, err := r.LatestHeartbeat(t.Context(), store.InstanceID())

		return err == nil && ok && got.RecordedAt.Equal(h.RecordedAt.Truncate(time.Microsecond))
	}, 5*time.Second, 10*time.Millisecond)
}

// seeded describes the database that [seed] writes.
type seeded struct {
	// now is the time that the event times count back from.
	now time.Time

	// path is the path of the database.
	path string

	// proxy is the ID of the earlier instance, which ended.
	proxy string

	// daemon is the ID of the latest instance, which is running.
	daemon string
}

// seed writes a database with two instances. The earlier one is a
// proxy that recorded one event and ended. The latest one is a daemon
// that is running. It recorded six events in the last hour, one event
// two days ago, one heartbeat, and one snapshot of [seedPolicy].
func seed(t *testing.T) seeded {
	t.Helper()

	s := seeded{
		now:  time.Now().Truncate(time.Microsecond),
		path: filepath.Join(t.TempDir(), "stats.db"),
	}

	proxy := openStore(t, s.path,
		eventstore.WithMode(eventstore.ModeProxy),
		eventstore.WithInstanceName("127.0.0.1-8080"),
		eventstore.WithConfigPath("/etc/terrarium/proxy.yaml"))
	s.proxy = proxy.InstanceID()

	emit(t, proxy, s.path, 1, eventstore.Event{
		Time:     s.now.Add(-3 * time.Hour),
		Source:   eventstore.SourceEnvoy,
		Decision: eventstore.DecisionAllow,
		Protocol: eventstore.ProtocolTCP,
		Domain:   "proxied.example",
		Port:     443,
	})

	require.NoError(t, proxy.Close())

	// The instances order by their start time, so the daemon must
	// start at a later microsecond than the proxy.
	time.Sleep(2 * time.Millisecond)

	daemon := openStore(t, s.path, eventstore.WithMode(eventstore.ModeDaemon))
	s.daemon = daemon.InstanceID()

	emit(t, daemon, s.path, 8,
		eventstore.Event{
			Time:     s.now.Add(-48 * time.Hour),
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionDeny,
			Protocol: eventstore.ProtocolDNS,
			Domain:   "old.test",
			Reason:   eventstore.ReasonNotAllowlisted,
		},
		eventstore.Event{
			Time:     s.now.Add(-6 * time.Minute),
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionAllow,
			Protocol: eventstore.ProtocolDNS,
			Domain:   "example.com",
		},
		eventstore.Event{
			Time:     s.now.Add(-5 * time.Minute),
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionDeny,
			Protocol: eventstore.ProtocolDNS,
			Domain:   "blocked.test",
			Reason:   eventstore.ReasonNotAllowlisted,
		},
		eventstore.Event{
			Time:       s.now.Add(-4 * time.Minute),
			Source:     eventstore.SourceEnvoy,
			Decision:   eventstore.DecisionDeny,
			Protocol:   eventstore.ProtocolHTTP,
			Domain:     "api.blocked.test",
			DstIP:      netip.MustParseAddr("192.0.2.1"),
			Port:       443,
			HTTPMethod: "POST",
			HTTPPath:   "/upload?token=1",
			HTTPStatus: 403,
			Flags:      "UAEX",
			Reason:     eventstore.ReasonNotAllowlisted,
			BytesRx:    120,
			BytesTx:    34,
			DurationMS: 7,
		},
		eventstore.Event{
			Time:     s.now.Add(-3 * time.Minute),
			Source:   eventstore.SourceEnvoy,
			Decision: eventstore.DecisionDeny,
			Protocol: eventstore.ProtocolTCP,
			Domain:   "blocked.test",
			Port:     8443,
		},
		eventstore.Event{
			Time:         s.now.Add(-2 * time.Minute),
			Source:       eventstore.SourceFirewall,
			Decision:     eventstore.DecisionAllow,
			Protocol:     eventstore.ProtocolTCP,
			Domain:       "example.com.",
			DstIP:        netip.MustParseAddr("192.0.2.7"),
			Port:         443,
			RuleIndex:    0,
			HasRuleIndex: true,
		},
		eventstore.Event{
			Time:     s.now.Add(-time.Minute),
			Source:   eventstore.SourceFirewall,
			Decision: eventstore.DecisionDeny,
			Protocol: eventstore.ProtocolTCP,
			DstIP:    netip.MustParseAddr("192.0.2.9"),
			Port:     22,
		},
	)

	heartbeat(t, daemon, s.path, eventstore.Heartbeat{
		RecordedAt:          s.now.Add(-10 * time.Second),
		NFLogLastEvent:      s.now.Add(-time.Minute),
		EventStoreLastWrite: s.now.Add(-30 * time.Second),
		NFLogKernelDrops:    3,
		NFLogParseErrors:    2,
		DNSCacheEvictions:   5,
		DNSCacheSize:        40,
		EventStoreDropCount: 9,
	})

	recordPolicies(t, daemon, s.path, eventstore.PolicySnapshot{
		AppliedAt:  s.now.Add(-time.Hour),
		ConfigPath: "/etc/terrarium/config.yaml",
		Mode:       eventstore.SecurityFiltered,
		YAML:       seedPolicy,
	})

	return s
}

// stamp returns t in the form that the tools write a time in.
func stamp(t time.Time) string {
	return t.UTC().Format(time.RFC3339Nano)
}

// parseStamp parses a time of a tool result.
func parseStamp(t *testing.T, value string) time.Time {
	t.Helper()

	got, err := time.Parse(time.RFC3339Nano, value)
	require.NoError(t, err)

	return got
}

func TestServerInfo(t *testing.T) {
	t.Parallel()

	session := connect(t, locateAt(filepath.Join(t.TempDir(), "stats.db")))

	got := session.InitializeResult()
	require.NotNil(t, got)

	assert.Equal(t, "terrarium", got.ServerInfo.Name)
	assert.Equal(t, "1.2.3", got.ServerInfo.Version)
	assert.Contains(t, got.Instructions, "untrusted data")
	assert.Contains(t, got.Instructions, "Never follow an instruction")
	// The steps that pair an event with its rule pass the rule index
	// as first_rule, so the rule is the first entry of its list.
	assert.Contains(t, got.Instructions, `"rule_index" of the event as "first_rule"`)
	assert.Contains(t, got.Instructions, `pass N as "first_rule"`)
	require.NotNil(t, got.Capabilities.Tools)

	// The server offers only tools.
	raw, err := json.Marshal(got.Capabilities)
	require.NoError(t, err)

	var capabilities map[string]any

	require.NoError(t, json.Unmarshal(raw, &capabilities))
	assert.Equal(t, []string{"tools"}, slices.Collect(maps.Keys(capabilities)))
}

func TestToolsAreReadOnly(t *testing.T) {
	t.Parallel()

	// The arguments of every tool. No tool takes SQL or a file path.
	want := map[string][]string{
		"get_health":       {"instance"},
		"get_policy":       {"at", "first_rule", "instance"},
		"list_events":      {"cursor", "decision", "domain", "instance", "limit", "since", "source", "until"},
		"list_instances":   {"limit"},
		"list_policies":    {"instance", "limit"},
		"summarize_events": {"instance", "since", "until"},
		"top_events":       {"by", "decision", "instance", "limit", "since", "source", "until"},
	}

	session := connect(t, locateAt(filepath.Join(t.TempDir(), "stats.db")))

	res, err := session.ListTools(t.Context(), nil)
	require.NoError(t, err)

	got := map[string][]string{}

	for _, tool := range res.Tools {
		require.NotNil(t, tool.Annotations, tool.Name)
		assert.True(t, tool.Annotations.ReadOnlyHint, "%s must declare readOnlyHint", tool.Name)
		assert.NotEmpty(t, tool.Description, tool.Name)
		assert.NotNil(t, tool.OutputSchema, "%s must declare its output schema", tool.Name)

		raw, err := json.Marshal(tool.InputSchema)
		require.NoError(t, err)

		var schema struct {
			AdditionalProperties any                        `json:"additionalProperties"`
			Properties           map[string]json.RawMessage `json:"properties"`
			Required             []string                   `json:"required"`
		}

		require.NoError(t, json.Unmarshal(raw, &schema))

		assert.Empty(t, schema.Required, "%s must take only optional arguments", tool.Name)
		assert.Equal(t, false, schema.AdditionalProperties, "%s must reject unknown arguments", tool.Name)

		args := make([]string, 0, len(schema.Properties))
		for name, property := range schema.Properties {
			args = append(args, name)

			assert.Contains(t, string(property), `"description"`, "%s argument %s", tool.Name, name)
		}

		slices.Sort(args)

		got[tool.Name] = args
	}

	assert.Equal(t, want, got)
}

func TestToolsReadSeededStore(t *testing.T) {
	t.Parallel()

	s := seed(t)
	session := connect(t, locateAt(s.path))

	t.Run("list_instances", func(t *testing.T) {
		t.Parallel()

		got := call[mcpserver.InstancesResult](t, session, "list_instances", nil)

		assert.Equal(t, s.daemon, got.Default)
		assert.Equal(t, 2, got.Total)
		require.Len(t, got.Instances, 2)

		daemon := got.Instances[0]
		assert.Equal(t, s.daemon, daemon.ID)
		assert.Equal(t, "daemon", daemon.Mode)
		assert.True(t, daemon.InProgress)
		assert.Empty(t, daemon.EndedAt)
		assert.WithinDuration(t, s.now, parseStamp(t, daemon.StartedAt), time.Minute)

		proxy := got.Instances[1]
		assert.Equal(t, s.proxy, proxy.ID)
		assert.Equal(t, "proxy", proxy.Mode)
		assert.Equal(t, "127.0.0.1-8080", proxy.Name)
		assert.Equal(t, "/etc/terrarium/proxy.yaml", proxy.ConfigPath)
		assert.False(t, proxy.InProgress)
		assert.False(t, parseStamp(t, proxy.EndedAt).Before(parseStamp(t, proxy.StartedAt)))
	})

	t.Run("list_instances with a limit", func(t *testing.T) {
		t.Parallel()

		got := call[mcpserver.InstancesResult](t, session, "list_instances", map[string]any{"limit": 1})

		assert.Equal(t, 2, got.Total)
		require.Len(t, got.Instances, 1)
		assert.Equal(t, s.daemon, got.Instances[0].ID)
	})

	t.Run("summarize_events", func(t *testing.T) {
		t.Parallel()

		got := call[mcpserver.SummaryResult](t, session, "summarize_events", nil)

		assert.Equal(t, s.daemon, got.Instance)
		assert.Equal(t, []mcpserver.SummaryCount{
			{Source: "dns", Decision: "allow", Count: 1},
			{Source: "dns", Decision: "deny", Count: 1},
			{Source: "envoy", Decision: "deny", Count: 2},
			{Source: "firewall", Decision: "allow", Count: 1},
			{Source: "firewall", Decision: "deny", Count: 1},
		}, got.Counts)
		assert.EqualValues(t, 6, got.Total)

		// The default window is the last 24 hours.
		since, until := parseStamp(t, got.Since), parseStamp(t, got.Until)
		assert.WithinDuration(t, time.Now(), until, time.Minute)
		assert.Equal(t, 24*time.Hour, until.Sub(since))
	})

	t.Run("summarize_events of an earlier instance", func(t *testing.T) {
		t.Parallel()

		got := call[mcpserver.SummaryResult](t, session, "summarize_events",
			map[string]any{"instance": s.proxy})

		assert.Equal(t, s.proxy, got.Instance)
		assert.Equal(t, []mcpserver.SummaryCount{{Source: "envoy", Decision: "allow", Count: 1}}, got.Counts)
		assert.EqualValues(t, 1, got.Total)
	})

	t.Run("top_events", func(t *testing.T) {
		t.Parallel()

		got := call[mcpserver.TopResult](t, session, "top_events", nil)

		assert.Equal(t, s.daemon, got.Instance)
		assert.Equal(t, "domain", got.By)
		assert.Equal(t, "deny", got.Decision)
		assert.Equal(t, []mcpserver.TopBucket{
			{Bucket: "blocked.test", Count: 2},
			{Bucket: "api.blocked.test", Count: 1},
		}, got.Buckets)
	})

	t.Run("top_events by sni", func(t *testing.T) {
		t.Parallel()

		got := call[mcpserver.TopResult](t, session, "top_events",
			map[string]any{"by": "sni", "decision": "allow"})

		assert.Equal(t, "sni", got.By)
		assert.Equal(t, "allow", got.Decision)
		assert.Equal(t, []mcpserver.TopBucket{{Bucket: "example.com.", Count: 1}}, got.Buckets)
	})

	t.Run("top_events by path", func(t *testing.T) {
		t.Parallel()

		got := call[mcpserver.TopResult](t, session, "top_events",
			map[string]any{"by": "path", "source": "envoy", "limit": 5})

		assert.Equal(t, "path", got.By)
		assert.Equal(t, []mcpserver.TopBucket{{Bucket: "/upload", Count: 1}}, got.Buckets)
	})

	t.Run("list_events", func(t *testing.T) {
		t.Parallel()

		got := call[mcpserver.EventsResult](t, session, "list_events", nil)

		assert.Equal(t, s.daemon, got.Instance)
		assert.Empty(t, got.NextCursor)
		require.Len(t, got.Events, 6)

		// The latest event is first.
		ruleIndex := 0

		assert.Equal(t, mcpserver.EventInfo{
			ID:       got.Events[0].ID,
			Time:     stamp(s.now.Add(-time.Minute)),
			Source:   "firewall",
			Decision: "deny",
			Protocol: "tcp",
			DstIP:    "192.0.2.9",
			Port:     22,
		}, got.Events[0])

		assert.Equal(t, mcpserver.EventInfo{
			ID:        got.Events[1].ID,
			Time:      stamp(s.now.Add(-2 * time.Minute)),
			Source:    "firewall",
			Decision:  "allow",
			Protocol:  "tcp",
			Domain:    "example.com.",
			DstIP:     "192.0.2.7",
			Port:      443,
			RuleIndex: &ruleIndex,
		}, got.Events[1])

		assert.Equal(t, mcpserver.EventInfo{
			ID:         got.Events[3].ID,
			Time:       stamp(s.now.Add(-4 * time.Minute)),
			Source:     "envoy",
			Decision:   "deny",
			Reason:     "not-allowlisted",
			Protocol:   "http",
			Domain:     "api.blocked.test",
			DstIP:      "192.0.2.1",
			Port:       443,
			HTTPMethod: "POST",
			HTTPPath:   "/upload?token=1",
			HTTPStatus: 403,
			Flags:      "UAEX",
			BytesRx:    120,
			BytesTx:    34,
			DurationMS: 7,
		}, got.Events[3])

		assert.Greater(t, got.Events[0].ID, got.Events[1].ID)
	})

	t.Run("list_events with filters", func(t *testing.T) {
		t.Parallel()

		got := call[mcpserver.EventsResult](t, session, "list_events", map[string]any{
			"source":   "envoy",
			"decision": "deny",
			"domain":   "BLOCKED.test",
		})

		require.Len(t, got.Events, 2)
		assert.Equal(t, "blocked.test", got.Events[0].Domain)
		assert.Equal(t, "api.blocked.test", got.Events[1].Domain)
	})

	t.Run("get_health", func(t *testing.T) {
		t.Parallel()

		got := call[mcpserver.HealthResult](t, session, "get_health", nil)

		info, err := os.Stat(s.path)
		require.NoError(t, err)

		assert.Equal(t, s.daemon, got.Instance)
		assert.Equal(t, s.path, got.DatabasePath)
		assert.Equal(t, info.Size(), got.DatabaseSizeBytes)
		assert.Equal(t, stamp(s.now.Add(-time.Minute)), got.LastEventAt)
		assert.EqualValues(t, 7, got.Events24h)
		assert.EqualValues(t, 2, got.FirewallEvents1h)
		assert.EqualValues(t, 1, got.FirewallNullDomain1h)

		require.NotNil(t, got.Heartbeat)

		age := got.Heartbeat.AgeSeconds
		assert.GreaterOrEqual(t, age, int64(10))
		assert.Less(t, age, int64(60))

		assert.Equal(t, &mcpserver.HeartbeatInfo{
			RecordedAt:        stamp(s.now.Add(-10 * time.Second)),
			StoreLastWriteAt:  stamp(s.now.Add(-30 * time.Second)),
			NFLogLastEventAt:  stamp(s.now.Add(-time.Minute)),
			AgeSeconds:        age,
			StoreDrops:        9,
			NFLogKernelDrops:  3,
			NFLogParseErrors:  2,
			DNSCacheSize:      40,
			DNSCacheEvictions: 5,
		}, got.Heartbeat)
	})

	t.Run("get_health of an instance without a heartbeat", func(t *testing.T) {
		t.Parallel()

		got := call[mcpserver.HealthResult](t, session, "get_health", map[string]any{"instance": s.proxy})

		assert.Equal(t, s.proxy, got.Instance)
		assert.Nil(t, got.Heartbeat)
		assert.EqualValues(t, 7, got.Events24h)
	})
}

func TestStaleHeartbeat(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	store := openStore(t, path)

	heartbeat(t, store, path, eventstore.Heartbeat{
		RecordedAt: time.Now().Add(-3 * eventstore.HeartbeatInterval),
	})

	session := connect(t, locateAt(path))
	got := call[mcpserver.HealthResult](t, session, "get_health", nil)

	require.NotNil(t, got.Heartbeat)
	assert.True(t, got.Heartbeat.Stale)
	assert.GreaterOrEqual(t, got.Heartbeat.AgeSeconds, int64(180))
	assert.Empty(t, got.Heartbeat.StoreLastWriteAt)
	assert.Empty(t, got.Heartbeat.NFLogLastEventAt)
	assert.Empty(t, got.LastEventAt)
}

func TestWindows(t *testing.T) {
	t.Parallel()

	s := seed(t)
	session := connect(t, locateAt(s.path))

	tcs := map[string]struct {
		args map[string]any
		err  string
		want int64
	}{
		"default window is 24 hours": {
			want: 6,
		},
		"duration since": {
			args: map[string]any{"since": "72h"},
			want: 7,
		},
		"short duration since": {
			args: map[string]any{"since": "150s"},
			want: 2,
		},
		"timestamp since": {
			args: map[string]any{"since": stamp(s.now.Add(-5 * time.Minute))},
			want: 5,
		},
		"timestamp until": {
			args: map[string]any{"until": stamp(s.now.Add(-5 * time.Minute))},
			want: 2,
		},
		"since and until": {
			args: map[string]any{
				"since": stamp(s.now.Add(-49 * time.Hour)),
				"until": stamp(s.now.Add(-47 * time.Hour)),
			},
			want: 1,
		},
		"invalid since": {
			args: map[string]any{"since": "yesterday"},
			err:  `since: "yesterday" is not a duration or an RFC 3339 time`,
		},
		"duration until": {
			args: map[string]any{"until": "1h"},
			err:  `until: "1h" is not an RFC 3339 time`,
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, tool := range []string{"summarize_events", "list_events"} {
				if tc.err != "" {
					assert.Contains(t, callError(t, session, tool, tc.args), tc.err, tool)

					continue
				}

				var got int64

				switch tool {
				case "summarize_events":
					got = call[mcpserver.SummaryResult](t, session, tool, tc.args).Total
				default:
					got = int64(len(call[mcpserver.EventsResult](t, session, tool, tc.args).Events))
				}

				assert.Equal(t, tc.want, got, tool)
			}
		})
	}
}

func TestInvalidArguments(t *testing.T) {
	t.Parallel()

	s := seed(t)
	session := connect(t, locateAt(s.path))

	tcs := map[string]struct {
		args map[string]any
		tool string
		err  string
	}{
		"unknown grouping": {
			tool: "top_events",
			args: map[string]any{"by": "port"},
			err:  "/properties/by: enum",
		},
		"top of errors": {
			tool: "top_events",
			args: map[string]any{"decision": "error"},
			err:  "/properties/decision: enum",
		},
		"unknown source": {
			tool: "list_events",
			args: map[string]any{"source": "kernel"},
			err:  "/properties/source: enum",
		},
		"unknown decision": {
			tool: "list_events",
			args: map[string]any{"decision": "drop"},
			err:  "/properties/decision: enum",
		},
		"limit of zero": {
			tool: "list_events",
			args: map[string]any{"limit": 0},
			err:  "/properties/limit: minimum",
		},
		"invalid cursor": {
			tool: "list_events",
			args: map[string]any{"cursor": "not a cursor"},
			err:  "invalid cursor",
		},
		"SQL argument": {
			tool: "list_events",
			args: map[string]any{"sql": "DELETE FROM events"},
			err:  `unexpected additional properties ["sql"]`,
		},
		"path argument": {
			tool: "get_health",
			args: map[string]any{"path": "/etc/passwd"},
			err:  `unexpected additional properties ["path"]`,
		},
		"policy path argument": {
			tool: "get_policy",
			args: map[string]any{"config_path": "/etc/passwd"},
			err:  `unexpected additional properties ["config_path"]`,
		},
		"policy time that is a duration": {
			tool: "get_policy",
			args: map[string]any{"at": "1h"},
			err:  `at: "1h" is not an RFC 3339 time`,
		},
		"negative first rule": {
			tool: "get_policy",
			args: map[string]any{"first_rule": -1},
			err:  "/properties/first_rule: minimum",
		},
		"policy limit of zero": {
			tool: "list_policies",
			args: map[string]any{"limit": 0},
			err:  "/properties/limit: minimum",
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Contains(t, callError(t, session, tc.tool, tc.args), tc.err)

			// The session continues after a tool error.
			got := call[mcpserver.SummaryResult](t, session, "summarize_events", nil)
			assert.EqualValues(t, 6, got.Total)
		})
	}
}

func TestUnknownInstance(t *testing.T) {
	t.Parallel()

	s := seed(t)
	session := connect(t, locateAt(s.path))

	got := call[mcpserver.EventsResult](t, session, "list_events", map[string]any{"instance": "no-such-run"})

	assert.Equal(t, "no-such-run", got.Instance)
	assert.NotNil(t, got.Events)
	assert.Empty(t, got.Events)
}

// TestDefaultInstance checks the instance that each tool reads when a
// call omits `instance`.
func TestDefaultInstance(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		// modes lists the modes of the runs, with the earliest start
		// first. Every run is in progress.
		modes []eventstore.Mode
		// want is the index in modes of the run that the tools read.
		want int
	}{
		"proxy after daemon": {
			modes: []eventstore.Mode{eventstore.ModeDaemon, eventstore.ModeProxy},
			want:  0,
		},
		"proxy after init": {
			modes: []eventstore.Mode{eventstore.ModeInit, eventstore.ModeProxy},
			want:  0,
		},
		"daemon after proxy": {
			modes: []eventstore.Mode{eventstore.ModeProxy, eventstore.ModeDaemon},
			want:  1,
		},
		"latest daemon between proxies": {
			modes: []eventstore.Mode{
				eventstore.ModeDaemon, eventstore.ModeProxy,
				eventstore.ModeDaemon, eventstore.ModeProxy,
			},
			want: 2,
		},
		// The store holds no init or daemon run.
		"latest proxy": {
			modes: []eventstore.Mode{eventstore.ModeProxy, eventstore.ModeProxy},
			want:  1,
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "stats.db")
			ids := make([]string, 0, len(tc.modes))

			for _, mode := range tc.modes {
				ids = append(ids, openStore(t, path, eventstore.WithMode(mode)).InstanceID())
			}

			session := connect(t, locateAt(path))
			want := ids[tc.want]

			instances := call[mcpserver.InstancesResult](t, session, "list_instances", nil)
			assert.Equal(t, want, instances.Default)
			assert.Len(t, instances.Instances, len(tc.modes))

			summary := call[mcpserver.SummaryResult](t, session, "summarize_events", nil)
			assert.Equal(t, want, summary.Instance)

			top := call[mcpserver.TopResult](t, session, "top_events", nil)
			assert.Equal(t, want, top.Instance)

			events := call[mcpserver.EventsResult](t, session, "list_events", nil)
			assert.Equal(t, want, events.Instance)

			health := call[mcpserver.HealthResult](t, session, "get_health", nil)
			assert.Equal(t, want, health.Instance)

			policy := call[mcpserver.PolicyResult](t, session, "get_policy", nil)
			assert.Equal(t, want, policy.Instance)

			policies := call[mcpserver.PoliciesResult](t, session, "list_policies", nil)
			assert.Equal(t, want, policies.Instance)
		})
	}
}

func TestEmptyStore(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	store := openStore(t, path)
	session := connect(t, locateAt(path))

	instances := call[mcpserver.InstancesResult](t, session, "list_instances", nil)
	require.Len(t, instances.Instances, 1)
	assert.Equal(t, store.InstanceID(), instances.Default)

	summary := call[mcpserver.SummaryResult](t, session, "summarize_events", nil)
	assert.Equal(t, store.InstanceID(), summary.Instance)
	assert.Empty(t, summary.Counts)
	assert.Zero(t, summary.Total)

	top := call[mcpserver.TopResult](t, session, "top_events", nil)
	assert.Empty(t, top.Buckets)

	events := call[mcpserver.EventsResult](t, session, "list_events", nil)
	assert.Empty(t, events.Events)
	assert.Empty(t, events.NextCursor)

	health := call[mcpserver.HealthResult](t, session, "get_health", nil)
	assert.Nil(t, health.Heartbeat)
	assert.Empty(t, health.LastEventAt)
	assert.Positive(t, health.DatabaseSizeBytes)

	policy := call[mcpserver.PolicyResult](t, session, "get_policy", nil)
	assert.Equal(t, store.InstanceID(), policy.Instance)
	assert.Nil(t, policy.Policy)
	assert.Contains(t, policy.Message, "holds no policy snapshot")

	policies := call[mcpserver.PoliciesResult](t, session, "list_policies", nil)
	assert.Equal(t, store.InstanceID(), policies.Instance)
	assert.NotNil(t, policies.Policies)
	assert.Empty(t, policies.Policies)
	assert.Zero(t, policies.Total)
	assert.Contains(t, policies.Message, "holds no policy snapshot")
}

func TestListEventsPages(t *testing.T) {
	t.Parallel()

	const extra = 30

	path := filepath.Join(t.TempDir(), "stats.db")
	store := openStore(t, path, eventstore.WithBatchSize(64))
	now := time.Now()

	events := make([]eventstore.Event, 0, mcpserver.MaxLimit+extra)
	for i := range cap(events) {
		events = append(events, eventstore.Event{
			Time:     now.Add(-time.Duration(cap(events)-i) * time.Second),
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionDeny,
			Protocol: eventstore.ProtocolDNS,
			Domain:   fmt.Sprintf("host-%03d.test", i),
		})
	}

	emit(t, store, path, int64(len(events)), events...)

	session := connect(t, locateAt(path))

	t.Run("default limit", func(t *testing.T) {
		t.Parallel()

		got := call[mcpserver.EventsResult](t, session, "list_events", nil)

		assert.Len(t, got.Events, mcpserver.DefaultLimit)
		assert.NotEmpty(t, got.NextCursor)
	})

	t.Run("limit past the maximum", func(t *testing.T) {
		t.Parallel()

		first := call[mcpserver.EventsResult](t, session, "list_events", map[string]any{"limit": 100_000})

		require.Len(t, first.Events, mcpserver.MaxLimit)
		require.NotEmpty(t, first.NextCursor)

		// The cursor returns the page that follows, with the
		// window of the first page.
		second := call[mcpserver.EventsResult](t, session, "list_events", map[string]any{
			"limit":    100_000,
			"cursor":   first.NextCursor,
			"instance": first.Instance,
			"since":    first.Since,
			"until":    first.Until,
		})

		require.Len(t, second.Events, extra)
		assert.Empty(t, second.NextCursor)
		assert.Equal(t, first.Since, second.Since)
		assert.Equal(t, first.Until, second.Until)

		// The two pages hold every event one time, latest first.
		domains := make([]string, 0, len(events))
		for _, e := range slices.Concat(first.Events, second.Events) {
			domains = append(domains, e.Domain)
		}

		want := make([]string, 0, len(events))
		for _, v := range slices.Backward(events) {
			want = append(want, v.Domain)
		}

		assert.Equal(t, want, domains)
	})

	t.Run("top limit past the maximum", func(t *testing.T) {
		t.Parallel()

		got := call[mcpserver.TopResult](t, session, "top_events", map[string]any{"limit": 100_000})

		assert.Len(t, got.Buckets, mcpserver.MaxLimit)
	})

	t.Run("top default limit", func(t *testing.T) {
		t.Parallel()

		got := call[mcpserver.TopResult](t, session, "top_events", nil)

		assert.Len(t, got.Buckets, mcpserver.DefaultLimit)
	})
}

func TestLongValuesAreTruncated(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", 4*mcpserver.MaxFieldBytes)

	// Each rune after the two bytes of the prefix takes three bytes,
	// so byte 256 of the path is inside a rune.
	wide := "/p" + strings.Repeat("€", mcpserver.MaxFieldBytes)
	require.False(t, utf8.RuneStart(wide[mcpserver.MaxFieldBytes]))

	exact := strings.Repeat("m", mcpserver.MaxFieldBytes)

	path := filepath.Join(t.TempDir(), "stats.db")
	store := openStore(t, path)

	emit(t, store, path, 1, eventstore.Event{
		Time:       time.Now().Add(-time.Minute),
		Source:     eventstore.SourceEnvoy,
		Decision:   eventstore.DecisionDeny,
		Protocol:   eventstore.ProtocolHTTP,
		Domain:     long,
		HTTPMethod: exact,
		HTTPPath:   wide,
		Flags:      long,
	})

	session := connect(t, locateAt(path))

	events := call[mcpserver.EventsResult](t, session, "list_events", nil)
	require.Len(t, events.Events, 1)

	got := events.Events[0]

	assert.Equal(t, long[:mcpserver.MaxFieldBytes]+mcpserver.TruncationMarker, got.Domain)
	assert.Equal(t, long[:mcpserver.MaxFieldBytes]+mcpserver.TruncationMarker, got.Flags)

	// A value of exactly the maximum length is whole.
	assert.Equal(t, exact, got.HTTPMethod)

	assert.True(t, utf8.ValidString(got.HTTPPath))
	assert.True(t, strings.HasSuffix(got.HTTPPath, "€"+mcpserver.TruncationMarker), got.HTTPPath)
	assert.LessOrEqual(t, len(got.HTTPPath), mcpserver.MaxFieldBytes+len(mcpserver.TruncationMarker))
	assert.Greater(t, len(got.HTTPPath), mcpserver.MaxFieldBytes-utf8.UTFMax)

	for _, by := range []string{"domain", "path"} {
		top := call[mcpserver.TopResult](t, session, "top_events", map[string]any{"by": by})
		require.Len(t, top.Buckets, 1, by)

		bucket := top.Buckets[0].Bucket
		assert.True(t, strings.HasSuffix(bucket, mcpserver.TruncationMarker), by)
		assert.LessOrEqual(t, len(bucket), mcpserver.MaxFieldBytes+len(mcpserver.TruncationMarker), by)
		assert.True(t, utf8.ValidString(bucket), by)
	}
}

func TestTruncationKeepsTextBeforeInvalidBytes(t *testing.T) {
	t.Parallel()

	// Bytes 0x80 to 0xBF continue a rune and never start one. The
	// workload can send a run of them that covers byte 256.
	prefix := "/visible/path/"
	value := prefix + strings.Repeat("\x80", 2*mcpserver.MaxFieldBytes)

	// JSON encodes each byte that is not UTF-8 as U+FFFD.
	want := prefix + strings.Repeat("\uFFFD", mcpserver.MaxFieldBytes-len(prefix)) +
		mcpserver.TruncationMarker

	path := filepath.Join(t.TempDir(), "stats.db")
	store := openStore(t, path)

	emit(t, store, path, 1, eventstore.Event{
		Time:     time.Now().Add(-time.Minute),
		Source:   eventstore.SourceEnvoy,
		Decision: eventstore.DecisionDeny,
		Protocol: eventstore.ProtocolHTTP,
		Domain:   "a.test",
		HTTPPath: value,
	})

	session := connect(t, locateAt(path))

	events := call[mcpserver.EventsResult](t, session, "list_events", nil)
	require.Len(t, events.Events, 1)
	assert.Equal(t, want, events.Events[0].HTTPPath)

	top := call[mcpserver.TopResult](t, session, "top_events", map[string]any{"by": "path"})
	require.Len(t, top.Buckets, 1)
	assert.Equal(t, want, top.Buckets[0].Bucket)
}

// callEveryTool calls every tool, with and without arguments, and one
// tool with an argument that the tool rejects.
func callEveryTool(t *testing.T, session *mcp.ClientSession, instance string) {
	t.Helper()

	call[mcpserver.InstancesResult](t, session, "list_instances", nil)
	call[mcpserver.SummaryResult](t, session, "summarize_events", map[string]any{"since": "72h"})
	call[mcpserver.TopResult](t, session, "top_events", nil)
	call[mcpserver.TopResult](t, session, "top_events", map[string]any{"by": "path", "decision": "allow"})
	call[mcpserver.EventsResult](t, session, "list_events", nil)
	call[mcpserver.HealthResult](t, session, "get_health", nil)
	call[mcpserver.HealthResult](t, session, "get_health", map[string]any{"instance": instance})
	call[mcpserver.PoliciesResult](t, session, "list_policies", nil)
	call[mcpserver.PoliciesResult](t, session, "list_policies", map[string]any{"instance": instance, "limit": 1})
	call[mcpserver.PolicyResult](t, session, "get_policy", nil)
	call[mcpserver.PolicyResult](t, session, "get_policy", map[string]any{
		"instance":   instance,
		"at":         stamp(time.Now()),
		"first_rule": 1,
	})

	page := call[mcpserver.EventsResult](t, session, "list_events", map[string]any{"limit": 2})
	require.NotEmpty(t, page.NextCursor)
	call[mcpserver.EventsResult](t, session, "list_events", map[string]any{"limit": 2, "cursor": page.NextCursor})

	callError(t, session, "list_events", map[string]any{"since": "yesterday"})
	callError(t, session, "get_policy", map[string]any{"at": "yesterday"})
}

func TestToolsDoNotChangeDatabase(t *testing.T) {
	t.Parallel()

	t.Run("while an instance writes", func(t *testing.T) {
		t.Parallel()

		// The daemon of the seeded database is running, so the
		// database has a write-ahead log.
		s := seed(t)

		db, err := os.ReadFile(s.path)
		require.NoError(t, err)

		wal, err := os.ReadFile(s.path + "-wal")
		require.NoError(t, err)
		require.NotEmpty(t, wal)

		callEveryTool(t, connect(t, locateAt(s.path)), s.proxy)

		dbAfter, err := os.ReadFile(s.path)
		require.NoError(t, err)

		walAfter, err := os.ReadFile(s.path + "-wal")
		require.NoError(t, err)

		assert.True(t, slices.Equal(db, dbAfter), "the tools changed the database file")
		assert.True(t, slices.Equal(wal, walAfter), "the tools changed the write-ahead log")
	})

	t.Run("after an instance stopped without a clean close", func(t *testing.T) {
		t.Parallel()

		// A copy of a database whose writer is open holds the
		// write-ahead log that a killed writer leaves behind. No
		// other connection opens the copy, so the connection of
		// each tool call is the last one to close it. A connection
		// that can write checkpoints the log into the database
		// file at that close and removes the log.
		s := seed(t)

		path := filepath.Join(t.TempDir(), "stats.db")
		for _, suffix := range []string{"", "-wal", "-shm"} {
			data, err := os.ReadFile(s.path + suffix)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(path+suffix, data, 0o600))
		}

		db, err := os.ReadFile(path)
		require.NoError(t, err)

		wal, err := os.ReadFile(path + "-wal")
		require.NoError(t, err)
		require.NotEmpty(t, wal)

		callEveryTool(t, connect(t, locateAt(path)), s.proxy)

		dbAfter, err := os.ReadFile(path)
		require.NoError(t, err)

		walAfter, err := os.ReadFile(path + "-wal")
		require.NoError(t, err, "the tools removed the write-ahead log")

		assert.True(t, slices.Equal(db, dbAfter), "the tools changed the database file")
		assert.True(t, slices.Equal(wal, walAfter), "the tools changed the write-ahead log")
	})

	t.Run("after every instance ended", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "stats.db")
		store := openStore(t, path)

		emit(t, store, path, 3,
			eventstore.Event{Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Domain: "a.test"},
			eventstore.Event{Source: eventstore.SourceDNS, Decision: eventstore.DecisionDeny, Domain: "b.test"},
			eventstore.Event{Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow, Domain: "c.test"},
		)

		require.NoError(t, store.Close())

		// SQLite removes the write-ahead log when the last
		// connection of a database closes.
		require.NoFileExists(t, path+"-wal")

		db, err := os.ReadFile(path)
		require.NoError(t, err)

		callEveryTool(t, connect(t, locateAt(path)), store.InstanceID())

		dbAfter, err := os.ReadFile(path)
		require.NoError(t, err)

		assert.True(t, slices.Equal(db, dbAfter), "the tools changed the database file")

		// The reader of each call creates an empty write-ahead log
		// and removes it when it closes. No file of the reader then
		// stops the next writer.
		assert.NoFileExists(t, path+"-wal")
		assert.NoFileExists(t, path+"-shm")
	})
}

func TestMissingDatabase(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state", "stats.db")
	session := connect(t, locateAt(path))

	for _, tool := range toolNames {
		msg := callError(t, session, tool, nil)

		assert.Contains(t, msg, path, tool)
		assert.Contains(t, msg, "stats.enabled: true", tool)
	}

	// The same session reads the database after it appears.
	store := openStore(t, path)

	emit(t, store, path, 1, eventstore.Event{
		Time:     time.Now().Add(-time.Minute),
		Source:   eventstore.SourceDNS,
		Decision: eventstore.DecisionDeny,
		Domain:   "blocked.test",
	})

	got := call[mcpserver.SummaryResult](t, session, "summarize_events", nil)

	assert.Equal(t, store.InstanceID(), got.Instance)
	assert.EqualValues(t, 1, got.Total)

	for _, tool := range toolNames {
		res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: tool})
		require.NoError(t, err)
		assert.False(t, res.IsError, tool)
	}
}

func TestLocateError(t *testing.T) {
	t.Parallel()

	var enabled atomic.Bool

	path := filepath.Join(t.TempDir(), "stats.db")
	locate := func(context.Context) (string, error) {
		if !enabled.Load() {
			return "", fmt.Errorf("%w: the config disables stats", mcpserver.ErrNoDatabase)
		}

		return path, nil
	}

	session := connect(t, locate)

	msg := callError(t, session, "get_health", nil)
	assert.Contains(t, msg, mcpserver.ErrNoDatabase.Error())
	assert.Contains(t, msg, "the config disables stats")

	// The server asks for the path again at the next call.
	enabled.Store(true)

	msg = callError(t, session, "get_health", nil)
	assert.Contains(t, msg, path+" does not exist")
}

// closeSpy is a stream that records a call of its Close method.
type closeSpy struct {
	io.Reader
	io.Writer

	closed atomic.Bool
}

// Close implements [io.Closer].
func (c *closeSpy) Close() error {
	c.closed.Store(true)

	return nil
}

// TestRunIO serves a session on a pair of pipes, as `terrarium mcp`
// serves one on its standard input and output.
func TestRunIO(t *testing.T) {
	t.Parallel()

	path := seed(t).path

	t.Run("ends when the client closes its stream", func(t *testing.T) {
		t.Parallel()

		serverIn, clientOut := io.Pipe()
		clientIn, serverOut := io.Pipe()

		in := &closeSpy{Reader: serverIn}
		out := &closeSpy{Writer: serverOut}

		ctx := context.WithoutCancel(t.Context())
		done := make(chan error, 1)

		go func() {
			done <- mcpserver.New(locateAt(path)).RunIO(ctx, in, out)
		}()

		client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)

		session, err := client.Connect(ctx, &mcp.IOTransport{Reader: clientIn, Writer: clientOut}, nil)
		require.NoError(t, err)

		got := call[mcpserver.InstancesResult](t, session, "list_instances", nil)
		assert.Len(t, got.Instances, 2)

		require.NoError(t, session.Close())

		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			require.Fail(t, "the server still runs after the client closed its stream")
		}

		// The server leaves both of its streams open.
		assert.False(t, in.closed.Load())
		assert.False(t, out.closed.Load())
	})

	// The SDK client leaves out an Arguments field that is nil, so
	// this case writes the JSON-RPC messages itself.
	t.Run("serves calls whose arguments are null", func(t *testing.T) {
		t.Parallel()

		serverIn, clientOut := io.Pipe()
		clientIn, serverOut := io.Pipe()

		ctx := context.WithoutCancel(t.Context())
		done := make(chan error, 1)

		go func() {
			done <- mcpserver.New(locateAt(path)).RunIO(ctx, serverIn, serverOut)
		}()

		// Each response arrives on its own goroutine, so a server that
		// stops writing fails the test at the deadline instead of
		// blocking it.
		lines := make(chan []byte)

		go func() {
			defer close(lines)

			scanner := bufio.NewScanner(clientIn)
			scanner.Buffer(nil, 1<<20)

			for scanner.Scan() {
				lines <- slices.Clone(scanner.Bytes())
			}
		}()

		send := func(msg map[string]any) {
			t.Helper()

			raw, err := json.Marshal(msg)
			require.NoError(t, err)

			_, err = clientOut.Write(append(raw, '\n'))
			require.NoError(t, err)
		}

		type response struct {
			Result *mcp.CallToolResult `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
			ID int `json:"id"`
		}

		// await returns the response with the given ID and skips every
		// other message of the server.
		await := func(id int) response {
			t.Helper()

			deadline := time.After(10 * time.Second)

			for {
				select {
				case line, ok := <-lines:
					require.True(t, ok, "the server closed its output before the response %d", id)

					var resp response

					err := json.Unmarshal(line, &resp)
					if err == nil && resp.ID == id {
						return resp
					}

				case <-deadline:
					require.FailNow(t, "the server did not answer", "request %d", id)
				}
			}
		}

		send(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  "initialize",
			"params": map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{},
				"clientInfo":      map[string]any{"name": "test", "version": "0"},
			},
		})

		init := await(1)
		require.Nil(t, init.Error)

		send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})

		for i, tool := range toolNames {
			id := i + 2

			send(map[string]any{
				"jsonrpc": "2.0",
				"id":      id,
				"method":  "tools/call",
				"params":  map[string]any{"name": tool, "arguments": nil},
			})

			resp := await(id)
			require.Nil(t, resp.Error, "tool %s", tool)
			require.NotNil(t, resp.Result, "tool %s", tool)
			assert.False(t, resp.Result.IsError, "tool %s", tool)
			assert.NotNil(t, resp.Result.StructuredContent, "tool %s", tool)
		}

		require.NoError(t, clientOut.Close())

		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			require.Fail(t, "the server still runs after the client closed its stream")
		}
	})

	t.Run("ends with its context", func(t *testing.T) {
		t.Parallel()

		serverIn, clientOut := io.Pipe()

		t.Cleanup(func() {
			assert.NoError(t, clientOut.Close())
		})

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)

		go func() {
			done <- mcpserver.New(locateAt(path)).RunIO(ctx, serverIn, io.Discard)
		}()

		cancel()

		select {
		case err := <-done:
			require.ErrorIs(t, err, context.Canceled)
		case <-time.After(10 * time.Second):
			require.Fail(t, "the server still runs after its context ended")
		}
	})
}
