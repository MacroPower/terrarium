package mcpserver_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/eventstore"
	"go.jacobcolvin.com/terrarium/mcpserver"
)

// seedPolicy is a policy document with three egress rules and two
// egressDeny rules. The keys after the rule lists are parts of the
// document that are not rules.
const seedPolicy = `egress:
  - toFQDNs:
      - matchName: example.com
    toPorts:
      - ports:
          - port: "443"
            protocol: TCP
  - toCIDR:
      - 192.0.2.0/24
  - toFQDNs:
      - matchPattern: "*.example.org"
egressDeny:
  - toCIDR:
      - 192.0.2.9/32
  - toCIDR:
      - 198.51.100.0/24
logging:
  firewall:
    enabled: true
`

// The JSON form of each rule of [seedPolicy], in the order of the
// document.
var (
	seedPolicyEgress = []string{
		`{"toFQDNs":[{"matchName":"example.com"}],"toPorts":[{"ports":[{"port":"443","protocol":"TCP"}]}]}`,
		`{"toCIDR":["192.0.2.0/24"]}`,
		`{"toFQDNs":[{"matchPattern":"*.example.org"}]}`,
	}

	seedPolicyEgressDeny = []string{
		`{"toCIDR":["192.0.2.9/32"]}`,
		`{"toCIDR":["198.51.100.0/24"]}`,
	}
)

// policySecret is the header value of [secretPolicy]. No other text
// of a test holds it, so a result that holds it holds the header
// value.
const policySecret = "hunter2-mcp-policy-secret"

// secretPolicy is a policy that injects [policySecret] into the
// requests of its second egress rule.
const secretPolicy = `egress:
  - toFQDNs:
      - matchName: first.example
    toPorts:
      - ports:
          - port: "443"
  - toFQDNs:
      - matchName: test.example
    toPorts:
      - ports:
          - port: "80"
        rules:
          http:
            - path: /v1/.*
              headerMatches:
                - name: Authorization
                  mismatch: REPLACE
                  value: ` + policySecret + `
                - name: X-Present
`

// v2SchemaSQL is the schema of a database from before the policy
// snapshots, which is user_version=2.
const v2SchemaSQL = `
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

// policyCount returns the number of snapshots of the instance in the
// database at path.
func policyCount(t *testing.T, path, instance string) (int, error) {
	t.Helper()

	r, err := eventstore.OpenReader(t.Context(), path)
	if err != nil {
		return 0, fmt.Errorf("opening the reader: %w", err)
	}

	defer r.Close() //nolint:errcheck // read-only handle in polling closure.

	infos, err := r.Policies(t.Context(), instance)
	if err != nil {
		return 0, fmt.Errorf("listing the snapshots: %w", err)
	}

	return len(infos), nil
}

// recordPolicies records the snapshots for the store, in order, and
// waits until the database at path holds each one. The store drops a
// snapshot when its channel is full, so recordPolicies waits for each
// snapshot before it records the next one.
func recordPolicies(t *testing.T, store *eventstore.Store, path string, snapshots ...eventstore.PolicySnapshot) {
	t.Helper()

	before, err := policyCount(t, path, store.InstanceID())
	require.NoError(t, err)

	for i := range snapshots {
		store.RecordPolicy(snapshots[i])

		require.Eventually(t, func() bool {
			n, err := policyCount(t, path, store.InstanceID())

			return err == nil && n == before+i+1
		}, 5*time.Second, time.Millisecond)
	}
}

// digest returns the SHA-256 of doc in hexadecimal digits.
func digest(doc string) string {
	sum := sha256.Sum256([]byte(doc))

	return hex.EncodeToString(sum[:])
}

// indexes returns the index of each rule, in order.
func indexes(rules []mcpserver.PolicyRule) []int {
	out := []int{}

	for i := range rules {
		out = append(out, rules[i].Index)
	}

	return out
}

// assertRules asserts that rules holds one rule for each JSON
// document of want, in order. The index of the first rule is first.
func assertRules(t *testing.T, want []string, first int, rules []mcpserver.PolicyRule) {
	t.Helper()

	require.Len(t, rules, len(want))

	for i := range rules {
		assert.Equal(t, first+i, rules[i].Index)

		raw, err := json.Marshal(rules[i].Rule)
		require.NoError(t, err)

		assert.JSONEq(t, want[i], string(raw), "rule %d", first+i)
	}
}

func TestGetPolicy(t *testing.T) {
	t.Parallel()

	s := seed(t)
	session := connect(t, locateAt(s.path))

	got := call[mcpserver.PolicyResult](t, session, "get_policy", nil)

	assert.Equal(t, s.daemon, got.Instance)
	assert.Empty(t, got.Message)
	require.NotNil(t, got.Policy)

	policy := got.Policy

	assert.Positive(t, policy.ID)
	assert.Equal(t, stamp(s.now.Add(-time.Hour)), policy.AppliedAt)
	assert.Equal(t, "/etc/terrarium/config.yaml", policy.ConfigPath)
	assert.Equal(t, digest(seedPolicy), policy.SHA256)
	assert.Equal(t, "filtered", policy.SecurityMode)
	assert.Equal(t, seedPolicy, policy.YAML)
	assert.Equal(t, 3, policy.EgressTotal)
	assert.Equal(t, 2, policy.EgressDenyTotal)

	assertRules(t, seedPolicyEgress, 0, policy.Egress)
	assertRules(t, seedPolicyEgressDeny, 0, policy.EgressDeny)

	// The same snapshot by the ID of its instance.
	byID := call[mcpserver.PolicyResult](t, session, "get_policy", map[string]any{"instance": s.daemon})
	assert.Equal(t, got, byID)

	// The rule of the firewall event that names a rule index. The
	// time of the event selects the snapshot, and the rule index
	// selects the rule.
	events := call[mcpserver.EventsResult](t, session, "list_events", map[string]any{"source": "firewall"})

	var paired int

	for i := range events.Events {
		event := &events.Events[i]
		if event.RuleIndex == nil {
			continue
		}

		paired++

		at := call[mcpserver.PolicyResult](t, session, "get_policy", map[string]any{
			"at":         event.Time,
			"first_rule": *event.RuleIndex,
		})

		require.NotNil(t, at.Policy)
		require.NotEmpty(t, at.Policy.Egress)
		assert.Equal(t, policy.ID, at.Policy.ID)
		assert.Equal(t, *event.RuleIndex, at.Policy.Egress[0].Index)
	}

	assert.Equal(t, 1, paired)

	// The proxy instance recorded no snapshot.
	none := call[mcpserver.PolicyResult](t, session, "get_policy", map[string]any{"instance": s.proxy})
	assert.Equal(t, s.proxy, none.Instance)
	assert.Nil(t, none.Policy)
	assert.Contains(t, none.Message, "holds no policy snapshot")
}

func TestGetPolicyFirstRule(t *testing.T) {
	t.Parallel()

	s := seed(t)
	session := connect(t, locateAt(s.path))

	tcs := map[string]struct {
		first          int
		wantEgress     []string
		wantEgressDeny []string
	}{
		"second rule": {
			first:          1,
			wantEgress:     seedPolicyEgress[1:],
			wantEgressDeny: seedPolicyEgressDeny[1:],
		},
		"past the egressDeny list": {
			first:      2,
			wantEgress: seedPolicyEgress[2:],
		},
		"past both lists": {
			first: 3,
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := call[mcpserver.PolicyResult](t, session, "get_policy", map[string]any{"first_rule": tc.first})
			require.NotNil(t, got.Policy)

			// A list without a rule is the empty list, not null.
			assert.NotNil(t, got.Policy.Egress)
			assert.NotNil(t, got.Policy.EgressDeny)

			assertRules(t, tc.wantEgress, tc.first, got.Policy.Egress)
			assertRules(t, tc.wantEgressDeny, tc.first, got.Policy.EgressDeny)

			// The totals count the rules of the policy.
			assert.Equal(t, 3, got.Policy.EgressTotal)
			assert.Equal(t, 2, got.Policy.EgressDenyTotal)
			assert.Equal(t, seedPolicy, got.Policy.YAML)
		})
	}
}

// twoSnapshots describes the database that [seedTwoSnapshots] writes.
type twoSnapshots struct {
	// first and second are the times of the two snapshots.
	first, second time.Time

	// otherAt is the time of the snapshot of the other instance.
	otherAt time.Time

	// path is the path of the database.
	path string

	// instance is the ID of the instance of the two snapshots.
	instance string

	// other is the ID of the other instance.
	other string
}

// firstPolicy and secondPolicy are the documents of the two snapshots
// of [seedTwoSnapshots].
const (
	firstPolicy  = "egress:\n  - toCIDR:\n      - 192.0.2.0/24\n"
	secondPolicy = "egress:\n  - {}\n"
)

// seedTwoSnapshots writes a database with two instances. The earlier
// one recorded one snapshot. The latest one recorded a snapshot of
// [firstPolicy] two hours ago and a snapshot of [secondPolicy] one
// hour ago.
func seedTwoSnapshots(t *testing.T) twoSnapshots {
	t.Helper()

	now := time.Now().Truncate(time.Microsecond)
	s := twoSnapshots{
		first:   now.Add(-2 * time.Hour),
		second:  now.Add(-time.Hour),
		otherAt: now.Add(-90 * time.Minute),
		path:    filepath.Join(t.TempDir(), "stats.db"),
	}

	other := openStore(t, s.path)
	s.other = other.InstanceID()

	recordPolicies(t, other, s.path, eventstore.PolicySnapshot{
		AppliedAt: s.otherAt,
		Mode:      eventstore.SecurityUnrestricted,
		YAML:      "{}\n",
	})

	require.NoError(t, other.Close())

	// The instances order by their start time, so the latest one
	// must start at a later microsecond than the other one.
	time.Sleep(2 * time.Millisecond)

	store := openStore(t, s.path)
	s.instance = store.InstanceID()

	recordPolicies(t, store, s.path,
		eventstore.PolicySnapshot{
			AppliedAt:  s.first,
			ConfigPath: "/etc/terrarium/config.yaml",
			Mode:       eventstore.SecurityFiltered,
			YAML:       firstPolicy,
		},
		eventstore.PolicySnapshot{
			AppliedAt:  s.second,
			ConfigPath: "/etc/terrarium/config.yaml",
			Mode:       eventstore.SecurityBlocked,
			YAML:       secondPolicy,
		})

	return s
}

func TestGetPolicyAt(t *testing.T) {
	t.Parallel()

	s := seedTwoSnapshots(t)
	session := connect(t, locateAt(s.path))

	tcs := map[string]struct {
		args map[string]any
		want string
		mode string
		at   time.Time
	}{
		"no time": {
			want: secondPolicy,
			mode: "blocked",
			at:   s.second,
		},
		"between the snapshots": {
			args: map[string]any{"at": stamp(s.first.Add(30 * time.Minute))},
			want: firstPolicy,
			mode: "filtered",
			at:   s.first,
		},
		"time of the first snapshot": {
			args: map[string]any{"at": stamp(s.first)},
			want: firstPolicy,
			mode: "filtered",
			at:   s.first,
		},
		"right before the second snapshot": {
			args: map[string]any{"at": stamp(s.second.Add(-time.Microsecond))},
			want: firstPolicy,
			mode: "filtered",
			at:   s.first,
		},
		"time of the second snapshot": {
			args: map[string]any{"at": stamp(s.second)},
			want: secondPolicy,
			mode: "blocked",
			at:   s.second,
		},
		"after the second snapshot": {
			args: map[string]any{"at": stamp(s.second.Add(time.Minute)), "instance": s.instance},
			want: secondPolicy,
			mode: "blocked",
			at:   s.second,
		},
		"time with an offset": {
			args: map[string]any{
				"at": s.first.Add(30 * time.Minute).In(time.FixedZone("", 2*60*60)).Format(time.RFC3339Nano),
			},
			want: firstPolicy,
			mode: "filtered",
			at:   s.first,
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := call[mcpserver.PolicyResult](t, session, "get_policy", tc.args)

			assert.Equal(t, s.instance, got.Instance)
			assert.Empty(t, got.Message)
			require.NotNil(t, got.Policy)
			assert.Equal(t, tc.want, got.Policy.YAML)
			assert.Equal(t, digest(tc.want), got.Policy.SHA256)
			assert.Equal(t, tc.mode, got.Policy.SecurityMode)
			assert.Equal(t, stamp(tc.at), got.Policy.AppliedAt)
			assert.Equal(t, 1, got.Policy.EgressTotal)
			assert.Zero(t, got.Policy.EgressDenyTotal)
			assert.Empty(t, got.Policy.EgressDeny)
		})
	}
}

// TestGetPolicyBeforeFirstSnapshot calls the tool with a time before
// the earliest snapshot of the instance. The result must hold no
// policy, and its message must name the time of that snapshot. It
// must also tell the client to pass the instance of the event.
func TestGetPolicyBeforeFirstSnapshot(t *testing.T) {
	t.Parallel()

	s := seedTwoSnapshots(t)
	session := connect(t, locateAt(s.path))

	at := s.first.Add(-time.Microsecond)

	got := call[mcpserver.PolicyResult](t, session, "get_policy", map[string]any{"at": stamp(at)})

	assert.Equal(t, s.instance, got.Instance)
	assert.Nil(t, got.Policy)
	assert.Contains(t, got.Message, "no policy snapshot of this instance from "+stamp(at)+" or earlier")
	assert.Contains(t, got.Message, "The earliest snapshot is from "+stamp(s.first)+".")
	assert.Contains(t, got.Message, "pass the instance that recorded it as `instance`")

	// The zero time is a time before the earliest snapshot, not a call
	// without at. An offset that names the same instant reads the same.
	for _, zero := range []string{"0001-01-01T00:00:00Z", "0001-01-01T02:00:00+02:00"} {
		got := call[mcpserver.PolicyResult](t, session, "get_policy", map[string]any{"at": zero})

		assert.Nil(t, got.Policy, zero)
		assert.Contains(t, got.Message,
			"no policy snapshot of this instance from 0001-01-01T00:00:00Z or earlier", zero)
	}

	// The ID of the other instance selects a snapshot of that
	// instance, not of the latest one.
	other := call[mcpserver.PolicyResult](t, session, "get_policy", map[string]any{
		"instance": s.other,
		"at":       stamp(s.otherAt),
	})
	assert.Equal(t, s.other, other.Instance)
	require.NotNil(t, other.Policy)
	assert.Equal(t, "{}\n", other.Policy.YAML)

	// The time that the message names selects the earliest snapshot.
	earliest := call[mcpserver.PolicyResult](t, session, "get_policy", map[string]any{"at": stamp(s.first)})
	require.NotNil(t, earliest.Policy)
	assert.Equal(t, firstPolicy, earliest.Policy.YAML)
}

func TestListPolicies(t *testing.T) {
	t.Parallel()

	s := seedTwoSnapshots(t)
	session := connect(t, locateAt(s.path))

	got := call[mcpserver.PoliciesResult](t, session, "list_policies", nil)

	assert.Equal(t, s.instance, got.Instance)
	assert.Empty(t, got.Message)
	assert.Equal(t, 2, got.Total)
	require.Len(t, got.Policies, 2)

	second, first := got.Policies[0], got.Policies[1]

	assert.Equal(t, mcpserver.SnapshotInfo{
		AppliedAt:    stamp(s.second),
		ConfigPath:   "/etc/terrarium/config.yaml",
		SHA256:       digest(secondPolicy),
		SecurityMode: "blocked",
		ID:           second.ID,
		Changed:      true,
	}, second)
	assert.Equal(t, mcpserver.SnapshotInfo{
		AppliedAt:    stamp(s.first),
		ConfigPath:   "/etc/terrarium/config.yaml",
		SHA256:       digest(firstPolicy),
		SecurityMode: "filtered",
		ID:           first.ID,
		Changed:      true,
	}, first)
	assert.Greater(t, second.ID, first.ID)

	// The time of a listed snapshot selects it in get_policy.
	policy := call[mcpserver.PolicyResult](t, session, "get_policy", map[string]any{"at": first.AppliedAt})
	require.NotNil(t, policy.Policy)
	assert.Equal(t, first.ID, policy.Policy.ID)

	// The list holds no policy body.
	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "list_policies"})
	require.NoError(t, err)
	assert.NotContains(t, text(t, res), "192.0.2.0")

	// The other instance holds one snapshot of its own.
	instances := call[mcpserver.InstancesResult](t, session, "list_instances", nil)
	require.Len(t, instances.Instances, 2)

	other := call[mcpserver.PoliciesResult](t, session, "list_policies", map[string]any{
		"instance": instances.Instances[1].ID,
	})

	assert.Equal(t, instances.Instances[1].ID, other.Instance)
	assert.Equal(t, 1, other.Total)
	require.Len(t, other.Policies, 1)
	assert.Equal(t, "unrestricted", other.Policies[0].SecurityMode)
	assert.Empty(t, other.Policies[0].ConfigPath)
	assert.True(t, other.Policies[0].Changed)
}

// TestListPoliciesChanged records a policy, a reload that changes
// nothing, a changed policy, and a return to the first policy.
func TestListPoliciesChanged(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	store := openStore(t, path)
	now := time.Now().Truncate(time.Microsecond)

	docs := []string{firstPolicy, firstPolicy, secondPolicy, firstPolicy}

	for i, doc := range docs {
		recordPolicies(t, store, path, eventstore.PolicySnapshot{
			AppliedAt: now.Add(time.Duration(i-len(docs)) * time.Minute),
			Mode:      eventstore.SecurityFiltered,
			YAML:      doc,
		})
	}

	session := connect(t, locateAt(path))

	got := call[mcpserver.PoliciesResult](t, session, "list_policies", nil)

	assert.Equal(t, 4, got.Total)
	require.Len(t, got.Policies, 4)

	var (
		changed []bool
		hashes  []string
	)

	for _, info := range got.Policies {
		changed = append(changed, info.Changed)
		hashes = append(hashes, info.SHA256)
	}

	// The latest snapshot is first.
	assert.Equal(t, []bool{true, true, false, true}, changed)
	assert.Equal(t, []string{
		digest(firstPolicy), digest(secondPolicy), digest(firstPolicy), digest(firstPolicy),
	}, hashes)

	// The limit keeps the latest snapshots. The snapshot before the
	// last returned one still decides its flag.
	limited := call[mcpserver.PoliciesResult](t, session, "list_policies", map[string]any{"limit": 3})

	assert.Equal(t, 4, limited.Total)
	assert.Equal(t, got.Policies[:3], limited.Policies)
}

// TestListPoliciesHeaderValue records the stored documents of two
// policies that differ only in a header value. The store holds the
// redaction marker for both values, so the documents are equal and
// the later snapshot has changed false. The description of
// list_policies says so.
func TestListPoliciesHeaderValue(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	store := openStore(t, path)
	now := time.Now().Truncate(time.Microsecond)

	rotated := strings.Replace(secretPolicy, policySecret, policySecret+"-rotated", 1)
	require.NotEqual(t, secretPolicy, rotated)

	for i, policy := range []string{secretPolicy, rotated} {
		cfg, err := config.ParseConfig(t.Context(), []byte(policy))
		require.NoError(t, err)

		doc, err := config.MarshalConfig(cfg.Redacted())
		require.NoError(t, err)

		recordPolicies(t, store, path, eventstore.PolicySnapshot{
			AppliedAt: now.Add(time.Duration(i-2) * time.Minute),
			Mode:      eventstore.SecurityFiltered,
			YAML:      string(doc),
		})
	}

	session := connect(t, locateAt(path))

	got := call[mcpserver.PoliciesResult](t, session, "list_policies", nil)
	require.Len(t, got.Policies, 2)

	assert.Equal(t, got.Policies[1].SHA256, got.Policies[0].SHA256)
	assert.False(t, got.Policies[0].Changed)
	assert.True(t, got.Policies[1].Changed)

	tools, err := session.ListTools(t.Context(), nil)
	require.NoError(t, err)

	var desc string

	for _, tool := range tools.Tools {
		if tool.Name == "list_policies" {
			desc = tool.Description
		}
	}

	assert.Contains(t, desc, "a reload that changes only a header value has `changed` false")
}

func TestListPoliciesLimit(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	store := openStore(t, path)
	now := time.Now().Truncate(time.Microsecond)

	const total = mcpserver.MaxLimit + 1

	for i := range total {
		recordPolicies(t, store, path, eventstore.PolicySnapshot{
			AppliedAt: now.Add(time.Duration(i-total) * time.Second),
			Mode:      eventstore.SecurityBlocked,
			YAML:      secondPolicy,
		})
	}

	session := connect(t, locateAt(path))

	tcs := map[string]struct {
		args map[string]any
		want int
	}{
		"default":            {want: mcpserver.DefaultLimit},
		"one":                {args: map[string]any{"limit": 1}, want: 1},
		"maximum":            {args: map[string]any{"limit": mcpserver.MaxLimit}, want: mcpserver.MaxLimit},
		"more than the most": {args: map[string]any{"limit": 100000}, want: mcpserver.MaxLimit},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := call[mcpserver.PoliciesResult](t, session, "list_policies", tc.args)

			assert.Equal(t, total, got.Total)
			require.Len(t, got.Policies, tc.want)

			// The list starts at the latest snapshot.
			assert.Equal(t, stamp(now.Add(-time.Second)), got.Policies[0].AppliedAt)

			for i := 1; i < len(got.Policies); i++ {
				assert.Greater(t, got.Policies[i-1].ID, got.Policies[i].ID)
			}
		})
	}
}

// TestPolicyRedaction stores the document that terrarium stores for a
// policy with a header value, which holds the redaction marker in
// place of the value. The tools must return the marker and must not
// return the value.
func TestPolicyRedaction(t *testing.T) {
	t.Parallel()

	cfg, err := config.ParseConfig(t.Context(), []byte(secretPolicy))
	require.NoError(t, err)

	doc, err := config.MarshalConfig(cfg.Redacted())
	require.NoError(t, err)
	require.NotContains(t, string(doc), policySecret)

	path := filepath.Join(t.TempDir(), "stats.db")
	store := openStore(t, path)

	recordPolicies(t, store, path, eventstore.PolicySnapshot{
		ConfigPath: "/etc/terrarium/config.yaml",
		Mode:       eventstore.SecurityFiltered,
		YAML:       string(doc),
	})

	session := connect(t, locateAt(path))

	for _, name := range []string{"get_policy", "list_policies"} {
		res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: name})
		require.NoError(t, err)
		require.False(t, res.IsError)

		assert.NotContains(t, text(t, res), policySecret)

		raw, err := json.Marshal(res.StructuredContent)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), policySecret)
	}

	got := call[mcpserver.PolicyResult](t, session, "get_policy", nil)
	require.NotNil(t, got.Policy)

	assert.Equal(t, string(doc), got.Policy.YAML)
	assert.Contains(t, got.Policy.YAML, "value: "+config.RedactedValue)

	// The rule with the header value keeps its index, and the rule
	// list holds the marker in place of the value.
	require.Len(t, got.Policy.Egress, 2)
	assert.Equal(t, 1, got.Policy.Egress[1].Index)

	rule, err := json.Marshal(got.Policy.Egress[1].Rule)
	require.NoError(t, err)

	var decoded struct {
		ToPorts []struct {
			Rules struct {
				HTTP []struct {
					HeaderMatches []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"headerMatches"`
				} `json:"http"`
			} `json:"rules"`
		} `json:"toPorts"`
	}

	require.NoError(t, json.Unmarshal(rule, &decoded))
	require.Len(t, decoded.ToPorts, 1)
	require.Len(t, decoded.ToPorts[0].Rules.HTTP, 1)

	headers := decoded.ToPorts[0].Rules.HTTP[0].HeaderMatches
	require.Len(t, headers, 2)
	assert.Equal(t, "Authorization", headers[0].Name)
	assert.Equal(t, config.RedactedValue, headers[0].Value)
	assert.Equal(t, "X-Present", headers[1].Name)
	assert.Empty(t, headers[1].Value)

	// The description of the tool says that it withholds the values.
	tools, err := session.ListTools(t.Context(), nil)
	require.NoError(t, err)

	for _, tool := range tools.Tools {
		if tool.Name == "get_policy" {
			assert.Contains(t, tool.Description, "withholds those values")
			assert.Contains(t, tool.Description, config.RedactedValue)
		}
	}
}

// TestPoliciesWithoutSnapshotSchema reads a database of a version of
// terrarium from before the policy snapshots. The two tools must
// return a result that says that the store holds no snapshot.
func TestPoliciesWithoutSnapshotSchema(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")

	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err)

	for _, stmt := range []string{
		v2SchemaSQL,
		`PRAGMA user_version = 2`,
		`INSERT INTO instances (id, started_at, ended_at, mode) VALUES ('old', 100, 200, 'daemon')`,
	} {
		_, err = raw.ExecContext(t.Context(), stmt)
		require.NoError(t, err)
	}

	require.NoError(t, raw.Close())

	session := connect(t, locateAt(path))

	tcs := map[string]map[string]any{
		"latest instance": nil,
		"by ID":           {"instance": "old"},
	}

	for name, args := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			policy := call[mcpserver.PolicyResult](t, session, "get_policy", args)
			assert.Equal(t, "old", policy.Instance)
			assert.Nil(t, policy.Policy)
			assert.Contains(t, policy.Message, "holds no policy snapshot")

			policies := call[mcpserver.PoliciesResult](t, session, "list_policies", args)
			assert.Equal(t, "old", policies.Instance)
			assert.NotNil(t, policies.Policies)
			assert.Empty(t, policies.Policies)
			assert.Zero(t, policies.Total)
			assert.Contains(t, policies.Message, "holds no policy snapshot")
		})
	}

	// A time gets the same result, because the store holds no
	// snapshot to name.
	at := call[mcpserver.PolicyResult](t, session, "get_policy", map[string]any{"at": stamp(time.Now())})
	assert.Nil(t, at.Policy)
	assert.Contains(t, at.Message, "holds no policy snapshot of this instance.")
}

// manyRules returns a policy document with one egress rule for each
// count of cidrs and one egressDeny rule. Each egress rule allows as
// many CIDRs as its count. It also returns the JSON form of each
// egress rule, in order.
func manyRules(cidrs ...int) (string, []string) {
	var (
		doc   strings.Builder
		rules []string
	)

	doc.WriteString("egress:\n")

	for i, n := range cidrs {
		doc.WriteString("  - toCIDR:\n")

		list := make([]string, 0, n)

		for j := range n {
			cidr := fmt.Sprintf("10.%d.%d.%d/32", i/256, i%256, j%256)
			fmt.Fprintf(&doc, "      - %s\n", cidr)

			list = append(list, `"`+cidr+`"`)
		}

		rules = append(rules, `{"toCIDR":[`+strings.Join(list, ",")+`]}`)
	}

	doc.WriteString("egressDeny:\n  - toCIDR:\n      - 192.0.2.9/32\n")

	return doc.String(), rules
}

// repeat returns n copies of v.
func repeat(v, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = v
	}

	return out
}

// TestGetPolicyBounds reads a policy that is longer than
// [mcpserver.MaxPolicyBytes]. The result must bound the document,
// each rule, and each rule list, and first_rule must reach every
// rule.
func TestGetPolicyBounds(t *testing.T) {
	t.Parallel()

	// The JSON form of a rule with this many CIDRs is longer than
	// the bound.
	long := mcpserver.MaxPolicyBytes / 10

	tcs := map[string]struct {
		cidrs []int
		// The number of calls that read every rule.
		wantCalls int
	}{
		// Each entry of the list holds 51 bytes or fewer of JSON,
		// with its index and its comma. One call therefore returns
		// at least 321 rules.
		"many short rules": {cidrs: repeat(1, 1500), wantCalls: 5},
		// Each rule is longer than the bound, so one call returns
		// one truncated rule.
		"rules longer than the bound": {cidrs: repeat(long, 3), wantCalls: 3},
		// The long rule does not fit after the short rules, so it
		// starts the second call, and the last rule starts the
		// third.
		"long rule after short rules": {cidrs: []int{1, 1, long, 1}, wantCalls: 3},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			doc, want := manyRules(tc.cidrs...)
			require.Greater(t, len(doc), mcpserver.MaxPolicyBytes)

			path := filepath.Join(t.TempDir(), "stats.db")
			store := openStore(t, path)

			recordPolicies(t, store, path, eventstore.PolicySnapshot{
				Mode: eventstore.SecurityFiltered,
				YAML: doc,
			})

			session := connect(t, locateAt(path))

			var (
				seen  []int
				calls int
			)

			for first := 0; first < len(want); calls++ {
				got := call[mcpserver.PolicyResult](t, session, "get_policy", map[string]any{"first_rule": first})
				require.NotNil(t, got.Policy)

				policy := got.Policy

				// The whole result has a bounded size.
				raw, err := json.Marshal(policy)
				require.NoError(t, err)
				assert.Less(t, len(raw), 3*mcpserver.MaxPolicyBytes)

				// The hash and the totals describe the whole policy.
				assert.Equal(t, digest(doc), policy.SHA256)
				assert.Equal(t, len(want), policy.EgressTotal)
				assert.Equal(t, 1, policy.EgressDenyTotal)

				assert.Equal(t, doc[:mcpserver.MaxPolicyBytes]+mcpserver.TruncationMarker, policy.YAML)

				// A call returns at least one rule.
				require.NotEmpty(t, policy.Egress)
				assert.Equal(t, first, policy.Egress[0].Index)

				for i := range policy.Egress {
					rule := policy.Egress[i]
					wantRule := want[rule.Index]

					if len(wantRule) <= mcpserver.MaxPolicyBytes {
						assert.False(t, rule.Truncated, "rule %d", rule.Index)

						ruleJSON, err := json.Marshal(rule.Rule)
						require.NoError(t, err)
						assert.JSONEq(t, wantRule, string(ruleJSON), "rule %d", rule.Index)

						continue
					}

					// A rule longer than the bound is a truncated
					// string, and it is the only rule of its list.
					assert.True(t, rule.Truncated, "rule %d", rule.Index)
					assert.Equal(t, wantRule[:mcpserver.MaxPolicyBytes]+mcpserver.TruncationMarker, rule.Rule)
					assert.Len(t, policy.Egress, 1)
				}

				// The JSON form of a list of more than one rule,
				// with the index of each rule, holds at most
				// MaxPolicyBytes bytes.
				listJSON, err := json.Marshal(policy.Egress)
				require.NoError(t, err)

				if len(policy.Egress) > 1 {
					assert.LessOrEqual(t, len(listJSON), mcpserver.MaxPolicyBytes)
				}

				// The list ends only before a rule that does not fit.
				last := policy.Egress[len(policy.Egress)-1].Index
				if last+1 < len(want) {
					next := mcpserver.PolicyRule{Rule: json.RawMessage(want[last+1]), Index: last + 1}
					if len(want[last+1]) > mcpserver.MaxPolicyBytes {
						next.Rule = want[last+1][:mcpserver.MaxPolicyBytes] + mcpserver.TruncationMarker
						next.Truncated = true
					}

					longer, err := json.Marshal(append(slices.Clone(policy.Egress), next))
					require.NoError(t, err)
					assert.Greater(t, len(longer), mcpserver.MaxPolicyBytes, "the list ends before the bound")
				}

				if first == 0 {
					assertRules(t, seedPolicyEgressDeny[:1], 0, policy.EgressDeny)
				} else {
					assert.Empty(t, policy.EgressDeny)
				}

				seen = append(seen, indexes(policy.Egress)...)
				first = seen[len(seen)-1] + 1
			}

			wantSeen := make([]int, len(want))
			for i := range wantSeen {
				wantSeen[i] = i
			}

			assert.Equal(t, wantSeen, seen)
			assert.Equal(t, tc.wantCalls, calls)

			// The rule index of an event as first_rule returns its
			// rule as the first entry, also when a call without
			// first_rule does not reach the rule.
			ruleIndex := len(want) - 1

			got := call[mcpserver.PolicyResult](t, session, "get_policy", map[string]any{"first_rule": ruleIndex})
			require.NotNil(t, got.Policy)
			require.NotEmpty(t, got.Policy.Egress)
			assert.Equal(t, ruleIndex, got.Policy.Egress[0].Index)
		})
	}
}

// TestGetPolicyNotYAML reads a snapshot whose document is not YAML.
// The store holds what terrarium recorded, so the tool reports the
// document as a tool error and the session stays open.
func TestGetPolicyNotYAML(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	store := openStore(t, path)

	recordPolicies(t, store, path, eventstore.PolicySnapshot{
		Mode: eventstore.SecurityFiltered,
		YAML: "egress: [\n",
	})

	session := connect(t, locateAt(path))

	msg := callError(t, session, "get_policy", nil)
	assert.Contains(t, msg, "parsing the policy document of snapshot")

	// The list does not read the document.
	got := call[mcpserver.PoliciesResult](t, session, "list_policies", nil)
	assert.Len(t, got.Policies, 1)
}
