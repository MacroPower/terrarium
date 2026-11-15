package eventstore_test

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/eventstore"
)

// writePolicies opens a store at path, records snaps in order, and
// closes the store. It returns the instance ID of the store.
func writePolicies(
	t *testing.T,
	path string,
	snaps []eventstore.PolicySnapshot,
	opts ...eventstore.Option,
) string {
	t.Helper()

	store, err := eventstore.Open(t.Context(), path, opts...)
	require.NoError(t, err)

	for _, snap := range snaps {
		store.RecordPolicy(snap)
	}

	require.NoError(t, store.Close())

	return store.InstanceID()
}

// appliedMicros returns the applied-at time of each snapshot in
// microseconds, which is the unit of the `policies` table.
func appliedMicros(infos []eventstore.PolicyInfo) []int64 {
	out := make([]int64, 0, len(infos))
	for _, info := range infos {
		out = append(out, info.AppliedAt.UnixMicro())
	}

	return out
}

func TestStore_RecordPolicy(t *testing.T) {
	t.Parallel()

	const doc = "egress:\n  - toFQDNs:\n      - matchName: example.com\n"

	path := filepath.Join(t.TempDir(), "stats.db")

	store, err := eventstore.Open(t.Context(), path)
	require.NoError(t, err)

	before := time.Now()

	// Close follows the call at once. The writer goroutine must
	// still write the snapshot.
	store.RecordPolicy(eventstore.PolicySnapshot{
		ConfigPath: "/etc/terrarium/config.yaml",
		Mode:       eventstore.SecurityFiltered,
		YAML:       doc,
	})
	require.NoError(t, store.Close())

	// A call after Close records nothing.
	store.RecordPolicy(eventstore.PolicySnapshot{Mode: eventstore.SecurityBlocked, YAML: "late"})

	r := openReader(t, path)

	got, ok, err := r.LatestPolicy(t.Context(), store.InstanceID())
	require.NoError(t, err)
	require.True(t, ok)

	sum := sha256.Sum256([]byte(doc))

	assert.Equal(t, store.InstanceID(), got.InstanceID)
	assert.Equal(t, "/etc/terrarium/config.yaml", got.ConfigPath)
	assert.Equal(t, eventstore.SecurityFiltered, got.Mode)
	assert.Equal(t, doc, got.YAML)
	assert.Equal(t, hex.EncodeToString(sum[:]), got.SHA256)
	assert.Positive(t, got.ID)

	// The store sets the zero AppliedAt to the time of the call.
	assert.GreaterOrEqual(t, got.AppliedAt.UnixMicro(), before.UnixMicro())
	assert.LessOrEqual(t, got.AppliedAt.UnixMicro(), time.Now().UnixMicro())

	infos, err := r.Policies(t.Context(), "")
	require.NoError(t, err)
	require.Len(t, infos, 1)
	assert.Equal(t, got.PolicyInfo, infos[0])
}

func TestStore_RecordPolicy_NilStore(t *testing.T) {
	t.Parallel()

	var store *eventstore.Store

	assert.NotPanics(t, func() {
		store.RecordPolicy(eventstore.PolicySnapshot{Mode: eventstore.SecurityBlocked})
	})
}

func TestOpen_RecordsInstanceIdentity(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		opts           []eventstore.Option
		wantName       string
		wantConfigPath string
	}{
		"name and config path": {
			opts: []eventstore.Option{
				eventstore.WithInstanceName("127.0.0.1-15001"),
				eventstore.WithConfigPath("/home/dev/.config/terrarium/config.yaml"),
			},
			wantName:       "127.0.0.1-15001",
			wantConfigPath: "/home/dev/.config/terrarium/config.yaml",
		},
		"config path only": {
			opts:           []eventstore.Option{eventstore.WithConfigPath("/etc/terrarium/config.yaml")},
			wantConfigPath: "/etc/terrarium/config.yaml",
		},
		"neither": {},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "stats.db")
			id := writeStore(t, path, nil, tc.opts...)

			instances, err := openReader(t, path).Instances(t.Context())
			require.NoError(t, err)
			require.Len(t, instances, 1)
			assert.Equal(t, id, instances[0].ID)
			assert.Equal(t, tc.wantName, instances[0].Name)
			assert.Equal(t, tc.wantConfigPath, instances[0].ConfigPath)
		})
	}
}

// TestReader_Policies reads the snapshots of two instances that share
// one database.
func TestReader_Policies(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	base := time.UnixMicro(1_700_000_000_000_000)
	at := func(minutes int) time.Time { return base.Add(time.Duration(minutes) * time.Minute) }

	first := writePolicies(t, path, []eventstore.PolicySnapshot{
		{AppliedAt: at(10), ConfigPath: "/a.yaml", Mode: eventstore.SecurityUnrestricted, YAML: "a-start\n"},
		{AppliedAt: at(20), ConfigPath: "/a.yaml", Mode: eventstore.SecurityFiltered, YAML: "a-reload-1\n"},
		{AppliedAt: at(30), ConfigPath: "/a.yaml", Mode: eventstore.SecurityBlocked, YAML: "a-reload-2\n"},
	})
	second := writePolicies(t, path, []eventstore.PolicySnapshot{
		{AppliedAt: at(25), ConfigPath: "/b.yaml", Mode: eventstore.SecurityFiltered, YAML: "b-start\n"},
	})
	// An instance without a snapshot.
	third := writeStore(t, path, nil)

	r := openReader(t, path)

	t.Run("latest", func(t *testing.T) {
		t.Parallel()

		tcs := map[string]struct {
			instance string
			want     string
		}{
			"first instance":   {instance: first, want: "a-reload-2\n"},
			"second instance":  {instance: second, want: "b-start\n"},
			"no snapshot":      {instance: third},
			"unknown instance": {instance: "deadbeefdeadbeef"},
			"empty instance":   {},
		}

		for name, tc := range tcs {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				got, ok, err := r.LatestPolicy(t.Context(), tc.instance)
				require.NoError(t, err)
				assert.Equal(t, tc.want != "", ok)
				assert.Equal(t, tc.want, got.YAML)
			})
		}
	})

	t.Run("at", func(t *testing.T) {
		t.Parallel()

		tcs := map[string]struct {
			instance string
			at       time.Time
			want     string
		}{
			"before the first snapshot":     {instance: first, at: at(9)},
			"at the first snapshot":         {instance: first, at: at(10), want: "a-start\n"},
			"between two snapshots":         {instance: first, at: at(25), want: "a-reload-1\n"},
			"at a reload":                   {instance: first, at: at(30), want: "a-reload-2\n"},
			"after the last snapshot":       {instance: first, at: at(90), want: "a-reload-2\n"},
			"other instance at same time":   {instance: second, at: at(25), want: "b-start\n"},
			"other instance before its own": {instance: second, at: at(24)},
			"no snapshot":                   {instance: third, at: at(90)},
			"empty instance":                {at: at(90)},
		}

		for name, tc := range tcs {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				got, ok, err := r.PolicyAt(t.Context(), tc.instance, tc.at)
				require.NoError(t, err)
				assert.Equal(t, tc.want != "", ok)
				assert.Equal(t, tc.want, got.YAML)

				if ok {
					assert.Equal(t, tc.instance, got.InstanceID)
				}
			})
		}
	})

	t.Run("list", func(t *testing.T) {
		t.Parallel()

		micros := func(minutes ...int) []int64 {
			out := make([]int64, 0, len(minutes))
			for _, m := range minutes {
				out = append(out, at(m).UnixMicro())
			}

			return out
		}

		tcs := map[string]struct {
			instance string
			want     []int64
		}{
			"first instance":   {instance: first, want: micros(30, 20, 10)},
			"second instance":  {instance: second, want: micros(25)},
			"every instance":   {want: micros(30, 25, 20, 10)},
			"no snapshot":      {instance: third, want: []int64{}},
			"unknown instance": {instance: "deadbeefdeadbeef", want: []int64{}},
		}

		for name, tc := range tcs {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				infos, err := r.Policies(t.Context(), tc.instance)
				require.NoError(t, err)
				assert.Equal(t, tc.want, appliedMicros(infos))
			})
		}

		infos, err := r.Policies(t.Context(), first)
		require.NoError(t, err)
		require.Len(t, infos, 3)
		assert.Equal(t, eventstore.SecurityBlocked, infos[0].Mode)
		assert.Equal(t, eventstore.SecurityFiltered, infos[1].Mode)
		assert.Equal(t, eventstore.SecurityUnrestricted, infos[2].Mode)
		assert.Equal(t, "/a.yaml", infos[0].ConfigPath)
		assert.NotEqual(t, infos[0].SHA256, infos[1].SHA256)
	})
}

// TestReader_SchemaVersion2 reads a database that holds no `policies`
// table and no identity columns in the `instances` table.
func TestReader_SchemaVersion2(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")

	rawDB(t, path,
		v2SchemaSQL,
		`PRAGMA user_version = 2`,
		`INSERT INTO instances (id, started_at, ended_at, mode) VALUES ('v2instance', 100, NULL, 'proxy')`,
		`INSERT INTO instance_metrics (instance_id, recorded_at, dnscache_size) VALUES ('v2instance', 150, 4)`,
	)

	r := openReader(t, path)

	_, ok, err := r.LatestPolicy(t.Context(), "v2instance")
	require.NoError(t, err)
	assert.False(t, ok)

	_, ok, err = r.PolicyAt(t.Context(), "v2instance", time.Now())
	require.NoError(t, err)
	assert.False(t, ok)

	infos, err := r.Policies(t.Context(), "")
	require.NoError(t, err)
	assert.Empty(t, infos)

	// The reader still returns the rows that version 2 holds.
	instances, err := r.Instances(t.Context())
	require.NoError(t, err)
	require.Len(t, instances, 1)
	assert.Equal(t, "v2instance", instances[0].ID)
	assert.Equal(t, eventstore.ModeProxy, instances[0].Mode)
	assert.Empty(t, instances[0].Name)
	assert.Empty(t, instances[0].ConfigPath)

	hb, ok, err := r.LatestHeartbeat(t.Context(), "v2instance")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, int64(4), hb.DNSCacheSize)
}

// TestReader_SchemaVersion3 reads a database whose `events` table
// holds no `dst_ip` column and no `rule_index` column.
func TestReader_SchemaVersion3(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")

	rawDB(t, path,
		v3SchemaSQL,
		`PRAGMA user_version = 3`,
		`INSERT INTO instances (id, started_at, ended_at, mode, name) VALUES ('v3instance', 100, NULL, 'proxy', 'p')`,
		`INSERT INTO events (ts, instance_id, source, decision, domain, port, protocol, reason)
		 VALUES (150, 'v3instance', 'firewall', 'allow', 'api.example', 443, 'tcp', 'rule=1')`,
	)

	r := openReader(t, path)

	page, err := r.Events(t.Context(), eventstore.EventsQuery{Limit: 10})
	require.NoError(t, err)
	require.Len(t, page.Events, 1)

	e := page.Events[0]
	assert.Equal(t, "v3instance", e.InstanceID)
	assert.Equal(t, "api.example", e.Domain)
	assert.Equal(t, 443, e.Port)
	assert.Equal(t, eventstore.Reason("rule=1"), e.Reason)
	assert.False(t, e.DstIP.IsValid())
	assert.False(t, e.HasRuleIndex)
	assert.Zero(t, e.RuleIndex)
}

// TestRetention_PolicySnapshots runs the age pruner against the
// snapshots of an instance that ended and of the instance that
// prunes.
func TestRetention_PolicySnapshots(t *testing.T) {
	t.Parallel()

	now := time.Now()
	ago := func(d time.Duration) time.Time { return now.Add(-d) }

	ended := []eventstore.PolicySnapshot{
		{AppliedAt: ago(5 * time.Hour), Mode: eventstore.SecurityFiltered, YAML: "ended-1\n"},
		{AppliedAt: ago(3 * time.Hour), Mode: eventstore.SecurityFiltered, YAML: "ended-2\n"},
	}
	running := []eventstore.PolicySnapshot{
		{AppliedAt: ago(4 * time.Hour), Mode: eventstore.SecurityFiltered, YAML: "running-1\n"},
		{AppliedAt: ago(2 * time.Hour), Mode: eventstore.SecurityFiltered, YAML: "running-2\n"},
		{AppliedAt: ago(30 * time.Minute), Mode: eventstore.SecurityFiltered, YAML: "running-3\n"},
		{AppliedAt: now, Mode: eventstore.SecurityFiltered, YAML: "running-4\n"},
	}

	tcs := map[string]struct {
		retention eventstore.Retention
		// The snapshots that stay, with the latest snapshot first.
		want []time.Time
	}{
		// The cutoff is one hour ago. Each instance keeps its
		// latest snapshot. The running instance also keeps the
		// snapshot that was in force at the cutoff.
		"max age": {
			retention: eventstore.Retention{MaxAge: time.Hour},
			want: []time.Time{
				now, ago(30 * time.Minute), ago(2 * time.Hour), ago(3 * time.Hour),
			},
		},
		"no max age": {
			retention: eventstore.Retention{MaxRows: 10},
			want: []time.Time{
				now, ago(30 * time.Minute), ago(2 * time.Hour), ago(3 * time.Hour),
				ago(4 * time.Hour), ago(5 * time.Hour),
			},
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "stats.db")
			writePolicies(t, path, ended)

			store, err := eventstore.Open(t.Context(), path,
				eventstore.WithRetention(tc.retention),
				eventstore.WithPruneInterval(10*time.Millisecond))
			require.NoError(t, err)

			t.Cleanup(func() { assert.NoError(t, store.Close()) })

			for _, snap := range running {
				store.RecordPolicy(snap)
			}

			want := make([]int64, 0, len(tc.want))
			for _, at := range tc.want {
				want = append(want, at.UnixMicro())
			}

			r := openReader(t, path)

			stored := func() []int64 {
				infos, err := r.Policies(t.Context(), "")
				if err != nil {
					return nil
				}

				return appliedMicros(infos)
			}

			require.Eventually(t, func() bool { return assert.ObjectsAreEqual(want, stored()) },
				5*time.Second, 10*time.Millisecond)

			// The pruner keeps running. It must remove nothing more.
			assert.Never(t, func() bool { return !assert.ObjectsAreEqual(want, stored()) },
				200*time.Millisecond, 20*time.Millisecond)

			// The events of the retention window still map to a policy.
			got, ok, err := r.PolicyAt(t.Context(), store.InstanceID(), ago(45*time.Minute))
			require.NoError(t, err)
			require.True(t, ok)
			assert.Equal(t, "running-2\n", got.YAML)
		})
	}
}
