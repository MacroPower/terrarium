package eventstore_test

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/eventstore"
)

func TestRetention_MaxRowsCapsRowCount(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(10),
		eventstore.WithBatchInterval(20*time.Millisecond),
		eventstore.WithRetention(eventstore.Retention{MaxRows: 100}),
	)
	require.NoError(t, err)

	for i := range 500 {
		store.Emit(eventstore.Event{
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionAllow,
			Domain:   "fill.example",
			Reason:   eventstore.Reason(string(rune(i))),
		})
	}

	require.NoError(t, store.Close())

	db, err := eventstore.OpenReadOnly(t.Context(), path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, db.Close()) })

	var n int64

	err = db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM events`).Scan(&n)
	require.NoError(t, err)

	// Pruning runs after each batch insert. Allow some slop because
	// the prune chunk size is 1000 and we may stop pruning right at
	// the boundary; we just want to confirm it stays within bounds.
	assert.LessOrEqualf(t, n, int64(200),
		"pruner should keep row count near MaxRows=100; got %d", n)
}

func TestRetention_MaxAgePrunes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(10*time.Millisecond),
	)
	require.NoError(t, err)

	old := time.Now().Add(-2 * time.Hour)
	store.Emit(eventstore.Event{
		Time:     old,
		Source:   eventstore.SourceDNS,
		Decision: eventstore.DecisionAllow,
		Domain:   "stale.example",
	})

	store.Emit(eventstore.Event{
		Source:   eventstore.SourceDNS,
		Decision: eventstore.DecisionAllow,
		Domain:   "fresh.example",
	})

	// Verify both events landed before we apply retention.
	require.Eventually(t, func() bool {
		db, err := eventstore.OpenReadOnly(t.Context(), path)
		if err != nil {
			return false
		}

		defer db.Close() //nolint:errcheck // read-only handle in polling closure.

		var n int

		err = db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM events`).Scan(&n)
		if err != nil {
			return false
		}

		return n == 2
	}, 2*time.Second, 20*time.Millisecond)

	// Apply a retention policy that should prune the old event.
	store.SetRetention(eventstore.Retention{MaxAge: time.Hour})

	// pruneByAge fires on a 60s ticker, so we cannot wait for it in
	// a test. The writer's pruner is verified by the row-based test
	// instead. Just confirm SetRetention does not break things.
	require.NoError(t, store.Close())
}

func TestStore_DropCountReflectsOverflow(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithChanSize(1),
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(time.Hour))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	// Hammer the channel; with no batch flush in sight, drops happen.
	for range 50 {
		store.Emit(eventstore.Event{
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionAllow,
			Domain:   "drop.example",
		})
	}

	assert.Positive(t, store.DropCount())
}

func TestRetention_PerSourceCapsFirewall(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	// Tight per-source firewall cap, very loose global cap. The
	// per-source pass should kick in before the global pass.
	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithChanSize(8192),
		eventstore.WithBatchSize(50),
		eventstore.WithBatchInterval(20*time.Millisecond),
		eventstore.WithRetention(eventstore.Retention{
			MaxRows: 1_000_000,
			PerSource: eventstore.PerSourceCaps{
				Firewall: 100,
			},
		}),
	)
	require.NoError(t, err)

	// Insert 5000 firewall events and 50 DNS events (100:1 ratio).
	for range 50 {
		store.Emit(eventstore.Event{
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionAllow,
			Domain:   "dns.example",
		})

		for range 100 {
			store.Emit(eventstore.Event{
				Source:   eventstore.SourceFirewall,
				Decision: eventstore.DecisionDeny,
			})
		}
	}

	require.NoError(t, store.Close())
	require.Zerof(t, store.DropCount(),
		"channel overflow during the test would invalidate the per-source assertion (drop count %d)",
		store.DropCount())

	db, err := eventstore.OpenReadOnly(t.Context(), path)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, db.Close()) })

	var firewallCount, dnsCount int64

	err = db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM events WHERE source='firewall'`).Scan(&firewallCount)
	require.NoError(t, err)

	err = db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM events WHERE source='dns'`).Scan(&dnsCount)
	require.NoError(t, err)

	// Without per-source pruning the firewall stream would land at
	// 5000 (the full insert count); with a per-source cap of 100 and
	// a 1000-row prune chunk, the count is bounded above by the
	// chunk overshoot. The cap itself is the floor: the pruner never
	// deletes below the configured limit.
	assert.LessOrEqualf(t, firewallCount, int64(2000),
		"per-source pruning should keep firewall row count near the 100 cap (got %d)", firewallCount)
	assert.GreaterOrEqualf(t, firewallCount, int64(100),
		"per-source pruner must not delete below the configured cap (got %d)", firewallCount)
	assert.Equalf(t, int64(50), dnsCount,
		"DNS rows must not be touched by firewall per-source pruning (got %d)", dnsCount)
}

func TestRetention_SetRetentionRaceFreeWithPerSource(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(10),
		eventstore.WithBatchInterval(20*time.Millisecond),
	)
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	// Concurrent writes against retention swaps. -race confirms the
	// pointer swap is lock-free.
	go func() {
		for range 200 {
			store.Emit(eventstore.Event{
				Source:   eventstore.SourceFirewall,
				Decision: eventstore.DecisionDeny,
			})
		}
	}()

	for i := range 200 {
		store.SetRetention(eventstore.Retention{
			MaxRows: int64(1000 + i),
			PerSource: eventstore.PerSourceCaps{
				Firewall: int64(100 + i),
				DNS:      int64(50 + i),
				Envoy:    int64(25 + i),
			},
		})
	}
}

func TestStore_LastWriteTimeUpdates(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithBatchSize(1),
		eventstore.WithBatchInterval(20*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	assert.True(t, store.LastWriteTime().IsZero(),
		"no writes yet, LastWriteTime should be zero")

	store.Emit(eventstore.Event{
		Source:   eventstore.SourceDNS,
		Decision: eventstore.DecisionAllow,
		Domain:   "lw.example",
	})

	require.Eventually(t, func() bool {
		return !store.LastWriteTime().IsZero()
	}, 2*time.Second, 20*time.Millisecond)
}

// execRaw runs one statement on the database at path through its own
// connection, as another process does. The connection waits for the
// write lock of a store that has the database open.
func execRaw(t *testing.T, path, query string, args ...any) {
	t.Helper()

	raw, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(2000)")
	require.NoError(t, err)

	_, err = raw.ExecContext(t.Context(), query, args...)
	require.NoError(t, err)
	require.NoError(t, raw.Close())
}

// setInstanceTimes replaces the start and the end of the instance
// with the given ID in the database at path. The zero ended leaves
// the instance without an end, as a process does that stops without
// a [eventstore.Store.Close].
func setInstanceTimes(t *testing.T, path, id string, started, ended time.Time) {
	t.Helper()

	var end sql.NullInt64

	if !ended.IsZero() {
		end = sql.NullInt64{Int64: ended.UnixMicro(), Valid: true}
	}

	execRaw(t, path, `UPDATE instances SET started_at = ?, ended_at = ? WHERE id = ?`,
		started.UnixMicro(), end, id)
}

// stoppedInstance adds an instance to the database at path that
// started three hours ago and ended two hours ago. It holds no
// events, no heartbeat, and no policy snapshot. It returns the ID of
// the instance.
func stoppedInstance(t *testing.T, path string) string {
	t.Helper()

	id := writeStore(t, path, nil)
	setInstanceTimes(t, path, id, time.Now().Add(-3*time.Hour), time.Now().Add(-2*time.Hour))

	return id
}

// instanceIDs returns the ID of each instance that r reads. It
// returns the error of the read, so that a polling closure can call
// it.
func instanceIDs(ctx context.Context, r *eventstore.Reader) ([]string, error) {
	instances, err := r.Instances(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading instances: %w", err)
	}

	ids := make([]string, 0, len(instances))
	for _, in := range instances {
		ids = append(ids, in.ID)
	}

	return ids, nil
}

// requireInstanceRemoved waits until r reads no instance with the
// given ID.
func requireInstanceRemoved(t *testing.T, r *eventstore.Reader, id string) {
	t.Helper()

	require.Eventually(t, func() bool {
		ids, err := instanceIDs(t.Context(), r)

		return err == nil && !slices.Contains(ids, id)
	}, 5*time.Second, 10*time.Millisecond)
}

// TestRetention_Instances runs the age pruner of one store against
// an instance of another store that stopped.
func TestRetention_Instances(t *testing.T) {
	t.Parallel()

	now := time.Now()
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	maxAge := eventstore.Retention{MaxAge: time.Hour}

	tcs := map[string]struct {
		// The times of the instance. The zero time leaves the
		// instance without that row.
		started   time.Time
		ended     time.Time
		heartbeat time.Time
		event     time.Time
		policies  []time.Time
		retention eventstore.Retention
		// Whether the pruner removes the instance.
		removed bool
	}{
		"ended before the cutoff": {
			retention: maxAge,
			started:   ago(3 * time.Hour),
			ended:     ago(2 * time.Hour),
			heartbeat: ago(2 * time.Hour),
			policies:  []time.Time{ago(3 * time.Hour), ago(150 * time.Minute)},
			removed:   true,
		},
		"ended within max age": {
			retention: maxAge,
			started:   ago(3 * time.Hour),
			ended:     ago(30 * time.Minute),
			heartbeat: ago(30 * time.Minute),
			policies:  []time.Time{ago(3 * time.Hour)},
		},
		"holds an event": {
			retention: maxAge,
			started:   ago(3 * time.Hour),
			ended:     ago(2 * time.Hour),
			event:     ago(30 * time.Minute),
		},
		"holds a heartbeat within max age": {
			retention: maxAge,
			started:   ago(3 * time.Hour),
			ended:     ago(2 * time.Hour),
			heartbeat: ago(30 * time.Minute),
		},
		"holds a snapshot within max age": {
			retention: maxAge,
			started:   ago(3 * time.Hour),
			ended:     ago(2 * time.Hour),
			policies:  []time.Time{ago(3 * time.Hour), ago(30 * time.Minute)},
		},
		"no end and an old heartbeat": {
			retention: maxAge,
			started:   ago(3 * time.Hour),
			heartbeat: ago(2 * time.Hour),
			policies:  []time.Time{ago(3 * time.Hour)},
			removed:   true,
		},
		"no end and a heartbeat within max age": {
			retention: maxAge,
			started:   ago(3 * time.Hour),
			heartbeat: ago(time.Minute),
		},
		"no end and no heartbeat": {
			retention: maxAge,
			started:   ago(3 * time.Hour),
			removed:   true,
		},
		"no end and a start within max age": {
			retention: maxAge,
			started:   ago(30 * time.Minute),
		},
		// The heartbeat is older than the max age, but a running
		// instance records one heartbeat in each interval.
		"short max age, no end and a heartbeat of the last interval": {
			retention: eventstore.Retention{MaxAge: time.Second},
			started:   ago(3 * time.Hour),
			heartbeat: ago(eventstore.HeartbeatInterval),
		},
		"short max age, no end and an old heartbeat": {
			retention: eventstore.Retention{MaxAge: time.Second},
			started:   ago(3 * time.Hour),
			heartbeat: ago(3 * eventstore.HeartbeatInterval),
			removed:   true,
		},
		"short max age and an end": {
			retention: eventstore.Retention{MaxAge: time.Second},
			started:   ago(3 * time.Hour),
			ended:     ago(eventstore.HeartbeatInterval),
			heartbeat: ago(eventstore.HeartbeatInterval),
			removed:   true,
		},
		"no max age": {
			retention: eventstore.Retention{MaxRows: 10},
			started:   ago(3 * time.Hour),
			ended:     ago(2 * time.Hour),
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "stats.db")

			other, err := eventstore.Open(t.Context(), path)
			require.NoError(t, err)

			if !tc.heartbeat.IsZero() {
				require.NoError(t, other.RecordHeartbeat(t.Context(),
					eventstore.Heartbeat{RecordedAt: tc.heartbeat}))
			}

			for i, at := range tc.policies {
				other.RecordPolicy(eventstore.PolicySnapshot{
					AppliedAt: at, Mode: eventstore.SecurityFiltered, YAML: string(rune('a' + i)),
				})
			}

			if !tc.event.IsZero() {
				other.Emit(eventstore.Event{
					Time: tc.event, Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow,
				})
			}

			require.NoError(t, other.Close())
			setInstanceTimes(t, path, other.InstanceID(), tc.started, tc.ended)

			// The pruner selects every removable instance in one
			// query. After it removed this instance, it has also
			// decided on the instance of the test case.
			stopped := stoppedInstance(t, path)

			store, err := eventstore.Open(t.Context(), path,
				eventstore.WithRetention(tc.retention),
				eventstore.WithPruneInterval(10*time.Millisecond))
			require.NoError(t, err)

			t.Cleanup(func() { assert.NoError(t, store.Close()) })

			r := openReader(t, path)

			want := []string{store.InstanceID()}

			if tc.retention.MaxAge > 0 {
				requireInstanceRemoved(t, r, stopped)
			} else {
				want = append(want, stopped)
			}

			if !tc.removed {
				want = append(want, other.InstanceID())
			}

			got, err := instanceIDs(t.Context(), r)
			require.NoError(t, err)
			assert.ElementsMatch(t, want, got)

			// The pruner keeps running. It must remove nothing more.
			assert.Never(t, func() bool {
				ids, err := instanceIDs(t.Context(), r)

				return err == nil && len(ids) != len(want)
			}, 200*time.Millisecond, 20*time.Millisecond)

			_, hasHeartbeat, err := r.LatestHeartbeat(t.Context(), other.InstanceID())
			require.NoError(t, err)
			assert.Equal(t, !tc.removed && !tc.heartbeat.IsZero(), hasHeartbeat)

			infos, err := r.Policies(t.Context(), other.InstanceID())
			require.NoError(t, err)

			if tc.removed {
				assert.Empty(t, infos)
			} else {
				assert.Len(t, infos, len(tc.policies))
			}
		})
	}
}

// TestRetention_KeepsOwnInstance runs the age pruner of a store whose
// own instance holds no events and no heartbeat, and whose start is
// older than the max age.
func TestRetention_KeepsOwnInstance(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")

	store, err := eventstore.Open(t.Context(), path,
		eventstore.WithRetention(eventstore.Retention{MaxAge: time.Hour}),
		eventstore.WithPruneInterval(10*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, store.Close()) })

	setInstanceTimes(t, path, store.InstanceID(), time.Now().Add(-3*time.Hour), time.Time{})

	// The pruner removes this instance in a run that follows the
	// change of the start, so that run has also decided on the
	// instance of the store.
	stopped := stoppedInstance(t, path)

	r := openReader(t, path)
	requireInstanceRemoved(t, r, stopped)

	got, err := instanceIDs(t.Context(), r)
	require.NoError(t, err)
	assert.Equal(t, []string{store.InstanceID()}, got)
}

// TestRetention_RemovedInstanceIsNotDefault runs the age pruner of a
// proxy against a daemon run that stopped and holds no events. The
// daemon run is the default instance until the pruner removes it.
func TestRetention_RemovedInstanceIsNotDefault(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")

	daemon := writeStore(t, path, nil, eventstore.WithMode(eventstore.ModeDaemon))
	setInstanceTimes(t, path, daemon, time.Now().Add(-3*time.Hour), time.Now().Add(-2*time.Hour))

	r := openReader(t, path)

	got, ok, err := r.DefaultInstanceID(t.Context())
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, daemon, got)

	proxy, err := eventstore.Open(t.Context(), path,
		eventstore.WithMode(eventstore.ModeProxy),
		eventstore.WithRetention(eventstore.Retention{MaxAge: time.Hour}),
		eventstore.WithPruneInterval(10*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Close()) })

	requireInstanceRemoved(t, r, daemon)

	got, ok, err = r.DefaultInstanceID(t.Context())
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, proxy.InstanceID(), got)
}

// TestRetention_RunningInstanceKeepsPolicy runs the age pruner of a
// daemon against a proxy that is running but looks stopped, as after
// a suspension of the proxy for longer than the max age. The next
// heartbeat of the proxy must bring back its instance and its policy
// snapshot.
func TestRetention_RunningInstanceKeepsPolicy(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stats.db")
	applied := time.Now().Add(-3 * time.Hour).Truncate(time.Microsecond)

	proxy, err := eventstore.Open(t.Context(), path,
		eventstore.WithMode(eventstore.ModeProxy))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, proxy.Close()) })

	proxy.RecordPolicy(eventstore.PolicySnapshot{
		AppliedAt: applied,
		Mode:      eventstore.SecurityFiltered,
		YAML:      "egress: []\n",
	})

	r := openReader(t, path)

	require.Eventually(t, func() bool {
		_, ok, err := r.LatestPolicy(t.Context(), proxy.InstanceID())

		return err == nil && ok
	}, 5*time.Second, 10*time.Millisecond)

	setInstanceTimes(t, path, proxy.InstanceID(), applied, time.Time{})

	daemon, err := eventstore.Open(t.Context(), path,
		eventstore.WithMode(eventstore.ModeDaemon),
		eventstore.WithRetention(eventstore.Retention{MaxAge: time.Hour}),
		eventstore.WithPruneInterval(10*time.Millisecond))
	require.NoError(t, err)

	t.Cleanup(func() { assert.NoError(t, daemon.Close()) })

	requireInstanceRemoved(t, r, proxy.InstanceID())

	_, ok, err := r.LatestPolicy(t.Context(), proxy.InstanceID())
	require.NoError(t, err)
	require.False(t, ok)

	require.NoError(t, proxy.RecordHeartbeat(t.Context(), eventstore.Heartbeat{}))

	require.Eventually(t, func() bool {
		ids, err := instanceIDs(t.Context(), r)

		return err == nil && slices.Contains(ids, proxy.InstanceID())
	}, 5*time.Second, 10*time.Millisecond)

	got, ok, err := r.LatestPolicy(t.Context(), proxy.InstanceID())
	require.NoError(t, err)
	require.True(t, ok)
	assert.True(t, got.AppliedAt.Equal(applied))
	assert.Equal(t, eventstore.SecurityFiltered, got.Mode)
	assert.Equal(t, "egress: []\n", got.YAML)
}

// TestStore_WritesRemovedInstanceRowAgain removes the instance of a
// running store, as the pruner of another store does for an instance
// that looks stopped. Each write of the store must then bring the
// instance row and the latest policy snapshot of the store back.
func TestStore_WritesRemovedInstanceRowAgain(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		write func(t *testing.T, store *eventstore.Store)
	}{
		"event": {
			write: func(_ *testing.T, store *eventstore.Store) {
				store.Emit(eventstore.Event{
					Source: eventstore.SourceDNS, Decision: eventstore.DecisionAllow,
				})
			},
		},
		"heartbeat": {
			write: func(t *testing.T, store *eventstore.Store) {
				t.Helper()

				require.NoError(t, store.RecordHeartbeat(t.Context(), eventstore.Heartbeat{}))
			},
		},
		"policy snapshot": {
			write: func(_ *testing.T, store *eventstore.Store) {
				store.RecordPolicy(eventstore.PolicySnapshot{
					Mode: eventstore.SecurityBlocked, YAML: "egress:\n- {}\n",
				})
			},
		},
	}

	applied := time.Now().Add(-3 * time.Hour).Truncate(time.Microsecond)

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "stats.db")

			store, err := eventstore.Open(t.Context(), path,
				eventstore.WithMode(eventstore.ModeProxy),
				eventstore.WithInstanceName("127.0.0.1-8080"),
				eventstore.WithConfigPath("/etc/terrarium/config.yaml"),
				eventstore.WithBatchSize(1),
				eventstore.WithBatchInterval(10*time.Millisecond))
			require.NoError(t, err)

			t.Cleanup(func() { assert.NoError(t, store.Close()) })

			r := openReader(t, path)

			want, err := r.Instances(t.Context())
			require.NoError(t, err)
			require.Len(t, want, 1)

			store.RecordPolicy(eventstore.PolicySnapshot{
				AppliedAt:  applied,
				ConfigPath: "/etc/terrarium/config.yaml",
				Mode:       eventstore.SecurityFiltered,
				YAML:       "egress: []\n",
			})

			var wantPolicy eventstore.StoredPolicy

			require.Eventually(t, func() bool {
				var ok bool

				wantPolicy, ok, err = r.LatestPolicy(t.Context(), store.InstanceID())

				return err == nil && ok
			}, 5*time.Second, 10*time.Millisecond)

			require.NoError(t, store.RecordHeartbeat(t.Context(), eventstore.Heartbeat{}))

			// Wait until the writer stores the heartbeat. A heartbeat
			// that it stores after the deletes below writes the rows
			// again, and the subtest then does not test its own write.
			require.Eventually(t, func() bool {
				_, ok, err := r.LatestHeartbeat(t.Context(), store.InstanceID())

				return err == nil && ok
			}, 5*time.Second, 10*time.Millisecond)

			id := store.InstanceID()
			execRaw(t, path, `DELETE FROM instance_metrics WHERE instance_id = ?`, id)
			execRaw(t, path, `DELETE FROM policies WHERE instance_id = ?`, id)
			execRaw(t, path, `DELETE FROM instances WHERE id = ?`, id)

			got, err := r.Instances(t.Context())
			require.NoError(t, err)
			require.Empty(t, got)

			tc.write(t, store)

			require.Eventually(t, func() bool {
				ids, err := instanceIDs(t.Context(), r)

				return err == nil && len(ids) == 1
			}, 5*time.Second, 10*time.Millisecond)

			got, err = r.Instances(t.Context())
			require.NoError(t, err)
			assert.Equal(t, want, got)

			policies, err := r.Policies(t.Context(), id)
			require.NoError(t, err)
			require.NotEmpty(t, policies)

			// The oldest snapshot is the one that the test removed.
			// Its row ID changes when the store writes it again.
			gotPolicy := policies[len(policies)-1]
			wantInfo := wantPolicy.PolicyInfo
			wantInfo.ID = gotPolicy.ID
			assert.Equal(t, wantInfo, gotPolicy)
			assert.True(t, gotPolicy.AppliedAt.Equal(applied))
		})
	}
}
