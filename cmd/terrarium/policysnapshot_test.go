package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/eventstore"
)

// snapshotSecret is the header value of [snapshotSecretPolicy]. No
// other text of a test holds it, so a file that holds it holds the
// header value.
const snapshotSecret = "hunter2-policy-snapshot-secret"

// snapshotSecretEgress injects [snapshotSecret] into the requests of
// one HTTP rule. The proxy mode accepts it, because it holds no
// `egressDeny` rule.
const snapshotSecretEgress = "egress:\n" +
	"  - toFQDNs:\n" +
	"      - matchName: first.example\n" +
	"    toPorts:\n" +
	"      - ports:\n" +
	"          - port: \"443\"\n" +
	"  - toFQDNs:\n" +
	"      - matchName: test.example\n" +
	"    toPorts:\n" +
	"      - ports:\n" +
	"          - port: \"80\"\n" +
	"        rules:\n" +
	"          http:\n" +
	"            - path: /v1/.*\n" +
	"              headerMatches:\n" +
	"                - name: Authorization\n" +
	"                  mismatch: REPLACE\n" +
	"                  value: " + snapshotSecret + "\n" +
	"                - name: X-Present\n"

// snapshotSecretPolicy is [snapshotSecretEgress] with one `egressDeny`
// rule.
const snapshotSecretPolicy = snapshotSecretEgress +
	"egressDeny:\n" +
	"  - toCIDR:\n" +
	"      - 198.51.100.0/24\n"

// policySnapshots returns the snapshots that the stats database at
// dbPath holds, with the latest snapshot first.
func policySnapshots(t *testing.T, dbPath string) []eventstore.PolicyInfo {
	t.Helper()

	r, err := eventstore.OpenReader(t.Context(), dbPath)
	require.NoError(t, err)

	defer func() { assert.NoError(t, r.Close()) }()

	infos, err := r.Policies(t.Context(), "")
	require.NoError(t, err)

	return infos
}

// latestPolicy returns the latest snapshot of the instance in the
// stats database at dbPath.
func latestPolicy(t *testing.T, dbPath, instanceID string) eventstore.StoredPolicy {
	t.Helper()

	r, err := eventstore.OpenReader(t.Context(), dbPath)
	require.NoError(t, err)

	defer func() { assert.NoError(t, r.Close()) }()

	policy, ok, err := r.LatestPolicy(t.Context(), instanceID)
	require.NoError(t, err)
	require.True(t, ok, "the store holds no snapshot of instance %s", instanceID)

	return policy
}

// requireNoSecretInDir fails the test when a file in dir holds
// secret. The directory of a stats database also holds the
// write-ahead log of the database.
func requireNoSecretInDir(t *testing.T, dir, secret string) {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		require.NoError(t, err)
		require.NotContains(t, string(data), secret, "%s holds the header value", entry.Name())
	}
}

func TestRecordPolicySnapshot(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		policy string
		want   eventstore.SecurityMode
	}{
		"unrestricted": {
			policy: "stats:\n  enabled: true\n",
			want:   eventstore.SecurityUnrestricted,
		},
		"blocked by an empty list": {
			policy: "egress: []\n",
			want:   eventstore.SecurityBlocked,
		},
		"blocked by an empty rule": {
			policy: "egress:\n  - {}\n",
			want:   eventstore.SecurityBlocked,
		},
		"filtered": {
			policy: "egress:\n" +
				"  - toEntities:\n" +
				"      - world\n" +
				"    toPorts:\n" +
				"      - ports:\n" +
				"          - port: \"443\"\n" +
				"  - toFQDNs:\n" +
				"      - matchName: API.Example.com\n",
			want: eventstore.SecurityFiltered,
		},
		"filtered with header values": {
			policy: snapshotSecretPolicy,
			want:   eventstore.SecurityFiltered,
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg := parseProxyConfig(t, tc.policy)

			dir := t.TempDir()
			dbPath := filepath.Join(dir, "stats.db")
			configPath := filepath.Join(t.TempDir(), "config.yaml")

			store, err := eventstore.Open(t.Context(), dbPath)
			require.NoError(t, err)

			recordPolicySnapshot(t.Context(), store, cfg, configPath)

			// The writer goroutine adds the snapshot. Check the files
			// of the running store, whose write-ahead log holds the
			// row, and then the files that Close leaves.
			require.Eventually(t, func() bool { return len(policySnapshots(t, dbPath)) == 1 },
				5*time.Second, 10*time.Millisecond)
			requireNoSecretInDir(t, dir, snapshotSecret)

			require.NoError(t, store.Close())
			requireNoSecretInDir(t, dir, snapshotSecret)

			require.Len(t, policySnapshots(t, dbPath), 1)

			got := latestPolicy(t, dbPath, store.InstanceID())
			assert.Equal(t, tc.want, got.Mode)
			assert.Equal(t, configPath, got.ConfigPath)

			// The stored document parses into the rules of the
			// source, with the marker in place of each header value.
			parsed, err := config.ParseConfig(t.Context(), []byte(got.YAML))
			require.NoError(t, err, "stored document:\n%s", got.YAML)
			assert.Equal(t, cfg.Redacted(), parsed)
			assert.Equal(t, tc.want, securityMode(parsed))

			// The call left the config of the process as it was.
			assert.Equal(t, parseProxyConfig(t, tc.policy), cfg)
		})
	}
}

// TestRecordPolicySnapshot_Redaction checks the stored document of a
// policy with header values. The check of the database files in
// [TestRecordPolicySnapshot] passes only when the store holds the
// document, so this test reads the document itself.
func TestRecordPolicySnapshot_Redaction(t *testing.T) {
	t.Parallel()

	cfg := parseProxyConfig(t, snapshotSecretPolicy)
	dbPath := filepath.Join(t.TempDir(), "stats.db")

	store, err := eventstore.Open(t.Context(), dbPath)
	require.NoError(t, err)

	recordPolicySnapshot(t.Context(), store, cfg, "config.yaml")
	require.NoError(t, store.Close())

	got := latestPolicy(t, dbPath, store.InstanceID())
	assert.NotContains(t, got.YAML, snapshotSecret)
	assert.Contains(t, got.YAML, "test.example")

	parsed, err := config.ParseConfig(t.Context(), []byte(got.YAML))
	require.NoError(t, err)

	// Each rule keeps its index, and only the entry with a value
	// holds the marker.
	rules := parsed.EgressRules()
	require.Len(t, rules, 2)
	assert.Equal(t, []config.FQDNSelector{{MatchName: "first.example"}}, rules[0].ToFQDNs)
	assert.Equal(t, []config.HeaderMatch{
		{Name: "Authorization", Value: config.RedactedValue, Mismatch: config.MismatchREPLACE},
		{Name: "X-Present"},
	}, rules[1].ToPorts[0].Rules.HTTP[0].HeaderMatches)
	assert.Len(t, parsed.EgressDenyRules(), 1)

	// The store records a relative config path as an absolute one.
	want, err := filepath.Abs("config.yaml")
	require.NoError(t, err)
	assert.Equal(t, want, got.ConfigPath)
}

func TestRecordPolicySnapshot_NilStore(t *testing.T) {
	t.Parallel()

	cfg := parseProxyConfig(t, "egress: []\n")

	assert.NotPanics(t, func() {
		recordPolicySnapshot(t.Context(), nil, cfg, "config.yaml")
	})
}
