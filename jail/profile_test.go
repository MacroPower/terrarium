package jail_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// workloadProfileRules returns the rules of the terrarium.workload
// profile that ships in the lima directory. Each rule has no comment
// and no surrounding whitespace.
func workloadProfileRules(t *testing.T) []string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "lima", "terrarium-workload.profile"))
	require.NoError(t, err)

	var rules []string

	for line := range strings.SplitSeq(string(data), "\n") {
		rule, _, _ := strings.Cut(line, "#")

		rule = strings.TrimSpace(rule)
		if rule != "" {
			rules = append(rules, rule)
		}
	}

	return rules
}

// TestWorkloadProfileDeniesUnfilteredSockets checks that the profile
// denies the link-layer socket families. Each of them sends frames on
// an Ethernet device without passing them through the inet hooks of
// the terrarium nftables table.
func TestWorkloadProfileDeniesUnfilteredSockets(t *testing.T) {
	t.Parallel()

	rules := workloadProfileRules(t)

	tcs := map[string]struct {
		want string
	}{
		"packet sockets": {want: "deny network packet,"},
		"XDP sockets":    {want: "deny network xdp,"},
		"LLC sockets":    {want: "deny network llc,"},
		"PPPoE sockets":  {want: "deny network pppox,"},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Contains(t, rules, tc.want)
		})
	}
}
