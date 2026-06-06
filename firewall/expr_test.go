//go:build linux

package firewall_test

import (
	"testing"

	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.jacobcolvin.com/terrarium/firewall"
)

func TestLogPrefixKeyAndPrefix(t *testing.T) {
	t.Parallel()

	exprs := firewall.LogPrefix("TERRARIUM_DENY: ")

	require.Len(t, exprs, 1)

	log, ok := exprs[0].(*expr.Log)
	require.True(t, ok, "first expr must be a *expr.Log")

	assert.Equal(t, uint32(1<<unix.NFTA_LOG_PREFIX), log.Key,
		"logPrefix sets only NFTA_LOG_PREFIX")
	assert.Equal(t, uint16(0), log.Group)
	assert.Equal(t, "TERRARIUM_DENY: ", string(log.Data))
}

func TestLogGroupPrefixKeyGroupAndPrefix(t *testing.T) {
	t.Parallel()

	exprs := firewall.LogGroupPrefix(5000, "TERRARIUM_DENY: ")

	require.Len(t, exprs, 1)

	log, ok := exprs[0].(*expr.Log)
	require.True(t, ok, "first expr must be a *expr.Log")

	wantKey := uint32(1<<unix.NFTA_LOG_PREFIX | 1<<unix.NFTA_LOG_GROUP)
	assert.Equal(t, wantKey, log.Key,
		"logGroupPrefix sets both NFTA_LOG_PREFIX and NFTA_LOG_GROUP")
	assert.Equal(t, uint16(5000), log.Group)
	assert.Equal(t, "TERRARIUM_DENY: ", string(log.Data))
}

func TestLogEmitterDispatchesByGroupFlag(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		useGroup bool
		group    uint16
		wantKey  uint32
		wantGrp  uint16
	}{
		"useGroup=false renders syslog form": {
			useGroup: false,
			group:    5000,
			wantKey:  1 << unix.NFTA_LOG_PREFIX,
			wantGrp:  0,
		},
		"useGroup=true renders nflog form": {
			useGroup: true,
			group:    5000,
			wantKey:  1<<unix.NFTA_LOG_PREFIX | 1<<unix.NFTA_LOG_GROUP,
			wantGrp:  5000,
		},
		"useGroup=true preserves a different group": {
			useGroup: true,
			group:    1234,
			wantKey:  1<<unix.NFTA_LOG_PREFIX | 1<<unix.NFTA_LOG_GROUP,
			wantGrp:  1234,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			exprs := firewall.EmitLogExpr(true, tc.useGroup, tc.group, "PREFIX ")

			require.Len(t, exprs, 1)

			log, ok := exprs[0].(*expr.Log)
			require.True(t, ok)

			assert.Equal(t, tc.wantKey, log.Key)
			assert.Equal(t, tc.wantGrp, log.Group)
			assert.Equal(t, "PREFIX ", string(log.Data))
		})
	}
}
