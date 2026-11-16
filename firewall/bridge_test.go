//go:build linux

package firewall_test

import (
	"slices"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/firewall"
)

// Meta keys of the kernel that the nftables library does not define.
const (
	// metaKeyIIFKind is the NFT_META_IIFKIND key.
	metaKeyIIFKind expr.MetaKey = 26
	// metaKeyBridgeBroute is the NFT_META_BRI_BROUTE key.
	metaKeyBridgeBroute expr.MetaKey = 35
)

func unrestrictedConfig() *config.Config {
	return &config.Config{}
}

func blockedConfig() *config.Config {
	return &config.Config{Egress: egressRules(config.EgressRule{})}
}

func filteredConfig() *config.Config {
	return &config.Config{
		Egress: egressRules(config.EgressRule{
			ToFQDNs: []config.FQDNSelector{{MatchName: "example.com"}},
			ToPorts: []config.PortRule{{Ports: []config.Port{{Port: "443"}}}},
		}),
	}
}

// tableFamilies returns the family of each terrarium table in tables.
func tableFamilies(t *testing.T, tables []*nftables.Table) []nftables.TableFamily {
	t.Helper()

	families := make([]nftables.TableFamily, 0, len(tables))

	for _, table := range tables {
		assert.Equal(t, firewall.TableName, table.Name)

		families = append(families, table.Family)
	}

	return families
}

func TestApplyRules_VMMode_BridgePreRouting(t *testing.T) {
	t.Parallel()

	// Each match loads a value into register 1 and compares it.
	pktTypeHost := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyPKTTYPE, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.PACKET_HOST}},
	}
	// The kernel compares the link kind as a NUL-padded
	// 16-byte interface name.
	vethPort := []expr.Any{
		&expr.Meta{Key: metaKeyIIFKind, Register: 1},
		&expr.Cmp{
			Op: expr.CmpOpEq, Register: 1,
			Data: []byte{'v', 'e', 't', 'h', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	}
	etherType := func(hi, lo byte) []expr.Any {
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 12, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{hi, lo}},
		}
	}
	udp := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
	}
	dstPort53 := []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 53}},
	}
	notLinkLocal := []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 2},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            2,
			Mask:           []byte{0xff, 0xc0},
			Xor:            []byte{0x00, 0x00},
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0xfe, 0x80}},
	}
	setBroute := []expr.Any{
		&expr.Immediate{Register: 1, Data: []byte{1}},
		&expr.Meta{Key: metaKeyBridgeBroute, SourceRegister: true, Register: 1},
	}

	want := [][]expr.Any{
		// DNS stays with the bridge.
		slices.Concat(udp, dstPort53, []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}),
		// IPv4 UDP from a veth port for the MAC address of the
		// bridge.
		slices.Concat(pktTypeHost, vethPort, etherType(0x08, 0x00), udp, setBroute),
		// IPv6 UDP from a veth port for the MAC address of the
		// bridge, except UDP to a link-local address.
		slices.Concat(pktTypeHost, vethPort, etherType(0x86, 0xdd), notLinkLocal, udp, setBroute),
	}

	tests := map[string]struct {
		cfg *config.Config
	}{
		"unrestricted": {cfg: unrestrictedConfig()},
		"filtered":     {cfg: filteredConfig()},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := &ruleRecorder{}

			err := firewall.ApplyRules(t.Context(), rec, tc.cfg, testVMUIDs)
			require.NoError(t, err)

			assert.Equal(t,
				[]nftables.TableFamily{nftables.TableFamilyINet, nftables.TableFamilyBridge},
				tableFamilies(t, rec.tables))

			var chain *nftables.Chain

			for _, c := range rec.chains {
				if c.Name == "bridge_prerouting" {
					chain = c
				}
			}

			require.NotNil(t, chain, "VM mode must add the bridge prerouting chain")

			// The chain is the only chain of the bridge table.
			for _, c := range rec.chains {
				assert.Equal(t, c == chain, c.Table.Family == nftables.TableFamilyBridge,
					"chain %s is in the wrong table", c.Name)
			}

			assert.Equal(t, nftables.ChainTypeFilter, chain.Type)
			require.NotNil(t, chain.Hooknum)
			assert.Equal(t, *nftables.ChainHookPrerouting, *chain.Hooknum)

			// br_netfilter runs at priority 0, and the chain must
			// run before it.
			require.NotNil(t, chain.Priority)
			assert.Equal(t, nftables.ChainPriority(-300), *chain.Priority)

			rules := rec.rulesForChain("bridge_prerouting")
			require.Len(t, rules, len(want))

			for i, r := range rules {
				assert.Same(t, chain.Table, r.Table, "rule %d", i)
				assert.Equal(t, want[i], r.Exprs, "rule %d", i)
			}
		})
	}
}

func TestApplyRules_BridgePreRouting_Absent(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		cfg  *config.Config
		uids firewall.UIDs
	}{
		// Blocked mode has no TPROXY rules, so no UDP leaves the
		// bridge.
		"vm blocked":             {cfg: blockedConfig(), uids: testVMUIDs},
		"container unrestricted": {cfg: unrestrictedConfig(), uids: testUIDs},
		"container filtered":     {cfg: filteredConfig(), uids: testUIDs},
		"container blocked":      {cfg: blockedConfig(), uids: testUIDs},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := &ruleRecorder{}

			err := firewall.ApplyRules(t.Context(), rec, tc.cfg, tc.uids)
			require.NoError(t, err)

			assert.Equal(t, []nftables.TableFamily{nftables.TableFamilyINet},
				tableFamilies(t, rec.tables))
			assert.NotContains(t, rec.chainNames(), "bridge_prerouting")
		})
	}
}

func TestApplyRules_DeletesTablesOfBothFamilies(t *testing.T) {
	t.Parallel()

	// A reload can change the mode, so each mode deletes the bridge
	// table that an earlier mode might have added.
	tests := map[string]struct {
		cfg  *config.Config
		uids firewall.UIDs
	}{
		"vm unrestricted":        {cfg: unrestrictedConfig(), uids: testVMUIDs},
		"vm filtered":            {cfg: filteredConfig(), uids: testVMUIDs},
		"vm blocked":             {cfg: blockedConfig(), uids: testVMUIDs},
		"container unrestricted": {cfg: unrestrictedConfig(), uids: testUIDs},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := &ruleRecorder{}

			err := firewall.ApplyRules(t.Context(), rec, tc.cfg, tc.uids)
			require.NoError(t, err)

			assert.Equal(t,
				[]nftables.TableFamily{nftables.TableFamilyINet, nftables.TableFamilyBridge},
				tableFamilies(t, rec.deleted))
		})
	}
}

func TestCleanup_DeletesTablesOfBothFamilies(t *testing.T) {
	t.Parallel()

	rec := &ruleRecorder{}

	err := firewall.Cleanup(t.Context(), rec)
	require.NoError(t, err)

	assert.Equal(t,
		[]nftables.TableFamily{nftables.TableFamilyINet, nftables.TableFamilyBridge},
		tableFamilies(t, rec.deleted))
	assert.Empty(t, rec.tables)
}
