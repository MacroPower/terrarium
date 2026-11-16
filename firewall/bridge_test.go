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

// withBridgeUplinks returns cfg with the given bridge uplinks.
func withBridgeUplinks(cfg *config.Config, uplinks ...string) *config.Config {
	cfg.BridgeUplinks = uplinks

	return cfg
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
	// The kernel compares the link kind as a NUL-padded 16-byte
	// name. Only the kinds of container ports match. A bond, a VLAN
	// device, or a physical network interface stays with the bridge.
	portKind := func(kind string) []expr.Any {
		data := make([]byte, 16)
		copy(data, kind)

		return []expr.Any{
			&expr.Meta{Key: metaKeyIIFKind, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
		}
	}
	// The kernel compares the interface name as a NUL-padded 16-byte
	// name.
	fromPort := func(name string) []expr.Any {
		data := make([]byte, 16)
		copy(data, name)

		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
		}
	}
	accept := []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}
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
	// An IPv4 fragment has the "more fragments" flag or a fragment
	// offset that is not zero.
	unfragmented4 := []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 6, Len: 2},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            2,
			Mask:           []byte{0x3f, 0xff},
			Xor:            []byte{0x00, 0x00},
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x00}},
	}
	// An IPv6 fragment has a Fragment extension header.
	unfragmented6 := []expr.Any{
		&expr.Exthdr{
			DestRegister: 1,
			Type:         unix.IPPROTO_FRAGMENT,
			Len:          1,
			Flags:        unix.NFT_EXTHDR_F_PRESENT,
			Op:           expr.ExthdrOpIpv6,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
	}
	setBroute := []expr.Any{
		&expr.Immediate{Register: 1, Data: []byte{1}},
		&expr.Meta{Key: metaKeyBridgeBroute, SourceRegister: true, Register: 1},
	}

	// DNS in one packet stays with the bridge. The rules do not
	// match a fragment. Only the first fragment of a datagram holds
	// the port. A rule that keeps that fragment with the bridge
	// separates it from the later fragments, and those fragments
	// leave the bridge.
	dns := [][]expr.Any{
		slices.Concat(etherType(0x08, 0x00), unfragmented4, udp, dstPort53, accept),
		slices.Concat(etherType(0x86, 0xdd), unfragmented6, udp, dstPort53, accept),
	}
	// IPv4 and IPv6 UDP for the MAC address of the bridge, from a
	// veth port and from a TAP port, whose link kind is "tun". The
	// IPv6 rules leave UDP to a link-local address with the bridge.
	broute := [][]expr.Any{
		slices.Concat(pktTypeHost, portKind("veth"), etherType(0x08, 0x00), udp, setBroute),
		slices.Concat(pktTypeHost, portKind("veth"), etherType(0x86, 0xdd), notLinkLocal, udp, setBroute),
		slices.Concat(pktTypeHost, portKind("tun"), etherType(0x08, 0x00), udp, setBroute),
		slices.Concat(pktTypeHost, portKind("tun"), etherType(0x86, 0xdd), notLinkLocal, udp, setBroute),
	}
	// withUplinks returns the rules of the chain: the DNS rules,
	// then uplinks, then the rules that set the broute flag.
	withUplinks := func(uplinks ...[]expr.Any) [][]expr.Any {
		return slices.Concat(dns, uplinks, broute)
	}

	tests := map[string]struct {
		cfg  *config.Config
		want [][]expr.Any
	}{
		"unrestricted": {
			cfg:  unrestrictedConfig(),
			want: withUplinks(),
		},
		"filtered": {
			cfg:  filteredConfig(),
			want: withUplinks(),
		},
		// Every frame of a named uplink stays with the bridge. Its
		// rule must come before the rules that set the broute flag.
		"unrestricted with one uplink": {
			cfg: withBridgeUplinks(unrestrictedConfig(), "veth-up"),
			want: withUplinks(
				slices.Concat(fromPort("veth-up"), accept),
			),
		},
		"filtered with two uplinks": {
			cfg: withBridgeUplinks(filteredConfig(), "veth-up", "tap-up"),
			want: withUplinks(
				slices.Concat(fromPort("veth-up"), accept),
				slices.Concat(fromPort("tap-up"), accept),
			),
		},
		// A name of 15 bytes fills the name but for its NUL byte.
		"uplink with the longest name": {
			cfg: withBridgeUplinks(unrestrictedConfig(), "abcdefghijklmno"),
			want: withUplinks(
				slices.Concat(fromPort("abcdefghijklmno"), accept),
			),
		},
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
			require.Len(t, rules, len(tc.want))

			for i, r := range rules {
				assert.Same(t, chain.Table, r.Table, "rule %d", i)
				assert.Equal(t, tc.want[i], r.Exprs, "rule %d", i)
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
		// Only VM mode reads the bridge uplinks.
		"container with an uplink": {
			cfg:  withBridgeUplinks(unrestrictedConfig(), "veth-up"),
			uids: testUIDs,
		},
		"vm blocked with an uplink": {
			cfg:  withBridgeUplinks(blockedConfig(), "veth-up"),
			uids: testVMUIDs,
		},
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
