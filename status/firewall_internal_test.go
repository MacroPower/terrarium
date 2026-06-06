package status

import (
	"errors"
	"syscall"
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/firewall"
)

// stubFirewaller is a recording stub that satisfies [firewaller] for
// tests. Each field holds the canned return value; string-keyed maps
// let tests target lookups by name.
type stubFirewaller struct {
	tables         map[string]*nftables.Table
	tableErrs      map[string]error
	chains         []*nftables.Chain
	chainsErr      error
	sets           []*nftables.Set
	setsErr        error
	setElements    map[string][]nftables.SetElement
	setElementErrs map[string]error
}

func (s *stubFirewaller) ListTableOfFamily(name string, _ nftables.TableFamily) (*nftables.Table, error) {
	if err, ok := s.tableErrs[name]; ok {
		return nil, err
	}

	return s.tables[name], nil
}

func (s *stubFirewaller) ListChainsOfTableFamily(_ nftables.TableFamily) ([]*nftables.Chain, error) {
	return s.chains, s.chainsErr
}

func (s *stubFirewaller) GetSets(_ *nftables.Table) ([]*nftables.Set, error) {
	return s.sets, s.setsErr
}

func (s *stubFirewaller) GetSetElements(set *nftables.Set) ([]nftables.SetElement, error) {
	if err, ok := s.setElementErrs[set.Name]; ok {
		return nil, err
	}

	return s.setElements[set.Name], nil
}

func TestCollectFirewallTableAbsent(t *testing.T) {
	t.Parallel()

	stub := &stubFirewaller{
		tableErrs: map[string]error{
			firewall.TableName:      syscall.ENOENT,
			firewall.GuardTableName: syscall.ENOENT,
		},
	}

	s := collectFirewallWith(stub, FirewallSection{
		TableName:   firewall.TableName,
		TableFamily: "inet",
	})

	assert.False(t, s.TablePresent)
	assert.False(t, s.GuardPresent)
	assert.Zero(t, s.ChainCount)
	assert.NoError(t, s.Err)
}

func TestCollectFirewallTablePresentChains(t *testing.T) {
	t.Parallel()

	table := &nftables.Table{Name: firewall.TableName, Family: nftables.TableFamilyINet}
	other := &nftables.Table{Name: "other", Family: nftables.TableFamilyINet}

	stub := &stubFirewaller{
		tables: map[string]*nftables.Table{
			firewall.TableName:      table,
			firewall.GuardTableName: {Name: firewall.GuardTableName},
		},
		chains: []*nftables.Chain{
			{Name: "output", Table: table},
			{Name: "terrarium_output", Table: table},
			{Name: "nat_output", Table: table},
			{Name: "unrelated", Table: other}, // must not count
		},
	}

	s := collectFirewallWith(stub, FirewallSection{
		TableName:   firewall.TableName,
		TableFamily: "inet",
	})

	assert.True(t, s.TablePresent)
	assert.True(t, s.GuardPresent)
	assert.Equal(t, 3, s.ChainCount)
}

func TestCollectFirewallSetsBucketedByPrefix(t *testing.T) {
	t.Parallel()

	table := &nftables.Table{Name: firewall.TableName, Family: nftables.TableFamilyINet}

	setFQDN4 := &nftables.Set{Name: config.FQDNSetName(0, false), KeyType: nftables.TypeIPAddr}
	setFQDN6 := &nftables.Set{Name: config.FQDNSetName(0, true), KeyType: nftables.TypeIP6Addr}
	setCA4 := &nftables.Set{Name: config.CatchAllFQDNSetName(1, false), KeyType: nftables.TypeIPAddr}
	setICMP4 := &nftables.Set{Name: config.ICMPFQDNSetName(2, false), KeyType: nftables.TypeIPAddr}
	setUnrelated := &nftables.Set{Name: "something_else", KeyType: nftables.TypeIPAddr}

	stub := &stubFirewaller{
		tables: map[string]*nftables.Table{
			firewall.TableName:      table,
			firewall.GuardTableName: {Name: firewall.GuardTableName},
		},
		sets: []*nftables.Set{setFQDN4, setFQDN6, setCA4, setICMP4, setUnrelated},
		setElements: map[string][]nftables.SetElement{
			setFQDN4.Name: {{Key: []byte{1, 2, 3, 4}}, {Key: []byte{5, 6, 7, 8}}},
			setFQDN6.Name: {{Key: make([]byte, 16)}},
			setCA4.Name:   {{Key: []byte{9, 9, 9, 9}}},
			setICMP4.Name: nil,
		},
	}

	s := collectFirewallWith(stub, FirewallSection{
		TableName:   firewall.TableName,
		TableFamily: "inet",
	})

	assert.True(t, s.TablePresent)
	assert.Equal(t, 2, s.FQDNSetCount)
	assert.Equal(t, 1, s.CatchAllSetCount)
	assert.Equal(t, 1, s.ICMPFQDNSetCount)
	assert.Equal(t, 3, s.IPv4Elements)
	assert.Equal(t, 1, s.IPv6Elements)
}

func TestCollectFirewallChainsError(t *testing.T) {
	t.Parallel()

	table := &nftables.Table{Name: firewall.TableName, Family: nftables.TableFamilyINet}
	stub := &stubFirewaller{
		tables: map[string]*nftables.Table{
			firewall.TableName:      table,
			firewall.GuardTableName: {Name: firewall.GuardTableName},
		},
		chainsErr: errors.New("netlink error"),
	}

	s := collectFirewallWith(stub, FirewallSection{
		TableName:   firewall.TableName,
		TableFamily: "inet",
	})

	assert.True(t, s.TablePresent)
	require.Error(t, s.Err)
	assert.Zero(t, s.ChainCount)
}
