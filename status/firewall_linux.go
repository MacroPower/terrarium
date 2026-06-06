package status

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"

	"github.com/google/nftables"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/firewall"
)

// firewaller abstracts the [nftables.Conn] methods that
// [collectFirewallWith] calls. Tests provide a stub; production uses
// the real netlink client from [nftables.New].
//
// Method signatures must match [*nftables.Conn] exactly. The
// compile-time assertion below catches any upstream signature drift
// so test stubs are forced to track the real library.
type firewaller interface {
	ListTableOfFamily(name string, family nftables.TableFamily) (*nftables.Table, error)
	ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error)
	GetSets(t *nftables.Table) ([]*nftables.Set, error)
	GetSetElements(s *nftables.Set) ([]nftables.SetElement, error)
}

var _ firewaller = (*nftables.Conn)(nil)

// tableFamilyInet is the nftables address-family label reported for
// terrarium's inet table.
const tableFamilyInet = "inet"

// collectFirewall introspects nftables state relevant to terrarium.
// Returns a [FirewallSection] populated from the real kernel via
// [nftables.New].
func collectFirewall() FirewallSection {
	s := FirewallSection{
		TableName:   firewall.TableName,
		TableFamily: tableFamilyInet,
	}

	conn, err := nftables.New()
	if err != nil {
		s.Err = fmt.Errorf("opening netlink: %w", err)
		return s
	}

	return collectFirewallWith(conn, s)
}

// collectFirewallWith is the testable core of [collectFirewall]. It
// accepts a [firewaller] so tests can substitute a stub that records
// calls without touching the kernel.
func collectFirewallWith(conn firewaller, s FirewallSection) FirewallSection {
	table, err := conn.ListTableOfFamily(firewall.TableName, nftables.TableFamilyINet)
	switch {
	case err != nil && isTableMissingError(err):
		s.TablePresent = false
	case err != nil:
		s.Err = fmt.Errorf("listing table %s: %w", firewall.TableName, err)
		return s

	default:
		s.TablePresent = table != nil
	}

	_, err = conn.ListTableOfFamily(firewall.GuardTableName, nftables.TableFamilyINet)
	switch {
	case err != nil && isTableMissingError(err):
		s.GuardPresent = false
	case err != nil:
		// Don't clobber a previous Err from the main table lookup.
		if s.Err == nil {
			s.Err = fmt.Errorf("listing guard table: %w", err)
		}

	default:
		s.GuardPresent = true
	}

	if !s.TablePresent {
		return s
	}

	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		s.Err = fmt.Errorf("listing chains: %w", err)
		return s
	}

	for _, c := range chains {
		if c.Table != nil && c.Table.Name == firewall.TableName {
			s.ChainCount++
		}
	}

	sets, err := conn.GetSets(table)
	if err != nil {
		s.Err = fmt.Errorf("listing sets: %w", err)
		return s
	}

	for _, set := range sets {
		switch {
		case strings.HasPrefix(set.Name, config.FQDNSetPrefix4),
			strings.HasPrefix(set.Name, config.FQDNSetPrefix6):
			s.FQDNSetCount++
		case strings.HasPrefix(set.Name, config.CatchAllFQDNSetPrefix4),
			strings.HasPrefix(set.Name, config.CatchAllFQDNSetPrefix6):
			s.CatchAllSetCount++
		case strings.HasPrefix(set.Name, config.ICMPFQDNSetPrefix4),
			strings.HasPrefix(set.Name, config.ICMPFQDNSetPrefix6):
			s.ICMPFQDNSetCount++
		default:
			continue
		}

		elements, eerr := conn.GetSetElements(set)
		if eerr != nil {
			// Best-effort: an individual set failure should not
			// abort the whole section.
			continue
		}

		switch set.KeyType.Name {
		case nftables.TypeIPAddr.Name:
			s.IPv4Elements += len(elements)
		case nftables.TypeIP6Addr.Name:
			s.IPv6Elements += len(elements)
		}
	}

	return s
}

// isTableMissingError reports whether err signals an absent table,
// as opposed to a permission denial or other failure. The netlink
// kernel path surfaces ENOENT, and the nftables library emits a
// distinctive "expected table count 1, got 0" for matched-family
// cases where the table header did not return. Either is treated as
// "absent" so the renderer can report the table state cleanly.
func isTableMissingError(err error) bool {
	if err == nil {
		return false
	}

	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
		return true
	}

	msg := err.Error()

	return strings.Contains(msg, "expected table count") ||
		strings.Contains(msg, "no such file or directory")
}
