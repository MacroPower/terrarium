package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"go.jacobcolvin.com/terrarium/config"
)

// ApplyRules deletes any existing terrarium table, builds the full
// nftables ruleset (table, chains, sets, rules), and applies
// atomically via Flush. A single inet-family table replaces all four
// iptables tables (nat/filter x IPv4/IPv6).
func ApplyRules(ctx context.Context, conn Conn, cfg *config.Config, uids UIDs) error {
	conn.DelTable(&nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	})
	// Best-effort: table may not exist yet on first run.
	err := conn.Flush()
	if err != nil {
		slog.DebugContext(ctx, "flushing stale table (may not exist)", slog.Any("err", err))
	}

	table := conn.AddTable(&nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	})

	switch {
	case cfg.IsEgressUnrestricted():
		addUnrestrictedRules(conn, table, cfg, uids)
	case cfg.IsEgressBlocked():
		addBlockedRules(conn, table, cfg, uids)
	default:
		err := addFilterRules(conn, table, cfg, uids)
		if err != nil {
			return err
		}
	}

	err = conn.Flush()
	if err != nil {
		return fmt.Errorf("applying nftables rules: %w", err)
	}

	return nil
}

// Cleanup removes the terrarium table and all its chains,
// rules, and sets.
func Cleanup(ctx context.Context, conn Conn) error {
	conn.DelTable(&nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	})

	err := conn.Flush()
	if err != nil {
		slog.DebugContext(ctx, "cleaning up nftables", slog.Any("err", err))
	}

	return nil
}

// UpdateFQDNSet adds IP addresses to an nftables set with per-element
// timeouts. Replaces the previous ipset restore approach. Uses its
// own [*nftables.Conn] to avoid batching conflicts with rule setup.
func UpdateFQDNSet(conn *nftables.Conn, setName string, ips []net.IP, ttl time.Duration) error {
	table := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}

	set, err := conn.GetSetByName(table, setName)
	if err != nil {
		return fmt.Errorf("getting set %s: %w", setName, err)
	}

	var elements []nftables.SetElement
	for _, ip := range ips {
		key := ip.To4()
		if key == nil {
			key = ip.To16()
		}

		elements = append(elements, nftables.SetElement{
			Key:     key,
			Timeout: ttl,
		})
	}

	if len(elements) > 0 {
		err = conn.SetAddElements(set, elements)
		if err != nil {
			return fmt.Errorf("adding elements to %s: %w", setName, err)
		}
	}

	err = conn.Flush()
	if err != nil {
		return fmt.Errorf("flushing FQDN set update: %w", err)
	}

	return nil
}

func addUnrestrictedRules(conn Conn, table *nftables.Table, cfg *config.Config, uids UIDs) {
	addInputChain(conn, table)

	policy := nftables.ChainPolicyDrop
	outputChain := conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})

	addOutputBaseRules(conn, table, outputChain)
	addOutputEstablishedAndICMP(conn, table, outputChain, uids)

	if cfg.Logging {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: outputChain,
			Exprs: flatExprs(logPrefix("SANDBOX_ALLOW: ")),
		})
	}

	conn.AddRule(&nftables.Rule{
		Table: table, Chain: outputChain,
		Exprs: flatExprs(verdictExprs(expr.VerdictAccept)),
	})

	// NAT: TCPForward REDIRECTs only.
	addTCPForwardNAT(conn, table, cfg, uids)
}

func addBlockedRules(conn Conn, table *nftables.Table, cfg *config.Config, uids UIDs) {
	addInputChain(conn, table)

	policy := nftables.ChainPolicyDrop
	outputChain := conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})

	addOutputBaseRules(conn, table, outputChain)
	addOutputEstablishedAndICMP(conn, table, outputChain, uids)

	if cfg.Logging {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: outputChain,
			Exprs: flatExprs(logPrefix("SANDBOX_DROP: ")),
		})
	}

	conn.AddRule(&nftables.Rule{
		Table: table, Chain: outputChain,
		Exprs: flatExprs(verdictExprs(expr.VerdictDrop)),
	})
}

// setRef holds the v4 and v6 set objects for a single FQDN rule.
type setRef struct {
	set4, set6 *nftables.Set
}

func addFilterRules(conn Conn, table *nftables.Table, cfg *config.Config, uids UIDs) error {
	addInputChain(conn, table)

	resolvedPorts := cfg.ResolvePorts()
	cidr4, cidr6 := cfg.ResolveCIDRRules()
	allCIDRs := slices.Concat(cidr4, cidr6)
	openPortRules := cfg.ResolveOpenPortRules()
	fqdnRulePorts := cfg.ResolveFQDNNonTCPPorts()
	unrestricted := cfg.HasUnrestrictedOpenPorts()

	// Create FQDN sets before rules reference them.
	fqdnSets := make(map[int]setRef)

	for _, frp := range fqdnRulePorts {
		s4 := &nftables.Set{
			Table:      table,
			Name:       config.FQDNSetName(frp.RuleIndex, false),
			KeyType:    nftables.TypeIPAddr,
			HasTimeout: true,
		}
		err := conn.AddSet(s4, nil)
		if err != nil {
			return fmt.Errorf("creating set %s: %w", s4.Name, err)
		}

		s6 := &nftables.Set{
			Table:      table,
			Name:       config.FQDNSetName(frp.RuleIndex, true),
			KeyType:    nftables.TypeIP6Addr,
			HasTimeout: true,
		}

		err = conn.AddSet(s6, nil)
		if err != nil {
			return fmt.Errorf("creating set %s: %w", s6.Name, err)
		}

		fqdnSets[frp.RuleIndex] = setRef{set4: s4, set6: s6}
	}

	// OUTPUT chain (filter).
	policy := nftables.ChainPolicyDrop
	outputChain := conn.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})

	addOutputBaseRules(conn, table, outputChain)

	// Dispatch UID 1000 to sandbox_output before ESTABLISHED.
	// This avoids the `! --uid-owner` negation pattern and its
	// ownerless-packet problem with meta skuid.
	sandboxChain := conn.AddChain(&nftables.Chain{
		Name:  "sandbox_output",
		Table: table,
	})

	conn.AddRule(&nftables.Rule{
		Table: table, Chain: outputChain,
		Exprs: flatExprs(
			matchUID(uids.Sandbox),
			verdictExprs(expr.VerdictJump, "sandbox_output"),
		),
	})

	addOutputEstablishedAndICMP(conn, table, outputChain, uids)

	if cfg.Logging {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: outputChain,
			Exprs: flatExprs(logPrefix("SANDBOX_DROP: ")),
		})
	}

	conn.AddRule(&nftables.Rule{
		Table: table, Chain: outputChain,
		Exprs: flatExprs(verdictExprs(expr.VerdictDrop)),
	})

	// sandbox_output chain rules.
	if !unrestricted {
		addCIDRChains(conn, table, sandboxChain, allCIDRs, uids)
	}

	// Envoy ACCEPT: Envoy can reach any IP (domain allowlist
	// in Envoy config provides security).
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: sandboxChain,
		Exprs: flatExprs(
			matchUID(uids.Envoy),
			verdictExprs(expr.VerdictAccept),
		),
	})

	if unrestricted {
		// Unrestricted open ports: ACCEPT all user traffic.
		// FQDN-port combinations are still intercepted by NAT
		// REDIRECT rules, preserving Envoy L7 filtering.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: sandboxChain,
			Exprs: flatExprs(
				matchUID(uids.Sandbox),
				verdictExprs(expr.VerdictAccept),
			),
		})
	} else {
		// Open port rules.
		for _, op := range openPortRules {
			addOpenPortRule(conn, table, sandboxChain, op, uids)
		}

		// FQDN non-TCP port rules.
		for _, frp := range fqdnRulePorts {
			ref := fqdnSets[frp.RuleIndex]
			addFQDNPortRules(conn, table, sandboxChain, frp, ref, uids)
		}
	}

	if cfg.Logging {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: sandboxChain,
			Exprs: flatExprs(logPrefix("SANDBOX_DROP: ")),
		})
	}

	conn.AddRule(&nftables.Rule{
		Table: table, Chain: sandboxChain,
		Exprs: flatExprs(verdictExprs(expr.VerdictDrop)),
	})

	// NAT chain.
	addNATRules(conn, table, cfg, resolvedPorts, cidr4, cidr6, openPortRules, uids)

	return nil
}
