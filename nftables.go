package terrarium

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"go.jacobcolvin.com/terrarium/config"
)

const tableName = "terrarium"

// UID/GID as uint32 for nftables expressions.
const (
	uidSandbox uint32 = 1000
	uidEnvoy   uint32 = 999
	uidRoot    uint32 = 0
)

// nftablesConn abstracts the nftables.Conn methods used by rule
// building. [*nftables.Conn] satisfies this interface. Tests provide
// a recording implementation.
type nftablesConn interface {
	AddTable(t *nftables.Table) *nftables.Table
	AddChain(c *nftables.Chain) *nftables.Chain
	AddRule(r *nftables.Rule) *nftables.Rule
	AddSet(s *nftables.Set, elements []nftables.SetElement) error
	DelTable(t *nftables.Table)
	Flush() error
}

// ApplyFirewallRules deletes any existing terrarium table, builds
// the full nftables ruleset (table, chains, sets, rules), and applies
// atomically via Flush. A single inet-family table replaces all four
// iptables tables (nat/filter x IPv4/IPv6).
func ApplyFirewallRules(ctx context.Context, conn nftablesConn, cfg *config.Config) error {
	// Clean slate: delete pre-existing table from a previous run
	// so restarts in the same network namespace do not fail on
	// duplicate resources (ISSUE-53, ISSUE-67).
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
		addUnrestrictedRules(conn, table, cfg)
	case cfg.IsEgressBlocked():
		addBlockedRules(conn, table, cfg)
	default:
		err := addFilterRules(conn, table, cfg)
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

// CleanupFirewall removes the terrarium table and all its chains,
// rules, and sets.
func CleanupFirewall(ctx context.Context, conn nftablesConn) error {
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

// --- Input chain (shared by all modes) ---

func addInputChain(conn nftablesConn, table *nftables.Table) {
	policy := nftables.ChainPolicyDrop
	chain := conn.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})

	// Allow loopback.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchIIFName("lo"),
			verdictExprs(expr.VerdictAccept),
		),
	})

	// Allow established/related.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchCtState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED),
			verdictExprs(expr.VerdictAccept),
		),
	})

	// Default DROP via chain policy.
}

// --- OUTPUT base rules (shared by all modes) ---

// addOutputBaseRules emits the initial OUTPUT rules that appear in all
// three modes: loopback interface accept and loopback CIDR accept
// (nfproto-scoped).
func addOutputBaseRules(conn nftablesConn, table *nftables.Table, chain *nftables.Chain) {
	// 1. Allow loopback interface.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchOIFName("lo"),
			verdictExprs(expr.VerdictAccept),
		),
	})

	// 2. Allow loopback CIDR (nfproto-scoped).
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchDstCIDR(mustParseCIDR("127.0.0.0/8")),
			verdictExprs(expr.VerdictAccept),
		),
	})

	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchDstCIDR(mustParseCIDR("::1/128")),
			verdictExprs(expr.VerdictAccept),
		),
	})
}

// addOutputEstablishedAndICMP adds the OUTPUT rules that appear after
// the UID 1000 dispatch (or in its place for unrestricted/blocked
// modes): CT state ESTABLISHED, per-type ICMP RELATED, and root DNS.
func addOutputEstablishedAndICMP(conn nftablesConn, table *nftables.Table, chain *nftables.Chain) {
	// CT state established -> accept (covers root, Envoy, and
	// ownerless kernel packets).
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchCtState(expr.CtStateBitESTABLISHED),
			verdictExprs(expr.VerdictAccept),
		),
	})

	// ICMP RELATED rules (nfproto-scoped). Not UID-scoped since
	// ICMP errors are legitimate responses for all connections.

	// IPv4: destination-unreachable(3), time-exceeded(11),
	// parameter-problem(12).
	for _, icmpType := range []byte{3, 11, 12} {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNFProto(unix.NFPROTO_IPV4),
				matchL4Proto(unix.IPPROTO_ICMP),
				matchICMPType(icmpType),
				matchCtState(expr.CtStateBitRELATED),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}

	// ICMPv6: destination-unreachable(1), packet-too-big(2),
	// time-exceeded(3), parameter-problem(4).
	for _, icmpType := range []byte{1, 2, 3, 4} {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNFProto(unix.NFPROTO_IPV6),
				matchL4Proto(unix.IPPROTO_ICMPV6),
				matchICMPType(icmpType),
				matchCtState(expr.CtStateBitRELATED),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}

	// Root DNS queries (UDP + TCP port 53).
	for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchUID(uidRoot),
				matchL4Proto(proto),
				matchDstPort(53),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}
}

// --- Unrestricted mode ---

func addUnrestrictedRules(conn nftablesConn, table *nftables.Table, cfg *config.Config) {
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
	addOutputEstablishedAndICMP(conn, table, outputChain)

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
	addTCPForwardNAT(conn, table, cfg)
}

// --- Blocked mode ---

func addBlockedRules(conn nftablesConn, table *nftables.Table, cfg *config.Config) {
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
	addOutputEstablishedAndICMP(conn, table, outputChain)

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

// --- Rules mode ---

// setRef holds the v4 and v6 set objects for a single FQDN rule.
type setRef struct {
	set4, set6 *nftables.Set
}

func addFilterRules(conn nftablesConn, table *nftables.Table, cfg *config.Config) error {
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
			matchUID(uidSandbox),
			verdictExprs(expr.VerdictJump, "sandbox_output"),
		),
	})

	addOutputEstablishedAndICMP(conn, table, outputChain)

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
		addCIDRChains(conn, table, sandboxChain, allCIDRs)
	}

	// Envoy ACCEPT: Envoy can reach any IP (domain allowlist
	// in Envoy config provides security).
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: sandboxChain,
		Exprs: flatExprs(
			matchUID(uidEnvoy),
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
				matchUID(uidSandbox),
				verdictExprs(expr.VerdictAccept),
			),
		})
	} else {
		// Open port rules.
		for _, op := range openPortRules {
			addOpenPortRule(conn, table, sandboxChain, op)
		}

		// FQDN non-TCP port rules.
		for _, frp := range fqdnRulePorts {
			ref := fqdnSets[frp.RuleIndex]
			addFQDNPortRules(conn, table, sandboxChain, frp, ref)
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
	addNATRules(conn, table, cfg, resolvedPorts, cidr4, cidr6, openPortRules)

	return nil
}

// addCIDRChains creates per-rule CIDR chains and adds jumps from
// the parent chain. Each chain evaluates one rule's CIDRs and
// excepts independently: RETURN for except hits (try next rule),
// ACCEPT for CIDR hits (allow packet). This preserves Cilium's
// OR semantics across egress rules. Using jump (not goto) ensures
// return-to-caller works for OR evaluation.
func addCIDRChains(conn nftablesConn, table *nftables.Table, parentChain *nftables.Chain, cidrs []config.ResolvedCIDR) {
	groups := groupCIDRsByRule(cidrs)

	for i, group := range groups {
		chainName := fmt.Sprintf("cidr_%d", i)
		chain := conn.AddChain(&nftables.Chain{
			Name:  chainName,
			Table: table,
		})

		// Except RETURNs scoped to this rule only.
		for _, rule := range group {
			for _, exc := range rule.Except {
				_, excNet, err := net.ParseCIDR(exc)
				if err != nil {
					continue // validated at config parse time
				}

				if len(rule.Ports) == 0 {
					conn.AddRule(&nftables.Rule{
						Table: table, Chain: chain,
						Exprs: flatExprs(
							matchUID(uidSandbox),
							matchDstCIDR(excNet),
							verdictExprs(expr.VerdictReturn),
						),
					})
				} else {
					for _, pp := range rule.Ports {
						conn.AddRule(&nftables.Rule{
							Table: table, Chain: chain,
							Exprs: flatExprs(
								matchUID(uidSandbox),
								matchPortProto(pp),
								matchDstCIDR(excNet),
								verdictExprs(expr.VerdictReturn),
							),
						})
					}
				}
			}
		}

		// CIDR ACCEPTs scoped to this rule.
		for _, rule := range group {
			_, cidrNet, err := net.ParseCIDR(rule.CIDR)
			if err != nil {
				continue
			}

			if len(rule.Ports) == 0 {
				conn.AddRule(&nftables.Rule{
					Table: table, Chain: chain,
					Exprs: flatExprs(
						matchUID(uidSandbox),
						matchDstCIDR(cidrNet),
						verdictExprs(expr.VerdictAccept),
					),
				})
			} else {
				for _, pp := range rule.Ports {
					conn.AddRule(&nftables.Rule{
						Table: table, Chain: chain,
						Exprs: flatExprs(
							matchUID(uidSandbox),
							matchPortProto(pp),
							matchDstCIDR(cidrNet),
							verdictExprs(expr.VerdictAccept),
						),
					})
				}
			}
		}

		// Jump from parent chain.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: parentChain,
			Exprs: flatExprs(verdictExprs(expr.VerdictJump, chainName)),
		})
	}
}

// addOpenPortRule adds ACCEPT rules for open port protocols that
// bypass Envoy. UDP/SCTP ports get direct ACCEPT; TCP port ranges
// get direct ACCEPT (Envoy cannot create listeners for arbitrary
// ranges); TCP single ports are handled by Envoy via NAT REDIRECT.
func addOpenPortRule(conn nftablesConn, table *nftables.Table, chain *nftables.Chain, op config.ResolvedOpenPort) {
	if op.Protocol == protoUDP || op.Protocol == protoSCTP {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchUID(uidSandbox),
				matchL4Proto(protoNum(op.Protocol)),
				matchDstPortOrRange(port16(op.Port), port16(op.EndPort)),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}

	if op.Protocol == protoTCP && op.EndPort > 0 {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchUID(uidSandbox),
				matchL4Proto(unix.IPPROTO_TCP),
				matchDstPortOrRange(port16(op.Port), port16(op.EndPort)),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}
}

// addFQDNPortRules adds per-rule FQDN set lookup rules. Two rules
// per port per address family: ESTABLISHED first (zombie/CT semantics
// -- conntrack keeps flows alive past set TTL expiry), then set
// lookup (gates new flows requiring DNS resolution).
func addFQDNPortRules(
	conn nftablesConn,
	table *nftables.Table,
	chain *nftables.Chain,
	frp config.FQDNRulePorts,
	ref setRef,
) {
	for _, fp := range frp.Ports {
		proto := protoNum(fp.Protocol)

		// ESTABLISHED first (zombie/CT semantics).
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchUID(uidSandbox),
				matchL4Proto(proto),
				matchDstPort(port16(fp.Port)),
				matchCtState(expr.CtStateBitESTABLISHED),
				verdictExprs(expr.VerdictAccept),
			),
		})

		// Set lookup (v4).
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNFProto(unix.NFPROTO_IPV4),
				matchUID(uidSandbox),
				matchL4Proto(proto),
				matchDstPort(port16(fp.Port)),
				setLookupDst(ref.set4),
				verdictExprs(expr.VerdictAccept),
			),
		})

		// Set lookup (v6).
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNFProto(unix.NFPROTO_IPV6),
				matchUID(uidSandbox),
				matchL4Proto(proto),
				matchDstPort(port16(fp.Port)),
				setLookupDst(ref.set6),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}
}

// addNATRules creates the NAT output chain with CIDR RETURN,
// open port RETURN, Envoy REDIRECT, and TCPForward REDIRECT rules.
func addNATRules(
	conn nftablesConn, table *nftables.Table, cfg *config.Config,
	resolvedPorts []int, cidr4, cidr6 []config.ResolvedCIDR,
	openPortRules []config.ResolvedOpenPort,
) {
	if len(resolvedPorts) == 0 && len(cfg.TCPForwards) == 0 {
		return
	}

	natChain := conn.AddChain(&nftables.Chain{
		Name:     "nat_output",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
	})

	// 1. CIDR RETURN rules (allowed CIDRs bypass Envoy).
	addCIDRNATReturn(conn, table, natChain, cidr4)
	addCIDRNATReturn(conn, table, natChain, cidr6)

	// 2. Open TCP single port RETURN (port subsumes FQDN L7
	// restrictions via OR semantics). Must come before REDIRECT.
	openTCPSinglePorts := make(map[int]bool)
	for _, op := range openPortRules {
		if op.Protocol == protoTCP && op.EndPort == 0 {
			openTCPSinglePorts[op.Port] = true
		}
	}

	for _, p := range resolvedPorts {
		if openTCPSinglePorts[p] {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: natChain,
				Exprs: flatExprs(
					matchUID(uidSandbox),
					matchL4Proto(unix.IPPROTO_TCP),
					matchDstPort(port16(p)),
					verdictExprs(expr.VerdictReturn),
				),
			})
		}
	}

	// 3. Envoy REDIRECT rules.
	for _, p := range resolvedPorts {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: natChain,
			Exprs: flatExprs(
				matchUID(uidSandbox),
				matchL4Proto(unix.IPPROTO_TCP),
				matchDstPort(port16(p)),
				redirectToPort(port16(config.ProxyPortBase+p)),
			),
		})
	}

	// 4. TCPForward REDIRECT rules.
	for _, fwd := range cfg.TCPForwards {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: natChain,
			Exprs: flatExprs(
				matchUID(uidSandbox),
				matchL4Proto(unix.IPPROTO_TCP),
				matchDstPort(port16(fwd.Port)),
				redirectToPort(port16(config.ProxyPortBase+fwd.Port)),
			),
		})
	}
}

// addTCPForwardNAT creates a NAT chain with only TCPForward
// REDIRECT rules (unrestricted mode).
func addTCPForwardNAT(conn nftablesConn, table *nftables.Table, cfg *config.Config) {
	if len(cfg.TCPForwards) == 0 {
		return
	}

	natChain := conn.AddChain(&nftables.Chain{
		Name:     "nat_output",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
	})

	for _, fwd := range cfg.TCPForwards {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: natChain,
			Exprs: flatExprs(
				matchUID(uidSandbox),
				matchL4Proto(unix.IPPROTO_TCP),
				matchDstPort(port16(fwd.Port)),
				redirectToPort(port16(config.ProxyPortBase+fwd.Port)),
			),
		})
	}
}

func addCIDRNATReturn(conn nftablesConn, table *nftables.Table, chain *nftables.Chain, cidrs []config.ResolvedCIDR) {
	for _, rule := range cidrs {
		_, cidrNet, err := net.ParseCIDR(rule.CIDR)
		if err != nil {
			continue
		}

		if len(rule.Ports) == 0 {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: chain,
				Exprs: flatExprs(
					matchUID(uidSandbox),
					matchDstCIDR(cidrNet),
					verdictExprs(expr.VerdictReturn),
				),
			})
		} else {
			for _, pp := range rule.Ports {
				conn.AddRule(&nftables.Rule{
					Table: table, Chain: chain,
					Exprs: flatExprs(
						matchUID(uidSandbox),
						matchPortProto(pp),
						matchDstCIDR(cidrNet),
						verdictExprs(expr.VerdictReturn),
					),
				})
			}
		}
	}
}

// groupCIDRsByRule groups resolved CIDRs by their RuleIndex,
// preserving order of first appearance.
func groupCIDRsByRule(cidrs []config.ResolvedCIDR) [][]config.ResolvedCIDR {
	if len(cidrs) == 0 {
		return nil
	}

	idxOrder := make([]int, 0)
	groups := make(map[int][]config.ResolvedCIDR)

	for _, c := range cidrs {
		if _, seen := groups[c.RuleIndex]; !seen {
			idxOrder = append(idxOrder, c.RuleIndex)
		}

		groups[c.RuleIndex] = append(groups[c.RuleIndex], c)
	}

	result := make([][]config.ResolvedCIDR, len(idxOrder))
	for i, idx := range idxOrder {
		result[i] = groups[idx]
	}

	return result
}

// --- Expression helpers ---

// flatExprs flattens multiple expression slices into one.
func flatExprs(groups ...[]expr.Any) []expr.Any {
	var result []expr.Any
	for _, g := range groups {
		result = append(result, g...)
	}

	return result
}

// ifname pads an interface name to IFNAMSIZ (16 bytes) for
// nftables Meta iifname/oifname matching.
func ifname(name string) []byte {
	b := make([]byte, 16)
	copy(b, name+"\x00")

	return b
}

func matchIIFName(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)},
	}
}

func matchOIFName(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)},
	}
}

func matchNFProto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

func matchCtState(stateBits uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(stateBits),
			Xor:            make([]byte, 4),
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     make([]byte, 4),
		},
	}
}

func matchUID(uid uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uid)},
	}
}

func matchL4Proto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

// mustParseCIDR parses a CIDR string that is known at compile time.
func mustParseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("invalid CIDR constant: " + err.Error())
	}

	return n
}

// port16 converts a validated port number to uint16. All port values
// are validated during config parsing to be in range [0, 65535].
//
//nolint:gosec // G115: integer overflow is prevented by config validation.
func port16(p int) uint16 { return uint16(p) }

func matchDstPort(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, // destination port
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
	}
}

func matchDstPortOrRange(port, endPort uint16) []expr.Any {
	if endPort == 0 {
		return matchDstPort(port)
	}

	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
		&expr.Cmp{Op: expr.CmpOpLte, Register: 1, Data: binaryutil.BigEndian.PutUint16(endPort)},
	}
}

func matchICMPType(icmpType byte) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       0, // ICMP type field
			Len:          1,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{icmpType}},
	}
}

// matchDstCIDR matches the destination IP address against a CIDR.
// Automatically prepends nfproto matching (IPv4 or IPv6) since CIDR
// matching is inherently address-family-specific. Payload offset
// differs: IPv4 dst at offset 16 (4 bytes), IPv6 dst at offset 24
// (16 bytes).
func matchDstCIDR(ipNet *net.IPNet) []expr.Any {
	ip := ipNet.IP
	mask := ipNet.Mask

	var (
		nfp             byte
		offset, addrLen uint32
	)

	if v4 := ip.To4(); v4 != nil {
		nfp = unix.NFPROTO_IPV4
		offset = 16
		addrLen = 4
		ip = v4
		mask = mask[len(mask)-4:]
	} else {
		nfp = unix.NFPROTO_IPV6
		offset = 24
		addrLen = 16
		ip = ip.To16()
	}

	networkAddr := make(net.IP, len(ip))
	for i := range ip {
		networkAddr[i] = ip[i] & mask[i]
	}

	return flatExprs(
		matchNFProto(nfp),
		[]expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       offset,
				Len:          addrLen,
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            addrLen,
				Mask:           []byte(mask),
				Xor:            make([]byte, addrLen),
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte(networkAddr),
			},
		},
	)
}

// matchPortProto matches a [config.ResolvedPortProto]
// (L4 protocol + port or range).
func matchPortProto(pp config.ResolvedPortProto) []expr.Any {
	return flatExprs(
		matchL4Proto(protoNum(pp.Protocol)),
		matchDstPortOrRange(port16(pp.Port), port16(pp.EndPort)),
	)
}

// setLookupDst loads the destination IP from the network header and
// looks it up in the given set.
func setLookupDst(set *nftables.Set) []expr.Any {
	var offset, addrLen uint32
	if set.KeyType == nftables.TypeIPAddr {
		offset = 16
		addrLen = 4
	} else {
		offset = 24
		addrLen = 16
	}

	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       offset,
			Len:          addrLen,
		},
		&expr.Lookup{
			SourceRegister: 1,
			SetName:        set.Name,
			SetID:          set.ID,
		},
	}
}

// verdictExprs returns the verdict expression(s) for a rule terminal.
func verdictExprs(kind expr.VerdictKind, chain ...string) []expr.Any {
	v := &expr.Verdict{Kind: kind}
	if len(chain) > 0 {
		v.Chain = chain[0]
	}

	return []expr.Any{v}
}

func logPrefix(prefix string) []expr.Any {
	return []expr.Any{
		&expr.Log{
			Key:  1 << unix.NFTA_LOG_PREFIX,
			Data: []byte(prefix),
		},
	}
}

func redirectToPort(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(port),
		},
		&expr.Redir{
			RegisterProtoMin: 1,
		},
	}
}

// protoNum converts a protocol string to its IP protocol number.
func protoNum(proto string) byte {
	switch proto {
	case protoTCP:
		return unix.IPPROTO_TCP
	case protoUDP:
		return unix.IPPROTO_UDP
	case protoSCTP:
		return unix.IPPROTO_SCTP
	default:
		return 0
	}
}
