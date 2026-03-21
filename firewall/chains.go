package firewall

import (
	"fmt"
	"net"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"go.jacobcolvin.com/terrarium/config"
)

func addInputChain(conn Conn, table *nftables.Table) {
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

// addOutputBaseRules emits the initial OUTPUT rules that appear in all
// three modes: loopback interface accept and loopback CIDR accept
// (nfproto-scoped). When excludeMark is non-zero, the loopback OIF
// accept rule is qualified with fwmark != excludeMark so that
// TPROXY-marked packets fall through to security evaluation.
func addOutputBaseRules(conn Conn, table *nftables.Table, chain *nftables.Chain, excludeMark uint32) {
	// 1. Allow loopback interface (optionally excluding marked packets).
	loExprs := matchOIFName("lo")
	if excludeMark != 0 {
		loExprs = flatExprs(loExprs, matchNotMark(excludeMark))
	}

	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			loExprs,
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
func addOutputEstablishedAndICMP(conn Conn, table *nftables.Table, chain *nftables.Chain, uids UIDs) {
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
				matchUID(uids.Root),
				matchL4Proto(proto),
				matchDstPort(53),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}
}

// addDenyCIDRChains creates per-rule deny CIDR chains and adds jumps
// from the parent chain. Each chain evaluates one deny rule's CIDRs
// and excepts independently: RETURN for except hits (don't deny),
// DROP for CIDR hits (deny packet). Deny chains are evaluated before
// allow chains so deny takes precedence.
func addDenyCIDRChains(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR, uids UIDs,
) {
	addDenyCIDRChainsWithVerdict(conn, table, parentChain, cidrs, uids, "deny_cidr", expr.VerdictDrop)
}

// addDenyCIDRChainsWithVerdict is the shared implementation for deny
// CIDR chain construction. The chainPrefix names the chains (e.g.
// "deny_cidr" or "deny_cidr_nat") and verdict is the action for
// matching traffic (DROP in filter, ACCEPT in NAT to skip redirect).
func addDenyCIDRChainsWithVerdict(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR, uids UIDs,
	chainPrefix string, verdict expr.VerdictKind,
) {
	groups := groupCIDRsByRule(cidrs)

	for i, group := range groups {
		chainName := fmt.Sprintf("%s_%d", chainPrefix, i)
		chain := conn.AddChain(&nftables.Chain{
			Name:  chainName,
			Table: table,
		})

		// Except RETURNs: don't deny these sub-ranges.
		for _, rule := range group {
			for _, exc := range rule.Except {
				_, excNet, err := net.ParseCIDR(exc)
				if err != nil {
					continue
				}

				if len(rule.Ports) == 0 {
					conn.AddRule(&nftables.Rule{
						Table: table, Chain: chain,
						Exprs: flatExprs(
							matchUID(uids.Terrarium),
							matchDstCIDR(excNet),
							verdictExprs(expr.VerdictReturn),
						),
					})
				} else {
					for _, pp := range rule.Ports {
						conn.AddRule(&nftables.Rule{
							Table: table, Chain: chain,
							Exprs: flatExprs(
								matchUID(uids.Terrarium),
								matchPortProto(pp),
								matchDstCIDR(excNet),
								verdictExprs(expr.VerdictReturn),
							),
						})
					}
				}
			}
		}

		// CIDR verdict rules: deny matching traffic.
		for _, rule := range group {
			_, cidrNet, err := net.ParseCIDR(rule.CIDR)
			if err != nil {
				continue
			}

			if len(rule.Ports) == 0 {
				conn.AddRule(&nftables.Rule{
					Table: table, Chain: chain,
					Exprs: flatExprs(
						matchUID(uids.Terrarium),
						matchDstCIDR(cidrNet),
						verdictExprs(verdict),
					),
				})
			} else {
				for _, pp := range rule.Ports {
					conn.AddRule(&nftables.Rule{
						Table: table, Chain: chain,
						Exprs: flatExprs(
							matchUID(uids.Terrarium),
							matchPortProto(pp),
							matchDstCIDR(cidrNet),
							verdictExprs(verdict),
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

// addDenyPortRules emits DROP rules on the parent chain for port-only
// deny rules (no L3 selector). Under Cilium semantics, a deny rule
// with only toPorts means "deny traffic to any destination on these
// ports." A zero-value [config.ResolvedPortProto] (port 0, empty
// protocol) means wildcard: deny all ports/protocols.
func addDenyPortRules(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	ports []config.ResolvedPortProto, uids UIDs,
) {
	for _, pp := range ports {
		if pp.Port == 0 && pp.Protocol == "" {
			// Wildcard: deny all traffic from terrarium UID.
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: parentChain,
				Exprs: flatExprs(
					matchUID(uids.Terrarium),
					verdictExprs(expr.VerdictDrop),
				),
			})
		} else {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: parentChain,
				Exprs: flatExprs(
					matchUID(uids.Terrarium),
					matchPortProto(pp),
					verdictExprs(expr.VerdictDrop),
				),
			})
		}
	}
}

// addCIDRChains creates per-rule CIDR chains and adds jumps from
// the parent chain. Each chain evaluates one rule's CIDRs and
// excepts independently: RETURN for except hits (try next rule),
// ACCEPT for CIDR hits (allow packet). This preserves Cilium's
// OR semantics across egress rules. Using jump (not goto) ensures
// return-to-caller works for OR evaluation.
func addCIDRChains(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR, uids UIDs,
) {
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
							matchUID(uids.Terrarium),
							matchDstCIDR(excNet),
							verdictExprs(expr.VerdictReturn),
						),
					})
				} else {
					for _, pp := range rule.Ports {
						conn.AddRule(&nftables.Rule{
							Table: table, Chain: chain,
							Exprs: flatExprs(
								matchUID(uids.Terrarium),
								matchPortProto(pp),
								matchDstCIDR(excNet),
								verdictExprs(expr.VerdictReturn),
							),
						})
					}
				}
			}
		}

		// CIDR ACCEPTs scoped to this rule. CIDR rules with
		// serverNames skip ACCEPT here; they are handled by NAT
		// REDIRECT to Envoy for SNI inspection. CIDR rules with
		// L7 ports also skip ACCEPT for those ports; they are
		// handled by REDIRECT to Envoy for HTTP filtering.
		for _, rule := range group {
			if len(rule.ServerNames) > 0 {
				continue
			}

			_, cidrNet, err := net.ParseCIDR(rule.CIDR)
			if err != nil {
				continue
			}

			if len(rule.Ports) == 0 {
				conn.AddRule(&nftables.Rule{
					Table: table, Chain: chain,
					Exprs: flatExprs(
						matchUID(uids.Terrarium),
						matchDstCIDR(cidrNet),
						verdictExprs(expr.VerdictAccept),
					),
				})
			} else {
				for _, pp := range rule.Ports {
					// L7 ports are handled by Envoy; skip ACCEPT.
					if rule.L7Ports[pp.Port] {
						continue
					}

					conn.AddRule(&nftables.Rule{
						Table: table, Chain: chain,
						Exprs: flatExprs(
							matchUID(uids.Terrarium),
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

// addOpenPortRule adds ACCEPT rules for open port protocols. UDP
// ports get direct ACCEPT (security decision); TPROXY routes UDP
// through Envoy independently for access logging. TCP port ranges get
// direct ACCEPT (Envoy cannot create listeners for arbitrary ranges);
// TCP single ports are handled by Envoy via NAT REDIRECT.
func addOpenPortRule(conn Conn, table *nftables.Table, chain *nftables.Chain, op config.ResolvedOpenPort, uids UIDs) {
	if op.Protocol == config.ProtoUDP {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchUID(uids.Terrarium),
				matchL4Proto(protoNum(op.Protocol)),
				matchDstPortOrRange(port16(op.Port), port16(op.EndPort)),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}

	if op.Protocol == config.ProtoTCP && op.EndPort > 0 {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchUID(uids.Terrarium),
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
	conn Conn,
	table *nftables.Table,
	chain *nftables.Chain,
	frp config.FQDNRulePorts,
	ref setRef,
	uids UIDs,
) {
	for _, fp := range frp.Ports {
		proto := protoNum(fp.Protocol)

		// ESTABLISHED first (zombie/CT semantics).
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchUID(uids.Terrarium),
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
				matchUID(uids.Terrarium),
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
				matchUID(uids.Terrarium),
				matchL4Proto(proto),
				matchDstPort(port16(fp.Port)),
				setLookupDst(ref.set6),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}
}

// addNATRules creates the NAT output chain with deny CIDR ACCEPT,
// allow CIDR REDIRECT, per-port REDIRECT, TCPForward REDIRECT, and
// catch-all TCP REDIRECT rules. The deny CIDR chains prevent denied
// traffic from being redirected to Envoy (ACCEPT in NAT skips
// modification; the filter chain's deny rules DROP the traffic). The
// allow CIDR chains redirect matching TCP to the CIDR catch-all
// listener for forwarding via original_dst. The catch-all sends
// remaining non-policy-port traffic to Envoy's blackhole listener.
func addNATRules(
	conn Conn, table *nftables.Table, cfg *config.Config,
	resolvedPorts []int, cidr4, cidr6, denyCIDRs []config.ResolvedCIDR,
	uids UIDs,
) {
	natChain := conn.AddChain(&nftables.Chain{
		Name:     "nat_output",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
	})

	allCIDRs := slices.Concat(cidr4, cidr6)

	// 1. Deny CIDR NAT ACCEPT (prevent redirect for denied CIDRs).
	addDenyCIDRNATAccept(conn, table, natChain, denyCIDRs, uids)

	// 2. Allow CIDR NAT REDIRECT (redirect TCP to CIDR catch-all).
	addCIDRNATRedirect(conn, table, natChain, allCIDRs, uids)

	// 3. Per-port FQDN REDIRECT rules.
	for _, p := range resolvedPorts {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: natChain,
			Exprs: flatExprs(
				matchUID(uids.Terrarium),
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
				matchUID(uids.Terrarium),
				matchL4Proto(unix.IPPROTO_TCP),
				matchDstPort(port16(fwd.Port)),
				redirectToPort(port16(config.ProxyPortBase+fwd.Port)),
			),
		})
	}

	// 5. Catch-all TCP REDIRECT -> catch-all TCP listener.
	// Traffic is logged and then rejected by Envoy (not forwarded).
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: natChain,
		Exprs: flatExprs(
			matchUID(uids.Terrarium),
			matchL4Proto(unix.IPPROTO_TCP),
			redirectToPort(port16(config.CatchAllProxyPort)),
		),
	})
}

// addUnrestrictedNAT creates a NAT chain for unrestricted mode that
// redirects port 80, 443, TCPForward, and catch-all TCP traffic
// through Envoy for centralized access logging.
func addUnrestrictedNAT(conn Conn, table *nftables.Table, cfg *config.Config, uids UIDs) {
	natChain := conn.AddChain(&nftables.Chain{
		Name:     "nat_output",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
	})

	// 1. Port 80 -> HTTP forward proxy.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: natChain,
		Exprs: flatExprs(
			matchUID(uids.Terrarium),
			matchL4Proto(unix.IPPROTO_TCP),
			matchDstPort(80),
			redirectToPort(15080),
		),
	})

	// 2. Port 443 -> TLS passthrough.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: natChain,
		Exprs: flatExprs(
			matchUID(uids.Terrarium),
			matchL4Proto(unix.IPPROTO_TCP),
			matchDstPort(443),
			redirectToPort(15443),
		),
	})

	// 3. TCPForward REDIRECTs.
	for _, fwd := range cfg.TCPForwards {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: natChain,
			Exprs: flatExprs(
				matchUID(uids.Terrarium),
				matchL4Proto(unix.IPPROTO_TCP),
				matchDstPort(port16(fwd.Port)),
				redirectToPort(port16(config.ProxyPortBase+fwd.Port)),
			),
		})
	}

	// 4. Catch-all TCP -> ORIGINAL_DST listener.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: natChain,
		Exprs: flatExprs(
			matchUID(uids.Terrarium),
			matchL4Proto(unix.IPPROTO_TCP),
			redirectToPort(port16(config.CatchAllProxyPort)),
		),
	})
}

// addDenyCIDRNATAccept creates per-rule deny CIDR chains in the NAT
// context. Each chain uses ACCEPT (instead of DROP) to skip NAT
// modification so the filter chain's deny rules DROP the traffic.
// ACCEPT in a jumped-to chain terminates the base chain, preventing
// subsequent allow REDIRECT rules from firing.
//
// This mirrors [addDenyCIDRChains] (filter) but in the NAT context.
// Because NAT fires before filter in the OUTPUT hook (priority -100
// vs 0), deny CIDRs must be enforced here to prevent denied traffic
// from being redirected to Envoy and forwarded via original_dst.
func addDenyCIDRNATAccept(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR, uids UIDs,
) {
	addDenyCIDRChainsWithVerdict(conn, table, parentChain, cidrs, uids, "deny_cidr_nat", expr.VerdictAccept)
}

// addCIDRNATRedirect creates per-rule CIDR chains in the NAT context
// and adds jumps from the parent chain. Each chain evaluates one
// rule's CIDRs: RETURN for except hits (excepted subnets skip this
// rule's redirect), REDIRECT for TCP CIDR hits (redirect to the CIDR
// catch-all listener for forwarding via original_dst). Non-TCP traffic
// has no NAT rules and implicitly returns from the chain (UDP is
// handled by TPROXY in the mangle chain instead).
//
// Rules with serverNames are skipped entirely (they already fall to
// per-port REDIRECT for SNI inspection). Individual L7 port entries
// are also skipped (they fall to per-port REDIRECT for HTTP filtering).
// Only TCP protocol entries emit REDIRECT rules; UDP uses TPROXY
// (not NAT REDIRECT).
func addCIDRNATRedirect(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR, uids UIDs,
) {
	groups := groupCIDRsByRule(cidrs)

	for i, group := range groups {
		if !slices.ContainsFunc(group, cidrNeedsTCPRedirect) {
			continue
		}

		chainName := fmt.Sprintf("cidr_nat_%d", i)
		chain := conn.AddChain(&nftables.Chain{
			Name:  chainName,
			Table: table,
		})

		// Except RETURNs: excepted subnets skip this rule's
		// redirect. TCP-only matching mirrors the redirect rules
		// below so non-TCP traffic returns from the chain unaffected
		// (UDP uses TPROXY instead of NAT REDIRECT).
		for _, rule := range group {
			if !cidrNeedsTCPRedirect(rule) {
				continue
			}

			for _, exc := range rule.Except {
				_, excNet, err := net.ParseCIDR(exc)
				if err != nil {
					continue
				}

				addCIDRNATTCPRules(conn, table, chain, rule, uids, excNet, verdictExprs(expr.VerdictReturn))
			}
		}

		// CIDR REDIRECTs: redirect matching TCP to CIDR catch-all.
		for _, rule := range group {
			if !cidrNeedsTCPRedirect(rule) {
				continue
			}

			_, cidrNet, err := net.ParseCIDR(rule.CIDR)
			if err != nil {
				continue
			}

			addCIDRNATTCPRules(conn, table, chain, rule, uids, cidrNet, redirectToPort(port16(config.CIDRCatchAllPort)))
		}

		// Jump from parent chain.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: parentChain,
			Exprs: flatExprs(verdictExprs(expr.VerdictJump, chainName)),
		})
	}
}

// cidrNeedsTCPRedirect reports whether a resolved CIDR rule has TCP
// ports eligible for NAT redirect. Rules with serverNames are handled
// by per-port SNI redirect. L7 ports are handled by per-port HTTP
// redirect. A portless rule (all-port) always needs redirect.
func cidrNeedsTCPRedirect(rule config.ResolvedCIDR) bool {
	if len(rule.ServerNames) > 0 {
		return false
	}

	if len(rule.Ports) == 0 {
		return true
	}

	for _, pp := range rule.Ports {
		if !rule.L7Ports[pp.Port] && pp.Protocol == config.ProtoTCP {
			return true
		}
	}

	return false
}

// addCIDRNATTCPRules emits nftables rules for a single CIDR rule's
// TCP ports, matching the given cidrNet and applying the terminal
// expression (verdict or redirect). Portless rules emit a single
// all-TCP rule; port-scoped rules emit one rule per eligible TCP port.
func addCIDRNATTCPRules(
	conn Conn, table *nftables.Table, chain *nftables.Chain,
	rule config.ResolvedCIDR, uids UIDs, cidrNet *net.IPNet,
	terminal []expr.Any,
) {
	if len(rule.Ports) == 0 {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchUID(uids.Terrarium),
				matchL4Proto(unix.IPPROTO_TCP),
				matchDstCIDR(cidrNet),
				terminal,
			),
		})

		return
	}

	for _, pp := range rule.Ports {
		if rule.L7Ports[pp.Port] || pp.Protocol != config.ProtoTCP {
			continue
		}

		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchUID(uids.Terrarium),
				matchL4Proto(unix.IPPROTO_TCP),
				matchDstPortOrRange(port16(pp.Port), port16(pp.EndPort)),
				matchDstCIDR(cidrNet),
				terminal,
			),
		})
	}
}

// addMangleOutputChain creates a route-type output chain at mangle
// priority that marks all terrarium-UID UDP packets (except port 53)
// with the TPROXY fwmark. The route chain type triggers a re-route
// lookup after marking, sending packets through loopback via policy
// routing. Port 53 is excluded because DNS must reach the DNS proxy
// directly.
//
// Although this chain fires at mangle priority (-150) before the
// filter output chain at priority 0, the route chain type only
// triggers a re-route lookup -- it does not bypass subsequent OUTPUT
// hook chains. The filter chain still evaluates and DROPs non-policy
// UDP ports before packets reach loopback and TPROXY. Only traffic
// ACCEPTed by the filter chain reaches the catch-all UDP listener.
func addMangleOutputChain(conn Conn, table *nftables.Table, uids UIDs) {
	chain := conn.AddChain(&nftables.Chain{
		Name:     "mangle_output",
		Table:    table,
		Type:     nftables.ChainTypeRoute,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityMangle,
	})

	// Mark terrarium UDP (except port 53) with tproxyMark.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchUID(uids.Terrarium),
			matchL4Proto(unix.IPPROTO_UDP),
			notMatchDstPort(53),
			markPacket(tproxyMark),
		),
	})
}

// addManglePreRoutingChain creates a filter-type prerouting chain at
// mangle priority that applies TPROXY to marked UDP packets. Per-AF
// rules are used (IPv4 and IPv6 separately) matching the codebase's
// convention in matchDstCIDR.
func addManglePreRoutingChain(conn Conn, table *nftables.Table, port uint16) {
	chain := conn.AddChain(&nftables.Chain{
		Name:     "mangle_prerouting",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
	})

	// IPv4: match fwmark + UDP -> TPROXY to port.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchMark(tproxyMark),
			matchL4Proto(unix.IPPROTO_UDP),
			matchNFProto(unix.NFPROTO_IPV4),
			tproxyToPort(unix.NFPROTO_IPV4, port),
		),
	})

	// IPv6: match fwmark + UDP -> TPROXY to port.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchMark(tproxyMark),
			matchL4Proto(unix.IPPROTO_UDP),
			matchNFProto(unix.NFPROTO_IPV6),
			tproxyToPort(unix.NFPROTO_IPV6, port),
		),
	})
}

// addDenyICMPRules emits DROP rules for deny ICMP entries. When an
// entry has CIDRs (L3 scope from sibling selectors), a per-rule
// chain is created with CIDR-scoped DROPs and except RETURNs,
// mirroring [addDenyCIDRChains]. Standalone entries (nil CIDRs)
// are emitted flat on the parent chain. Deny ICMP rules are
// evaluated before allow ICMP rules (deny precedence).
func addDenyICMPRules(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	icmps []config.ResolvedICMP, uids UIDs,
) {
	addICMPVerdictRules(conn, table, parentChain, icmps, nil, uids, "deny_icmp", expr.VerdictDrop)
}

// addICMPRules emits ACCEPT rules for allow ICMP entries. When an
// entry has CIDRs (L3 scope from sibling selectors), a per-rule
// chain is created with CIDR-scoped ACCEPTs and except RETURNs,
// mirroring [addCIDRChains]. When an entry uses FQDN sets, an
// ESTABLISHED rule and set lookup rules are emitted. Standalone
// entries (nil CIDRs, no FQDN) are emitted flat on the parent chain.
func addICMPRules(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	icmps []config.ResolvedICMP, icmpFQDNSets map[int]setRef, uids UIDs,
) {
	addICMPVerdictRules(conn, table, parentChain, icmps, icmpFQDNSets, uids, "icmp", expr.VerdictAccept)
}

// addICMPVerdictRules is the shared implementation for
// [addDenyICMPRules] and [addICMPRules]. It emits per-entry rules
// with the given verdict kind. The chainPrefix names per-entry
// sub-chains for CIDR-scoped entries. When icmpFQDNSets is non-nil
// and an entry has UseFQDNSet, ESTABLISHED and set lookup rules are
// emitted instead of CIDR chain dispatch.
func addICMPVerdictRules(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	icmps []config.ResolvedICMP, icmpFQDNSets map[int]setRef, uids UIDs,
	chainPrefix string, verdict expr.VerdictKind,
) {
	chainIdx := 0

	for _, icmp := range icmps {
		nfProto, l4Proto := icmpProtos(icmp.Family)

		// FQDN set branch: ESTABLISHED + set lookup.
		if icmp.UseFQDNSet && icmpFQDNSets != nil {
			ref, ok := icmpFQDNSets[icmp.FQDNRuleIndex]
			if !ok {
				continue
			}

			// ESTABLISHED scoped to ICMP proto + type.
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: parentChain,
				Exprs: flatExprs(
					matchUID(uids.Terrarium),
					matchNFProto(nfProto),
					matchL4Proto(l4Proto),
					matchICMPType(icmp.Type),
					matchCtState(expr.CtStateBitESTABLISHED),
					verdictExprs(verdict),
				),
			})

			// Set lookup for the correct address family.
			var set *nftables.Set
			if icmp.Family == config.FamilyIPv6 {
				set = ref.set6
			} else {
				set = ref.set4
			}

			conn.AddRule(&nftables.Rule{
				Table: table, Chain: parentChain,
				Exprs: flatExprs(
					matchNFProto(nfProto),
					matchUID(uids.Terrarium),
					matchL4Proto(l4Proto),
					matchICMPType(icmp.Type),
					setLookupDst(set),
					verdictExprs(verdict),
				),
			})

			continue
		}

		if len(icmp.CIDRs) == 0 {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: parentChain,
				Exprs: flatExprs(
					matchUID(uids.Terrarium),
					matchNFProto(nfProto),
					matchL4Proto(l4Proto),
					matchICMPType(icmp.Type),
					verdictExprs(verdict),
				),
			})

			continue
		}

		chainName := fmt.Sprintf("%s_%d", chainPrefix, chainIdx)
		chainIdx++

		chain := conn.AddChain(&nftables.Chain{
			Name:  chainName,
			Table: table,
		})

		addICMPCIDRRules(conn, table, chain, icmp, nfProto, l4Proto, uids, verdict)

		conn.AddRule(&nftables.Rule{
			Table: table, Chain: parentChain,
			Exprs: flatExprs(verdictExprs(expr.VerdictJump, chainName)),
		})
	}
}

// addICMPCIDRRules emits except RETURN and CIDR verdict rules for a
// single CIDR-scoped ICMP entry on the given chain. Used by both
// allow and deny ICMP rule generation.
func addICMPCIDRRules(
	conn Conn, table *nftables.Table, chain *nftables.Chain,
	icmp config.ResolvedICMP, nfProto, l4Proto byte, uids UIDs,
	verdict expr.VerdictKind,
) {
	// Except RETURNs first.
	for _, cidr := range icmp.CIDRs {
		for _, exc := range cidr.Except {
			_, excNet, err := net.ParseCIDR(exc)
			if err != nil {
				continue
			}

			conn.AddRule(&nftables.Rule{
				Table: table, Chain: chain,
				Exprs: flatExprs(
					matchUID(uids.Terrarium),
					matchNFProto(nfProto),
					matchL4Proto(l4Proto),
					matchICMPType(icmp.Type),
					matchDstCIDR(excNet),
					verdictExprs(expr.VerdictReturn),
				),
			})
		}
	}

	// CIDR match rules.
	for _, cidr := range icmp.CIDRs {
		_, cidrNet, err := net.ParseCIDR(cidr.CIDR)
		if err != nil {
			continue
		}

		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchUID(uids.Terrarium),
				matchNFProto(nfProto),
				matchL4Proto(l4Proto),
				matchICMPType(icmp.Type),
				matchDstCIDR(cidrNet),
				verdictExprs(verdict),
			),
		})
	}
}

// icmpProtos returns the nfproto and l4proto byte values for a given
// ICMP address family string.
func icmpProtos(family string) (byte, byte) {
	if family == config.FamilyIPv6 {
		return unix.NFPROTO_IPV6, unix.IPPROTO_ICMPV6
	}

	return unix.NFPROTO_IPV4, unix.IPPROTO_ICMP
}

// addCatchAllFQDNRules adds per-rule FQDN set lookup rules that ACCEPT
// traffic matching the FQDN ipset on any port and protocol. These rules
// enforce catch-all FQDN rules (toFQDNs without toPorts) at the IP
// level, matching how Cilium's datapath handles portless FQDN selectors.
// For TCP, traffic is also captured by the catch-all NAT REDIRECT for
// access logging via Envoy, but the ACCEPT here is the security decision.
func addCatchAllFQDNRules(
	conn Conn,
	table *nftables.Table,
	chain *nftables.Chain,
	ruleIndices []int,
	sets map[int]setRef,
	uids UIDs,
) {
	for _, ruleIdx := range ruleIndices {
		ref := sets[ruleIdx]

		// ESTABLISHED first (zombie/CT semantics).
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchUID(uids.Terrarium),
				matchCtState(expr.CtStateBitESTABLISHED),
				verdictExprs(expr.VerdictAccept),
			),
		})

		// Set lookup (v4) -- any port, any protocol.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNFProto(unix.NFPROTO_IPV4),
				matchUID(uids.Terrarium),
				setLookupDst(ref.set4),
				verdictExprs(expr.VerdictAccept),
			),
		})

		// Set lookup (v6) -- any port, any protocol.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNFProto(unix.NFPROTO_IPV6),
				matchUID(uids.Terrarium),
				setLookupDst(ref.set6),
				verdictExprs(expr.VerdictAccept),
			),
		})
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
