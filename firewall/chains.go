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

// matchFilteredTraffic returns UID-match expressions that scope a
// rule to policy-evaluated traffic. In container mode this matches
// the single Terrarium UID; in VM mode it returns nil so the
// calling rule applies to all UIDs (Envoy and Root are excluded by
// dedicated ACCEPT rules earlier in the chain).
//
// Note: the postrouting guard uses [matchHasSocketOwner] instead of
// this function in VM mode so that forwarded packets (no socket
// owner) pass through after being policy-evaluated in the FORWARD
// chain.
func matchFilteredTraffic(uids UIDs) []expr.Any {
	if uids.VMMode {
		return nil
	}

	return matchUID(uids.Terrarium)
}

func addInputChain(conn Conn, table *nftables.Table, uids UIDs) {
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

	// VM mode: accept DNATted forwarded traffic (TCP + DNS) that was
	// redirected to 127.0.0.1 by NAT PREROUTING. Without this rule,
	// forwarded packets arriving on INPUT after DNAT would be dropped
	// by the chain policy.
	if uids.VMMode {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchCtStatusDNAT(),
				verdictExprs(expr.VerdictAccept),
			),
		})

		// Accept TPROXY-marked forwarded traffic. TPROXY assigns the
		// socket in mangle PREROUTING but the packet must still pass
		// INPUT for delivery. Covers IPv6 forwarded TCP/DNS and
		// fixes a latent gap for existing forwarded UDP TPROXY.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchMark(tproxyMark),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}

	// Default DROP via chain policy.
}

// addOutputBaseRules emits the initial OUTPUT rules that appear in all
// three modes: loopback interface accept and loopback CIDR accept
// (nfproto-scoped). When excludeMark is non-zero (filtered mode),
// the blanket oifname "lo" accept is omitted entirely. Traffic to
// non-loopback IPs routed through lo (e.g., the VM's own address)
// must reach policy evaluation so deny rules can fire. The CIDR
// rules below still accept traffic to 127.0.0.0/8 and ::1.
func addOutputBaseRules(conn Conn, table *nftables.Table, chain *nftables.Chain, excludeMark uint32) {
	// 1. Allow loopback interface (unrestricted/blocked modes only).
	// In filtered mode, skip this rule so traffic to non-loopback IPs
	// on lo reaches the terrarium_output policy chain.
	if excludeMark == 0 {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchOIFName("lo"),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}

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
							matchFilteredTraffic(uids),
							matchDstCIDR(excNet),
							verdictExprs(expr.VerdictReturn),
						),
					})
				} else {
					for _, pp := range rule.Ports {
						conn.AddRule(&nftables.Rule{
							Table: table, Chain: chain,
							Exprs: flatExprs(
								matchFilteredTraffic(uids),
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
						matchFilteredTraffic(uids),
						matchDstCIDR(cidrNet),
						verdictExprs(verdict),
					),
				})
			} else {
				for _, pp := range rule.Ports {
					conn.AddRule(&nftables.Rule{
						Table: table, Chain: chain,
						Exprs: flatExprs(
							matchFilteredTraffic(uids),
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
					matchFilteredTraffic(uids),
					verdictExprs(expr.VerdictDrop),
				),
			})
		} else {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: parentChain,
				Exprs: flatExprs(
					matchFilteredTraffic(uids),
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
							matchFilteredTraffic(uids),
							matchDstCIDR(excNet),
							verdictExprs(expr.VerdictReturn),
						),
					})
				} else {
					for _, pp := range rule.Ports {
						conn.AddRule(&nftables.Rule{
							Table: table, Chain: chain,
							Exprs: flatExprs(
								matchFilteredTraffic(uids),
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
						matchFilteredTraffic(uids),
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
							matchFilteredTraffic(uids),
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
				matchFilteredTraffic(uids),
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
				matchFilteredTraffic(uids),
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
				matchFilteredTraffic(uids),
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
				matchFilteredTraffic(uids),
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
				matchFilteredTraffic(uids),
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

	// VM mode: skip Envoy and root traffic to prevent redirect
	// loops (Envoy) and allow DNS proxy upstream queries (root).
	if uids.VMMode {
		for _, uid := range []uint32{uids.Envoy, uids.Root} {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: natChain,
				Exprs: flatExprs(
					matchUID(uid),
					verdictExprs(expr.VerdictAccept),
				),
			})
		}
	}

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
				matchFilteredTraffic(uids),
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
				matchFilteredTraffic(uids),
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
			matchFilteredTraffic(uids),
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

	// VM mode: skip Envoy and root traffic to prevent redirect
	// loops (Envoy) and allow DNS proxy upstream queries (root).
	if uids.VMMode {
		for _, uid := range []uint32{uids.Envoy, uids.Root} {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: natChain,
				Exprs: flatExprs(
					matchUID(uid),
					verdictExprs(expr.VerdictAccept),
				),
			})
		}
	}

	// 1. Port 80 -> HTTP forward proxy.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: natChain,
		Exprs: flatExprs(
			matchFilteredTraffic(uids),
			matchL4Proto(unix.IPPROTO_TCP),
			matchDstPort(80),
			redirectToPort(15080),
		),
	})

	// 2. Port 443 -> TLS passthrough.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: natChain,
		Exprs: flatExprs(
			matchFilteredTraffic(uids),
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
				matchFilteredTraffic(uids),
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
			matchFilteredTraffic(uids),
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
	buildCIDRTCPChains(conn, table, parentChain, cidrs,
		"cidr_nat", matchFilteredTraffic(uids),
		redirectToPort(port16(config.CIDRCatchAllPort)), nil)
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

// emitCIDRTCPRules emits nftables rules for a single CIDR rule's TCP
// ports, matching the given cidrNet and applying the terminal
// expression (verdict, redirect, or TPROXY). Portless rules emit a
// single all-TCP rule; port-scoped rules emit one rule per eligible
// TCP port. The prefix expressions are prepended to each rule (e.g.
// UID matching for NAT paths, or nil for TPROXY paths where the
// parent chain jump already scopes the traffic).
func emitCIDRTCPRules(
	conn Conn, table *nftables.Table, chain *nftables.Chain,
	rule config.ResolvedCIDR, prefix []expr.Any, cidrNet *net.IPNet,
	terminal []expr.Any,
) {
	if len(rule.Ports) == 0 {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				prefix,
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
				prefix,
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

	// VM mode: skip Envoy and root UDP so their traffic is not
	// rerouted through TPROXY.
	if uids.VMMode {
		for _, uid := range []uint32{uids.Envoy, uids.Root} {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: chain,
				Exprs: flatExprs(
					matchUID(uid),
					verdictExprs(expr.VerdictAccept),
				),
			})
		}
	}

	// Mark filtered UDP (except port 53) with tproxyMark.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchFilteredTraffic(uids),
			matchL4Proto(unix.IPPROTO_UDP),
			notMatchDstPort(53),
			markPacket(tproxyMark),
		),
	})
}

// addManglePreRoutingChain creates a filter-type prerouting chain at
// mangle priority that applies TPROXY to marked UDP packets. Per-AF
// rules are used (IPv4 and IPv6 separately) matching the codebase's
// convention in matchDstCIDR. In VM mode, forwarded UDP and IPv6 TCP
// packets are also marked for TPROXY interception before the dispatch
// rules. IPv6 forwarded TCP uses TPROXY because Linux has no
// route_localnet equivalent for IPv6 (DNAT to 127.0.0.1 only works
// for IPv4).
func addManglePreRoutingChain(
	conn Conn, table *nftables.Table,
	udpPort uint16,
	resolvedPorts []int,
	tcpForwards []config.TCPForward,
	cidr6, denyCIDR6 []config.ResolvedCIDR,
	uids UIDs,
) {
	chain := conn.AddChain(&nftables.Chain{
		Name:     "mangle_prerouting",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
	})

	// VM mode: mark forwarded traffic for TPROXY interception.
	// These marking rules fire before the dispatch rules below.
	if uids.VMMode {
		// IPv4 forwarded UDP: mark for TPROXY, excluding port 53
		// (IPv4 DNS uses DNAT in NAT PREROUTING).
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNFProto(unix.NFPROTO_IPV4),
				matchNotIIFName("lo"),
				matchNotLocalDst(),
				matchL4Proto(unix.IPPROTO_UDP),
				notMatchDstPort(53),
				markPacket(tproxyMark),
			),
		})

		// IPv6 forwarded UDP: mark for TPROXY, including port 53
		// (IPv6 DNS must use TPROXY since there is no route_localnet).
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNFProto(unix.NFPROTO_IPV6),
				matchNotIIFName("lo"),
				matchNotLocalDst(),
				matchL4Proto(unix.IPPROTO_UDP),
				markPacket(tproxyMark),
			),
		})

		// IPv6 forwarded TCP: mark for TPROXY. IPv4 TCP uses DNAT
		// in NAT PREROUTING via route_localnet.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNFProto(unix.NFPROTO_IPV6),
				matchNotIIFName("lo"),
				matchNotLocalDst(),
				matchL4Proto(unix.IPPROTO_TCP),
				markPacket(tproxyMark),
			),
		})

		// IPv6 DNS TPROXY (UDP + TCP port 53) -> DNS proxy.
		// Must appear before the generic UDP/TCP TPROXY rules.
		for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: chain,
				Exprs: flatExprs(
					matchMark(tproxyMark),
					matchNFProto(unix.NFPROTO_IPV6),
					matchL4Proto(proto),
					matchDstPort(53),
					tproxyToPort(unix.NFPROTO_IPV6, 53),
				),
			})
		}

		// IPv6 deny CIDR: ACCEPT to skip TPROXY so traffic falls
		// to the FORWARD chain for policy DROP. Uses per-rule
		// chains with except RETURNs and port scoping, mirroring
		// addDenyCIDRChainsWithVerdict for the IPv4 NAT path.
		addIPv6DenyCIDRTPROXYSkip(conn, table, chain, denyCIDR6)

		// IPv6 allow CIDR + TCP -> TPROXY to CIDR catch-all port.
		// Uses per-rule chains with except RETURNs, port scoping,
		// and serverName/L7 skipping, mirroring addCIDRNATRedirect.
		addIPv6AllowCIDRTPROXY(conn, table, chain, cidr6)

		// IPv6 per-port TCP -> TPROXY to ProxyPortBase+port.
		for _, p := range resolvedPorts {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: chain,
				Exprs: flatExprs(
					matchMark(tproxyMark),
					matchNFProto(unix.NFPROTO_IPV6),
					matchL4Proto(unix.IPPROTO_TCP),
					matchDstPort(port16(p)),
					tproxyToPort(unix.NFPROTO_IPV6, port16(config.ProxyPortBase+p)),
				),
			})
		}

		// IPv6 TCPForward -> TPROXY to ProxyPortBase+fwd.Port.
		for _, fwd := range tcpForwards {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: chain,
				Exprs: flatExprs(
					matchMark(tproxyMark),
					matchNFProto(unix.NFPROTO_IPV6),
					matchL4Proto(unix.IPPROTO_TCP),
					matchDstPort(port16(fwd.Port)),
					tproxyToPort(unix.NFPROTO_IPV6, port16(config.ProxyPortBase+fwd.Port)),
				),
			})
		}

		// IPv6 catch-all TCP -> TPROXY to catch-all proxy port.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchMark(tproxyMark),
				matchNFProto(unix.NFPROTO_IPV6),
				matchL4Proto(unix.IPPROTO_TCP),
				tproxyToPort(unix.NFPROTO_IPV6, port16(config.CatchAllProxyPort)),
			),
		})
	}

	// IPv4: match fwmark + UDP -> TPROXY to port.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchMark(tproxyMark),
			matchL4Proto(unix.IPPROTO_UDP),
			matchNFProto(unix.NFPROTO_IPV4),
			tproxyToPort(unix.NFPROTO_IPV4, udpPort),
		),
	})

	// IPv6: match fwmark + UDP -> TPROXY to port.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchMark(tproxyMark),
			matchL4Proto(unix.IPPROTO_UDP),
			matchNFProto(unix.NFPROTO_IPV6),
			tproxyToPort(unix.NFPROTO_IPV6, udpPort),
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
					matchFilteredTraffic(uids),
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
					matchFilteredTraffic(uids),
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
					matchFilteredTraffic(uids),
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
					matchFilteredTraffic(uids),
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
				matchFilteredTraffic(uids),
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
				matchFilteredTraffic(uids),
				matchCtState(expr.CtStateBitESTABLISHED),
				verdictExprs(expr.VerdictAccept),
			),
		})

		// Set lookup (v4) -- any port, any protocol.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNFProto(unix.NFPROTO_IPV4),
				matchFilteredTraffic(uids),
				setLookupDst(ref.set4),
				verdictExprs(expr.VerdictAccept),
			),
		})

		// Set lookup (v6) -- any port, any protocol.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNFProto(unix.NFPROTO_IPV6),
				matchFilteredTraffic(uids),
				setLookupDst(ref.set6),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}
}

// addPostroutingGuard creates a filter-type POSTROUTING chain that
// drops filtered traffic leaving on non-loopback interfaces.
// NAT REDIRECT (TCP) and TPROXY (UDP) route traffic to Envoy on
// loopback; this chain catches any traffic that escapes those
// mechanisms, providing belt-and-suspenders enforcement that all
// filtered egress flows through Envoy.
//
// In container mode the chain uses policy ACCEPT so non-terrarium
// traffic (Envoy UID, root DNS proxy, kernel ICMP) passes through
// unaffected. In VM mode, explicit Envoy and root ACCEPT rules are
// added because matchFilteredTraffic matches all UIDs.
func addPostroutingGuard(conn Conn, table *nftables.Table, logging bool, uids UIDs) {
	policy := nftables.ChainPolicyAccept
	chain := conn.AddChain(&nftables.Chain{
		Name:     "postrouting_guard",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})

	// VM mode: Envoy and root legitimately send to non-loopback
	// (Envoy proxies to upstream, root forwards DNS queries).
	if uids.VMMode {
		for _, uid := range []uint32{uids.Envoy, uids.Root} {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: chain,
				Exprs: flatExprs(
					matchUID(uid),
					verdictExprs(expr.VerdictAccept),
				),
			})
		}
	}

	// In VM mode, use matchHasSocketOwner so forwarded packets (no
	// socket owner) pass through -- they were already policy-evaluated
	// in the FORWARD chain. In container mode, use matchFilteredTraffic
	// to scope to the Terrarium UID.
	trafficMatch := matchFilteredTraffic(uids)
	if uids.VMMode {
		trafficMatch = matchHasSocketOwner()
	}

	if logging {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				trafficMatch,
				notMatchOIFName("lo"),
				logPrefix("TERRARIUM_EGRESS_LEAK: "),
			),
		})
	}

	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			trafficMatch,
			notMatchOIFName("lo"),
			verdictExprs(expr.VerdictDrop),
		),
	})
}

// forwardGuardExprs returns the common match expressions for
// PREROUTING/FORWARD rules targeting forwarded traffic: non-loopback
// input interface, non-local destination, and IPv4 protocol.
func forwardGuardExprs() []expr.Any {
	return flatExprs(
		matchNotIIFName("lo"),
		matchNotLocalDst(),
		matchNFProto(unix.NFPROTO_IPV4),
	)
}

// addNATPreRouting creates a NAT PREROUTING chain for VM mode that
// DNATs forwarded IPv4 TCP and DNS traffic to 127.0.0.1 for Envoy
// and DNS proxy interception. All rules are scoped to non-loopback
// input, non-local destination, and IPv4 (no route_localnet equivalent
// for IPv6).
func addNATPreRouting(
	conn Conn, table *nftables.Table, cfg *config.Config,
	resolvedPorts []int, cidr4, denyCIDRs []config.ResolvedCIDR,
	uids UIDs,
) {
	chain := conn.AddChain(&nftables.Chain{
		Name:     "nat_prerouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	guard := forwardGuardExprs()

	// 1. DNS DNAT: UDP/TCP port 53 -> DNS proxy.
	for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				guard,
				matchL4Proto(proto),
				matchDstPort(53),
				dnatToLocal(53),
			),
		})
	}

	// 2. Deny CIDR NAT ACCEPT (prevent redirect for denied CIDRs).
	// Filter to IPv4-only deny CIDRs for PREROUTING.
	var deny4 []config.ResolvedCIDR
	for _, c := range denyCIDRs {
		_, ipNet, err := net.ParseCIDR(c.CIDR)
		if err != nil {
			continue
		}

		if ipNet.IP.To4() != nil {
			deny4 = append(deny4, c)
		}
	}

	addDenyCIDRChainsWithVerdict(conn, table, chain, deny4, uids,
		"deny_cidr_nat_pre", expr.VerdictAccept)

	// 3. Allow CIDR DNAT to CIDR catch-all port. Per-rule chains
	// with except RETURNs mirror addCIDRNATRedirect so excepted
	// subnets are not DNATted to Envoy.
	addCIDRNATPreRoutingDNAT(conn, table, chain, cidr4, uids)

	// 4. Per-port FQDN DNAT.
	for _, p := range resolvedPorts {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				guard,
				matchL4Proto(unix.IPPROTO_TCP),
				matchDstPort(port16(p)),
				dnatToLocal(port16(config.ProxyPortBase+p)),
			),
		})
	}

	// 5. TCPForward DNAT.
	for _, fwd := range cfg.TCPForwards {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				guard,
				matchL4Proto(unix.IPPROTO_TCP),
				matchDstPort(port16(fwd.Port)),
				dnatToLocal(port16(config.ProxyPortBase+fwd.Port)),
			),
		})
	}

	// 6. Catch-all TCP DNAT -> blackhole listener.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			guard,
			matchL4Proto(unix.IPPROTO_TCP),
			dnatToLocal(port16(config.CatchAllProxyPort)),
		),
	})
}

// addUnrestrictedNATPreRouting creates a NAT PREROUTING chain for
// VM mode unrestricted policy. DNATs forwarded IPv4 TCP traffic to
// Envoy for access logging (port 80 -> 15080, 443 -> 15443,
// TCPForwards, and catch-all).
func addUnrestrictedNATPreRouting(conn Conn, table *nftables.Table, cfg *config.Config) {
	chain := conn.AddChain(&nftables.Chain{
		Name:     "nat_prerouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	guard := forwardGuardExprs()

	// 1. DNS DNAT.
	for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				guard,
				matchL4Proto(proto),
				matchDstPort(53),
				dnatToLocal(53),
			),
		})
	}

	// 2. Port 80 -> HTTP forward proxy.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			guard,
			matchL4Proto(unix.IPPROTO_TCP),
			matchDstPort(80),
			dnatToLocal(15080),
		),
	})

	// 3. Port 443 -> TLS passthrough.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			guard,
			matchL4Proto(unix.IPPROTO_TCP),
			matchDstPort(443),
			dnatToLocal(15443),
		),
	})

	// 4. TCPForward DNAT.
	for _, fwd := range cfg.TCPForwards {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				guard,
				matchL4Proto(unix.IPPROTO_TCP),
				matchDstPort(port16(fwd.Port)),
				dnatToLocal(port16(config.ProxyPortBase+fwd.Port)),
			),
		})
	}

	// 5. Catch-all TCP DNAT.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			guard,
			matchL4Proto(unix.IPPROTO_TCP),
			dnatToLocal(port16(config.CatchAllProxyPort)),
		),
	})
}

// addCIDRNATPreRoutingDNAT creates per-rule CIDR chains in the NAT
// PREROUTING context, mirroring [addCIDRNATRedirect] for the OUTPUT
// path. Each chain evaluates one rule's CIDRs: RETURN for except hits
// (excepted subnets skip this rule's DNAT), DNAT for TCP CIDR hits
// (DNAT to the CIDR catch-all listener). Uses [dnatToLocal] instead
// of [redirectToPort] because REDIRECT in PREROUTING would redirect
// to the incoming interface's address, not loopback.
func addCIDRNATPreRoutingDNAT(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR, uids UIDs,
) {
	buildCIDRTCPChains(conn, table, parentChain, cidrs,
		"cidr_nat_pre", matchFilteredTraffic(uids),
		dnatToLocal(port16(config.CIDRCatchAllPort)), nil)
}

// tproxyIPv6Guard returns the common match expressions for IPv6
// TPROXY dispatch rules in mangle PREROUTING: fwmark match and
// IPv6 protocol scope.
func tproxyIPv6Guard() []expr.Any {
	return flatExprs(
		matchMark(tproxyMark),
		matchNFProto(unix.NFPROTO_IPV6),
	)
}

// addIPv6DenyCIDRTPROXYSkip creates per-rule deny CIDR chains that
// ACCEPT (skip TPROXY) for denied IPv6 CIDRs. Traffic that skips
// TPROXY falls to the FORWARD chain where the filter deny rules DROP
// it. Mirrors [addDenyCIDRChainsWithVerdict] but scoped to IPv6
// TPROXY-marked traffic instead of UID-filtered traffic.
func addIPv6DenyCIDRTPROXYSkip(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR,
) {
	groups := groupCIDRsByRule(cidrs)
	guard := tproxyIPv6Guard()

	for i, group := range groups {
		chainName := fmt.Sprintf("deny_cidr_tproxy_%d", i)
		chain := conn.AddChain(&nftables.Chain{
			Name:  chainName,
			Table: table,
		})

		// Except RETURNs: don't skip TPROXY for these sub-ranges.
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
							matchDstCIDR(excNet),
							verdictExprs(expr.VerdictReturn),
						),
					})
				} else {
					for _, pp := range rule.Ports {
						conn.AddRule(&nftables.Rule{
							Table: table, Chain: chain,
							Exprs: flatExprs(
								matchPortProto(pp),
								matchDstCIDR(excNet),
								verdictExprs(expr.VerdictReturn),
							),
						})
					}
				}
			}
		}

		// CIDR ACCEPT: skip TPROXY for matching denied traffic.
		for _, rule := range group {
			_, cidrNet, err := net.ParseCIDR(rule.CIDR)
			if err != nil {
				continue
			}

			if len(rule.Ports) == 0 {
				conn.AddRule(&nftables.Rule{
					Table: table, Chain: chain,
					Exprs: flatExprs(
						matchDstCIDR(cidrNet),
						verdictExprs(expr.VerdictAccept),
					),
				})
			} else {
				for _, pp := range rule.Ports {
					conn.AddRule(&nftables.Rule{
						Table: table, Chain: chain,
						Exprs: flatExprs(
							matchPortProto(pp),
							matchDstCIDR(cidrNet),
							verdictExprs(expr.VerdictAccept),
						),
					})
				}
			}
		}

		// Jump from parent chain (scoped to IPv6 TPROXY traffic).
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: parentChain,
			Exprs: flatExprs(
				guard,
				verdictExprs(expr.VerdictJump, chainName),
			),
		})
	}
}

// addIPv6AllowCIDRTPROXY creates per-rule CIDR chains that TPROXY
// matching IPv6 TCP traffic to the CIDR catch-all listener. Mirrors
// [addCIDRNATRedirect] / [addCIDRNATPreRoutingDNAT] but uses TPROXY
// instead of REDIRECT/DNAT. Rules with serverNames or L7 ports are
// skipped (they fall to per-port TPROXY dispatch for SNI/HTTP
// filtering via Envoy).
func addIPv6AllowCIDRTPROXY(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR,
) {
	buildCIDRTCPChains(conn, table, parentChain, cidrs,
		"cidr_tproxy", nil,
		tproxyToPort(unix.NFPROTO_IPV6, port16(config.CIDRCatchAllPort)),
		tproxyIPv6Guard())
}

// buildCIDRTCPChains is the shared implementation for
// [addCIDRNATRedirect], [addCIDRNATPreRoutingDNAT], and
// [addIPv6AllowCIDRTPROXY]. It creates per-rule CIDR chains with
// except RETURNs and terminal expressions (redirect, DNAT, or
// TPROXY). The rulePrefix expressions are prepended to each rule
// inside the chain. The jumpGuard expressions are prepended to the
// jump rule on the parent chain (nil for an unconditional jump).
func buildCIDRTCPChains(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR,
	chainPrefix string, rulePrefix []expr.Any,
	terminal, jumpGuard []expr.Any,
) {
	groups := groupCIDRsByRule(cidrs)

	for i, group := range groups {
		if !slices.ContainsFunc(group, cidrNeedsTCPRedirect) {
			continue
		}

		chainName := fmt.Sprintf("%s_%d", chainPrefix, i)
		chain := conn.AddChain(&nftables.Chain{
			Name:  chainName,
			Table: table,
		})

		// Except RETURNs: excepted subnets skip this rule's
		// terminal action.
		for _, rule := range group {
			if !cidrNeedsTCPRedirect(rule) {
				continue
			}

			for _, exc := range rule.Except {
				_, excNet, err := net.ParseCIDR(exc)
				if err != nil {
					continue
				}

				emitCIDRTCPRules(conn, table, chain, rule, rulePrefix, excNet, verdictExprs(expr.VerdictReturn))
			}
		}

		// CIDR terminal: apply the action to matching TCP.
		for _, rule := range group {
			if !cidrNeedsTCPRedirect(rule) {
				continue
			}

			_, cidrNet, err := net.ParseCIDR(rule.CIDR)
			if err != nil {
				continue
			}

			emitCIDRTCPRules(conn, table, chain, rule, rulePrefix, cidrNet, terminal)
		}

		// Jump from parent chain.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: parentChain,
			Exprs: flatExprs(
				jumpGuard,
				verdictExprs(expr.VerdictJump, chainName),
			),
		})
	}
}

// addForwardChain creates a FORWARD chain for VM mode that
// policy-evaluates forwarded traffic. The chain handles established
// connections, ICMP RELATED, and jumps to the terrarium_output chain
// for new connection policy evaluation. Traffic not accepted by policy
// is dropped.
func addForwardChain(conn Conn, table *nftables.Table, terrariumChain *nftables.Chain) {
	policy := nftables.ChainPolicyDrop
	chain := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})

	// CT state established/related -> ACCEPT.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchCtState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED),
			verdictExprs(expr.VerdictAccept),
		),
	})

	// Per-type ICMP RELATED rules (same pattern as addOutputEstablishedAndICMP).
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

	// Jump to terrarium_output for policy evaluation.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			verdictExprs(expr.VerdictJump, terrariumChain.Name),
		),
	})

	// Terminal DROP via chain policy.
}

// addForwardChainUnrestricted creates a FORWARD chain for VM mode
// unrestricted policy that accepts all forwarded traffic after
// established/related checks.
func addForwardChainUnrestricted(conn Conn, table *nftables.Table) {
	policy := nftables.ChainPolicyDrop
	chain := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})

	// CT state established/related -> ACCEPT.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchCtState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED),
			verdictExprs(expr.VerdictAccept),
		),
	})

	// Accept all forwarded traffic.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			verdictExprs(expr.VerdictAccept),
		),
	})
}

// addForwardChainBlocked creates a FORWARD chain for VM mode blocked
// policy that drops all new forwarded traffic (only
// established/related is accepted for connection draining).
func addForwardChainBlocked(conn Conn, table *nftables.Table) {
	policy := nftables.ChainPolicyDrop
	chain := conn.AddChain(&nftables.Chain{
		Name:     "forward",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})

	// CT state established/related -> ACCEPT.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchCtState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED),
			verdictExprs(expr.VerdictAccept),
		),
	})

	// Terminal DROP via chain policy.
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
