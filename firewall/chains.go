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

// addDNSRedirect adds NAT REDIRECT rules for DNS (port 53, UDP +
// TCP) to the given chain. UIDs listed in [UIDs.ExcludeUIDs] get
// port-53 ACCEPT rules before the REDIRECT so they can reach upstream
// DNS servers without being looped back to the local proxy. The
// REDIRECT rules use [matchFilteredTraffic] for UID scoping: in
// container mode only the Terrarium UID is matched; in VM mode all
// UIDs are matched (Envoy and root are excluded by earlier ACCEPT
// rules in the chain).
func addDNSRedirect(conn Conn, table *nftables.Table, chain *nftables.Chain, uids UIDs) {
	// Let excluded UIDs (e.g., dnsmasq) bypass DNS interception.
	for _, uid := range uids.ExcludeUIDs {
		for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: chain,
				Exprs: flatExprs(
					matchUID(uid),
					matchL4Proto(proto),
					matchDstPort(53),
					verdictExprs(expr.VerdictAccept),
				),
			})
		}
	}

	for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchFilteredTraffic(uids),
				matchL4Proto(proto),
				matchDstPort(53),
				redirectToPort(53),
			),
		})
	}
}

// addOutputBaseRules emits the initial OUTPUT rules shared across all
// three security modes: the guard mark, loopback CIDR accepts
// (127.0.0.0/8 and ::1), and a conditional blanket oifname "lo" accept.
// When excludeMark is non-zero (filtered mode), the blanket oifname
// "lo" accept is omitted so that traffic to non-loopback IPs routed
// through lo (e.g., the VM's own address) reaches policy evaluation
// where deny rules can fire.
//
// The guard mark ([guardMark] 0x2) is set as the very first rule via
// [orMarkBit], before any loopback accepts. This ensures packets to
// non-loopback IPs routed through lo (e.g., the VM's own address)
// carry the mark into the external guard table even when the oifname
// "lo" accept short-circuits policy evaluation. The external guard
// table checks this bit to accept policy-evaluated packets without
// enumerating terrarium-internal details.
func addOutputBaseRules(conn Conn, table *nftables.Table, chain *nftables.Chain, excludeMark uint32) {
	// 1. Mark packet as policy-evaluated for the guard table.
	// Must be first so packets accepted by loopback rules below
	// still carry the mark into the external guard table.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: orMarkBit(guardMark),
	})

	// 2. Allow loopback interface (unrestricted/blocked modes only).
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

	// 3. Allow loopback CIDR (nfproto-scoped).
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

	// Excluded UID DNS queries (UDP + TCP port 53). These UIDs
	// bypass DNS NAT redirect (see [addDNSRedirect]) and need a
	// matching filter allow rule so their queries to external
	// upstream resolvers are not dropped by the output chain policy.
	for _, uid := range uids.ExcludeUIDs {
		for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: chain,
				Exprs: flatExprs(
					matchUID(uid),
					matchL4Proto(proto),
					matchDstPort(53),
					verdictExprs(expr.VerdictAccept),
				),
			})
		}
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

	// DNS REDIRECT: intercept all DNS (port 53, UDP + TCP) from
	// policy-evaluated traffic and send it to the local DNS proxy.
	addDNSRedirect(conn, table, natChain, uids)

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

	// DNS REDIRECT: intercept all DNS (port 53, UDP + TCP) from
	// policy-evaluated traffic and send it to the local DNS proxy.
	addDNSRedirect(conn, table, natChain, uids)

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
// convention in matchDstCIDR. In VM mode, forwarded UDP and TCP
// packets are also marked for TPROXY interception before the dispatch
// rules. Forwarded TCP uses TPROXY (instead of NAT PREROUTING DNAT)
// because br_netfilter prevents DNAT to 127.0.0.1 for
// bridge-forwarded TCP packets.
func addManglePreRoutingChain(
	conn Conn, table *nftables.Table,
	udpPort uint16,
	resolvedPorts []int,
	tcpForwards []config.TCPForward,
	cidr4, cidr6, denyCIDR4, denyCIDR6 []config.ResolvedCIDR,
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
	//
	// Each rule includes notMatchMark(guardMark) to exclude
	// locally-generated traffic that re-enters PREROUTING via
	// br_netfilter when traversing a bridge to a container. The
	// output filter chain sets guardMark on all locally-generated
	// packets; genuinely forwarded container traffic never passes
	// through OUTPUT and therefore has no guard mark.
	if uids.VMMode {
		// Accept established/related traffic before marking.
		// Return traffic for forwarded connections (e.g.,
		// SYN-ACK from a container on br-tproxy to a container
		// on cni0) must not be marked for TPROXY, otherwise the
		// catch-all TPROXY rule intercepts the reply and Envoy
		// receives a SYN-ACK for a connection it never opened.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNotIIFName("lo"),
				matchNotLocalDst(),
				matchCtState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED),
				verdictExprs(expr.VerdictAccept),
			),
		})

		// IPv4 forwarded UDP: mark for TPROXY, excluding port 53
		// (IPv4 DNS uses DNAT in NAT PREROUTING).
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				notMatchMark(guardMark),
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
				notMatchMark(guardMark),
				matchNFProto(unix.NFPROTO_IPV6),
				matchNotIIFName("lo"),
				matchNotLocalDst(),
				matchL4Proto(unix.IPPROTO_UDP),
				markPacket(tproxyMark),
			),
		})

		// Forwarded TCP: mark for TPROXY. IPv4 uses TPROXY instead
		// of DNAT because br_netfilter prevents DNAT to 127.0.0.1
		// for bridge-forwarded TCP (the bridge path does not re-route
		// DNATted packets through loopback).
		for _, nfProto := range []byte{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6} {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: chain,
				Exprs: flatExprs(
					notMatchMark(guardMark),
					matchNFProto(nfProto),
					matchNotIIFName("lo"),
					matchNotLocalDst(),
					matchL4Proto(unix.IPPROTO_TCP),
					markPacket(tproxyMark),
				),
			})
		}

		// IPv4 DNS TCP TPROXY -> DNS proxy. IPv4 DNS UDP uses DNAT
		// in NAT PREROUTING (UDP DNAT works with br_netfilter).
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchMark(tproxyMark),
				matchNFProto(unix.NFPROTO_IPV4),
				matchL4Proto(unix.IPPROTO_TCP),
				matchDstPort(53),
				tproxyToPort(unix.NFPROTO_IPV4, 53),
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

		// Deny CIDR: ACCEPT to skip TPROXY so traffic falls to the
		// FORWARD chain for policy DROP.
		addForwardedDenyCIDRTPROXYSkip(conn, table, chain, denyCIDR4, unix.NFPROTO_IPV4)
		addForwardedDenyCIDRTPROXYSkip(conn, table, chain, denyCIDR6, unix.NFPROTO_IPV6)

		// Allow CIDR + TCP -> TPROXY to CIDR catch-all port.
		addForwardedAllowCIDRSkipTPROXY(conn, table, chain, cidr4, unix.NFPROTO_IPV4)
		addForwardedAllowCIDRSkipTPROXY(conn, table, chain, cidr6, unix.NFPROTO_IPV6)

		// Per-port TCP -> TPROXY to ProxyPortBase+port.
		for _, p := range resolvedPorts {
			for _, nfProto := range []byte{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6} {
				conn.AddRule(&nftables.Rule{
					Table: table, Chain: chain,
					Exprs: flatExprs(
						matchMark(tproxyMark),
						matchNFProto(nfProto),
						matchL4Proto(unix.IPPROTO_TCP),
						matchDstPort(port16(p)),
						tproxyToPort(nfProto, port16(config.ProxyPortBase+p)),
					),
				})
			}
		}

		// TCPForward -> TPROXY to ProxyPortBase+fwd.Port.
		for _, fwd := range tcpForwards {
			for _, nfProto := range []byte{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6} {
				conn.AddRule(&nftables.Rule{
					Table: table, Chain: chain,
					Exprs: flatExprs(
						matchMark(tproxyMark),
						matchNFProto(nfProto),
						matchL4Proto(unix.IPPROTO_TCP),
						matchDstPort(port16(fwd.Port)),
						tproxyToPort(nfProto, port16(config.ProxyPortBase+fwd.Port)),
					),
				})
			}
		}

		// Catch-all TCP -> TPROXY to catch-all proxy port.
		for _, nfProto := range []byte{unix.NFPROTO_IPV4, unix.NFPROTO_IPV6} {
			conn.AddRule(&nftables.Rule{
				Table: table, Chain: chain,
				Exprs: flatExprs(
					matchMark(tproxyMark),
					matchNFProto(nfProto),
					matchL4Proto(unix.IPPROTO_TCP),
					tproxyToPort(nfProto, port16(config.CatchAllProxyPort)),
				),
			})
		}
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
// ICMP/ICMPv6 is explicitly accepted because it is never proxied
// through Envoy -- its policy is enforced by the filter chain.
//
// In container mode the chain uses policy ACCEPT so non-terrarium
// traffic (Envoy UID, root DNS proxy) passes through unaffected.
// In VM mode, explicit Envoy and root ACCEPT rules are added
// because matchFilteredTraffic matches all UIDs.
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

		// Excluded UIDs (e.g., dnsmasq) need non-loopback DNS egress
		// to reach their upstream resolvers. Without this, the guard
		// drop rule blocks their queries to external nameservers.
		for _, uid := range uids.ExcludeUIDs {
			for _, proto := range []byte{unix.IPPROTO_UDP, unix.IPPROTO_TCP} {
				conn.AddRule(&nftables.Rule{
					Table: table, Chain: chain,
					Exprs: flatExprs(
						matchUID(uid),
						matchL4Proto(proto),
						matchDstPort(53),
						verdictExprs(expr.VerdictAccept),
					),
				})
			}
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

	// ICMP is never proxied through Envoy; its policy is enforced by
	// the filter chain. Allow it through unconditionally so it can
	// egress on non-loopback interfaces.
	for _, proto := range []byte{unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6} {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				trafficMatch,
				matchL4Proto(proto),
				verdictExprs(expr.VerdictAccept),
			),
		})
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

// dnsGuardExprs returns match expressions for DNS interception in
// NAT PREROUTING: non-loopback input interface and IPv4 protocol.
// Unlike the TPROXY marking rules in mangle PREROUTING, it omits
// the non-local destination check so DNS queries to bridge-local
// addresses (e.g., BuildKit's embedded resolver on the CNI gateway)
// are also intercepted and forwarded to the terrarium DNS proxy.
func dnsGuardExprs() []expr.Any {
	return flatExprs(
		matchNotIIFName("lo"),
		matchNFProto(unix.NFPROTO_IPV4),
	)
}

// addNATPreRouting creates a NAT PREROUTING chain for VM mode that
// DNATs forwarded DNS traffic to 127.0.0.1 for the DNS proxy. Uses
// [dnsGuardExprs] (no local-dst check) so DNS to bridge-local
// addresses (e.g., BuildKit's embedded resolver on the CNI gateway)
// is also intercepted. Non-DNS forwarded TCP uses TPROXY in mangle
// PREROUTING because br_netfilter prevents DNAT to 127.0.0.1 for
// bridge-forwarded TCP; DNS TCP to local destinations is not
// bridge-forwarded (it is locally delivered), so DNAT works.
// DNS TCP to non-local destinations is already handled by TPROXY in
// mangle PREROUTING (higher priority), so this DNAT rule only fires
// for the local-destination case.
//
// After DNS rules, per-port bridge-local DNAT rules redirect TCP
// traffic from bridge containers destined for the VM's own IPs to
// Envoy. These use [matchLocalDst] so only locally-delivered traffic
// is intercepted (non-local forwarded traffic uses TPROXY). Per-port
// matching avoids intercepting SSH (port 22).
func addNATPreRouting(conn Conn, table *nftables.Table, resolvedPorts []int, tcpForwards []config.TCPForward) {
	chain := conn.AddChain(&nftables.Chain{
		Name:     "nat_prerouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	guard := dnsGuardExprs()

	// DNS DNAT: UDP + TCP port 53 -> DNS proxy.
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

	// Bridge-local TCP DNAT: redirect bridge-container traffic destined
	// for the VM's own IPs to Envoy proxy ports. Non-lo + IPv4 +
	// local-dst scoping ensures only locally-delivered bridge traffic
	// matches (not forwarded traffic, which uses TPROXY).
	bridgeGuard := flatExprs(
		matchNotIIFName("lo"),
		matchNFProto(unix.NFPROTO_IPV4),
		matchLocalDst(),
		matchL4Proto(unix.IPPROTO_TCP),
	)

	for _, port := range resolvedPorts {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				bridgeGuard,
				matchDstPort(port16(port)),
				dnatToLocal(port16(config.ProxyPortBase+port)),
			),
		})
	}

	for _, fwd := range tcpForwards {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				bridgeGuard,
				matchDstPort(port16(fwd.Port)),
				dnatToLocal(port16(config.ProxyPortBase+fwd.Port)),
			),
		})
	}
}

// addUnrestrictedNATPreRouting creates a NAT PREROUTING chain for
// VM mode unrestricted policy. DNATs forwarded DNS traffic to the
// DNS proxy. Uses [dnsGuardExprs] for the same bridge-local DNS
// interception as [addNATPreRouting]. After DNS rules, bridge-local
// DNAT rules redirect ports 80, 443, and TCPForward ports to Envoy.
// Forwarded non-local TCP uses TPROXY in mangle PREROUTING.
func addUnrestrictedNATPreRouting(conn Conn, table *nftables.Table, tcpForwards []config.TCPForward) {
	chain := conn.AddChain(&nftables.Chain{
		Name:     "nat_prerouting",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
	})

	guard := dnsGuardExprs()

	// DNS DNAT: UDP + TCP port 53 -> DNS proxy.
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

	// Bridge-local TCP DNAT: hardcoded ports 80 and 443 (matching
	// addUnrestrictedNAT OUTPUT rules) plus per-port TCPForwards.
	bridgeGuard := flatExprs(
		matchNotIIFName("lo"),
		matchNFProto(unix.NFPROTO_IPV4),
		matchLocalDst(),
		matchL4Proto(unix.IPPROTO_TCP),
	)

	for _, port := range []int{80, 443} {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				bridgeGuard,
				matchDstPort(port16(port)),
				dnatToLocal(port16(config.ProxyPortBase+port)),
			),
		})
	}

	for _, fwd := range tcpForwards {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				bridgeGuard,
				matchDstPort(port16(fwd.Port)),
				dnatToLocal(port16(config.ProxyPortBase+fwd.Port)),
			),
		})
	}
}

// tproxyNFProtoGuard returns the common match expressions for
// TPROXY dispatch rules in mangle PREROUTING: fwmark match and
// address family scope.
func tproxyNFProtoGuard(nfProto byte) []expr.Any {
	return flatExprs(
		matchMark(tproxyMark),
		matchNFProto(nfProto),
	)
}

// addForwardedDenyCIDRTPROXYSkip creates per-rule deny CIDR chains
// that ACCEPT (skip TPROXY) for denied CIDRs in the given address
// family. Traffic that skips TPROXY falls to the FORWARD chain where
// the filter deny rules DROP it. Mirrors [addDenyCIDRChainsWithVerdict]
// but scoped to TPROXY-marked forwarded traffic.
func addForwardedDenyCIDRTPROXYSkip(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR, nfProto byte,
) {
	groups := groupCIDRsByRule(cidrs)
	guard := tproxyNFProtoGuard(nfProto)

	for i, group := range groups {
		familySuffix := "4"
		if nfProto == unix.NFPROTO_IPV6 {
			familySuffix = "6"
		}

		chainName := fmt.Sprintf("deny_cidr_tproxy%s_%d", familySuffix, i)
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

		// Jump from parent chain (scoped to TPROXY-marked traffic).
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: parentChain,
			Exprs: flatExprs(
				guard,
				verdictExprs(expr.VerdictJump, chainName),
			),
		})
	}
}

// addForwardedAllowCIDRSkipTPROXY creates per-rule CIDR chains that
// clear the TPROXY fwmark and accept, letting matching TCP traffic
// bypass Envoy and be forwarded directly by the kernel. The FORWARD
// chain's policy evaluation ([addForwardChain]) still enforces the
// CIDR allowlist.
//
// CIDR traffic cannot use TPROXY or NAT REDIRECT in the PREROUTING
// path because br_netfilter's ip_sabotage_in prevents inet hooks
// from running on the ip_rcv pass for bridge-delivered packets. The
// TPROXY mark (table 100, local default) would route the packet to
// INPUT instead of FORWARD, and the CIDR catch-all listener never
// receives the connection. Clearing the mark restores normal
// forwarding.
func addForwardedAllowCIDRSkipTPROXY(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR, nfProto byte,
) {
	familySuffix := "4"
	if nfProto == unix.NFPROTO_IPV6 {
		familySuffix = "6"
	}

	// Clear mark + accept: the packet exits mangle_prerouting with
	// mark 0. Policy routing (table 100) does not apply, so the
	// kernel forwards the packet normally via the FORWARD chain.
	clearAndAccept := flatExprs(
		markPacket(0),
		verdictExprs(expr.VerdictAccept),
	)

	buildCIDRTCPChains(conn, table, parentChain, cidrs,
		"cidr_tproxy"+familySuffix, nil,
		clearAndAccept,
		tproxyNFProtoGuard(nfProto))
}

// buildCIDRTCPChains is the shared implementation for
// [addCIDRNATRedirect] and [addForwardedAllowCIDRSkipTPROXY]. It creates
// per-rule CIDR chains with
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
