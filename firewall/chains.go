//go:build linux

package firewall

import (
	"fmt"
	"net"
	"slices"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/firewall/logprefix"
)

// nftables chain names shared across the rule and chain builders.
const (
	chainOutput           = "output"
	chainForward          = "forward"
	chainInput            = "input"
	chainNATOutput        = "nat_output"
	chainBridgePreRouting = "bridge_prerouting"

	chainDenyPortNAT = "deny_port_nat"
)

// ICMPv6 types of the messages that the kernel sends without a socket
// owner and that conntrack does not track.
var (
	// The neighbor discovery messages (RFC 4861) that a host sends:
	// router solicitation, neighbor solicitation, and neighbor
	// advertisement.
	neighborDiscoveryTypes = []byte{133, 135, 136}

	// The Multicast Listener Discovery (MLD) messages that a host
	// sends: the MLDv1 listener report and listener done (RFC 2710),
	// and the MLDv2 listener report (RFC 3810).
	multicastListenerTypes = []byte{131, 132, 143}
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
// modes). The rules accept CT state ESTABLISHED, per-type ICMP
// RELATED, IPv6 neighbor discovery, IPv6 multicast listener
// discovery, and root DNS.
//
// The neighbor discovery rules accept router solicitations, neighbor
// solicitations, and neighbor advertisements under every policy. The
// kernel sends those messages to resolve the link-layer address of
// each IPv6 next hop and to answer the solicitations of its
// neighbors. The messages have no socket owner and conntrack does not
// track them, so no UID rule and no CT state rule accepts them.
//
// The multicast listener discovery rules accept MLDv1 listener
// reports, MLDv1 listener done messages, and MLDv2 listener reports
// to multicast destinations under every policy. The kernel sends
// those messages when it joins or leaves a multicast group, such as
// the solicited-node group of each IPv6 address. Switches that do MLD
// snooping forward the traffic of a group only to the ports that
// reported it. So a host that sends no reports does not receive the
// neighbor solicitations for its addresses. The messages have no
// socket owner and conntrack does not track them either.
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

	// ICMPv6 neighbor discovery: router-solicitation(133),
	// neighbor-solicitation(135), neighbor-advertisement(136). Not
	// UID-scoped and not CT-scoped, because the kernel sends these
	// without a socket owner and conntrack leaves them untracked.
	for _, icmpType := range neighborDiscoveryTypes {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNFProto(unix.NFPROTO_IPV6),
				matchL4Proto(unix.IPPROTO_ICMPV6),
				matchICMPType(icmpType),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}

	// ICMPv6 multicast listener discovery: listener-report(131),
	// listener-done(132), v2-listener-report(143). Not UID-scoped
	// and not CT-scoped, for the same reason as neighbor discovery.
	// The rules match every multicast destination, not only the
	// link-local scope ff02::/16. The kernel sends an MLDv1 report
	// to the group that it reports, and the scope of that group can
	// be wider than the link.
	for _, icmpType := range multicastListenerTypes {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchDstCIDR(mustParseCIDR("ff00::/8")),
				matchL4Proto(unix.IPPROTO_ICMPV6),
				matchICMPType(icmpType),
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
// allow chains so deny takes precedence. The emitter logs the first
// packet of each new flow that a DROP matches, with the egressDeny
// index of the rule.
func addDenyCIDRChains(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR, uids UIDs, emitter logEmitter,
) {
	addDenyCIDRChainsWithVerdict(
		conn, table, parentChain, cidrs, uids, emitter, "deny_cidr", expr.VerdictDrop, nil, false,
	)
}

// addDenyCIDRChainsWithVerdict is the shared implementation for deny
// CIDR chain construction. The chainPrefix names the chains (e.g.
// "deny_cidr" or "deny_cidr_nat") and verdict is the action for
// matching traffic (DROP in filter, ACCEPT in NAT to skip redirect).
// For a DROP, the emitter logs the first packet of each new flow that
// the verdict matches, with the egressDeny index of the rule. A
// caller that passes another verdict must pass a disabled emitter,
// because the emitter logs an ACCEPT as allowed by an egress rule.
// The jumpGuard expressions scope each jump from the parent chain. A
// nil jumpGuard jumps for every packet. With returnLoopback, each
// chain starts with the rules of [addLoopbackReturns], so the verdict
// never applies to a packet to a loopback address.
func addDenyCIDRChainsWithVerdict(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR, uids UIDs, emitter logEmitter,
	chainPrefix string, verdict expr.VerdictKind, jumpGuard []expr.Any,
	returnLoopback bool,
) {
	groups := groupCIDRsByRule(cidrs)

	for i, group := range groups {
		chainName := fmt.Sprintf("%s_%d", chainPrefix, i)
		chain := conn.AddChain(&nftables.Chain{
			Name:  chainName,
			Table: table,
		})

		if returnLoopback {
			addLoopbackReturns(conn, table, chain)
		}

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
				emitter.verdict(conn, table, chain, verdict, rule.RuleIndex,
					matchFilteredTraffic(uids),
					matchDstCIDR(cidrNet),
				)
			} else {
				for _, pp := range rule.Ports {
					emitter.verdict(conn, table, chain, verdict, rule.RuleIndex,
						matchFilteredTraffic(uids),
						matchPortProto(pp),
						matchDstCIDR(cidrNet),
					)
				}
			}
		}

		// Jump from parent chain.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: parentChain,
			Exprs: flatExprs(jumpGuard, verdictExprs(expr.VerdictJump, chainName)),
		})
	}
}

// addDenyPortRules emits DROP rules on the parent chain for port-only
// deny rules (no L3 selector). Under Cilium semantics, a deny rule
// with only toPorts means "deny traffic to any destination on these
// ports." A zero-value [config.ResolvedPortProto] (port 0, empty
// protocol) means wildcard: deny all ports/protocols. The emitter
// logs the first packet of each new flow that a DROP matches, with
// the DenyIndex of its port.
func addDenyPortRules(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	ports []config.ResolvedDenyPort, uids UIDs, emitter logEmitter,
) {
	for _, dp := range ports {
		pp := dp.ResolvedPortProto
		if pp.Port == 0 && pp.Protocol == "" {
			// Wildcard: deny all traffic from terrarium UID.
			emitter.drop(conn, table, parentChain, dp.DenyIndex,
				matchFilteredTraffic(uids),
			)
		} else {
			emitter.drop(conn, table, parentChain, dp.DenyIndex,
				matchFilteredTraffic(uids),
				matchPortProto(pp),
			)
		}
	}
}

// addCIDRChains creates per-rule CIDR chains and adds jumps from
// the parent chain. Each chain evaluates one rule's CIDRs and
// excepts independently: RETURN for except hits (try next rule),
// ACCEPT for CIDR hits (allow packet). This preserves Cilium's
// OR semantics across egress rules. Using jump (not goto) ensures
// return-to-caller works for OR evaluation. The emitter logs the
// first packet of each new flow that an ACCEPT matches, with the
// egress index of the rule.
func addCIDRChains(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR, uids UIDs, emitter logEmitter,
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
				emitter.accept(conn, table, chain, rule.RuleIndex,
					matchFilteredTraffic(uids),
					matchDstCIDR(cidrNet),
				)
			} else {
				for _, pp := range rule.Ports {
					// L7 ports are handled by Envoy; skip ACCEPT.
					if rule.L7Ports[pp.Port] {
						continue
					}

					emitter.accept(conn, table, chain, rule.RuleIndex,
						matchFilteredTraffic(uids),
						matchPortProto(pp),
						matchDstCIDR(cidrNet),
					)
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
// TCP single ports are handled by Envoy via NAT REDIRECT. The emitter
// logs the first packet of each new flow that an ACCEPT matches, with
// the egress index of the rule.
func addOpenPortRule(
	conn Conn, table *nftables.Table, chain *nftables.Chain,
	op config.ResolvedOpenPort, uids UIDs, emitter logEmitter,
) {
	if op.Protocol == config.ProtoUDP {
		emitter.accept(conn, table, chain, op.EgressIndex,
			matchFilteredTraffic(uids),
			matchL4Proto(protoNum(op.Protocol)),
			matchDstPortOrRange(port16(op.Port), port16(op.EndPort)),
		)
	}

	if op.Protocol == config.ProtoTCP && op.EndPort > 0 {
		emitter.accept(conn, table, chain, op.EgressIndex,
			matchFilteredTraffic(uids),
			matchL4Proto(unix.IPPROTO_TCP),
			matchDstPortOrRange(port16(op.Port), port16(op.EndPort)),
		)
	}
}

// addFQDNPortRules adds per-rule FQDN set lookup rules. Two rules
// per port per address family: ESTABLISHED first (zombie/CT semantics
// -- conntrack keeps flows alive past set TTL expiry), then set
// lookup (gates new flows requiring DNS resolution). The emitter logs
// the first packet of each new flow that a set lookup accepts, with
// the egress index of the rule.
func addFQDNPortRules(
	conn Conn,
	table *nftables.Table,
	chain *nftables.Chain,
	frp config.FQDNRulePorts,
	ref setRef,
	uids UIDs,
	emitter logEmitter,
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
		emitter.accept(conn, table, chain, frp.EgressIndex,
			matchNFProto(unix.NFPROTO_IPV4),
			matchFilteredTraffic(uids),
			matchL4Proto(proto),
			matchDstPort(port16(fp.Port)),
			setLookupDst(ref.set4),
		)

		// Set lookup (v6).
		emitter.accept(conn, table, chain, frp.EgressIndex,
			matchNFProto(unix.NFPROTO_IPV6),
			matchFilteredTraffic(uids),
			matchL4Proto(proto),
			matchDstPort(port16(fp.Port)),
			setLookupDst(ref.set6),
		)
	}
}

// addNATRules creates the NAT output chain. In order, it holds the
// deny CIDR ACCEPT, deny port ACCEPT, allow CIDR REDIRECT, per-port
// REDIRECT, TCPForward REDIRECT, and catch-all TCP REDIRECT rules.
// The deny CIDR chains and the deny port chain keep denied traffic
// away from Envoy. An ACCEPT in NAT leaves the packet unchanged, and
// the deny rules of the filter chain DROP it. The allow CIDR chains
// redirect matching TCP to the CIDR catch-all listener for forwarding
// via original_dst. The catch-all sends remaining non-policy-port
// traffic to Envoy's blackhole listener.
func addNATRules(
	conn Conn, table *nftables.Table, cfg *config.Config,
	resolvedPorts []int, cidr4, cidr6, denyCIDRs []config.ResolvedCIDR,
	denyPorts []config.ResolvedDenyPort, uids UIDs,
) {
	natChain := conn.AddChain(&nftables.Chain{
		Name:     chainNATOutput,
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

	// 2. Deny port NAT ACCEPT (prevent redirect for the TCP ports
	// of port-only deny rules).
	addDenyPortNATAccept(conn, table, natChain, denyPorts, uids)

	// 3. Allow CIDR NAT REDIRECT (redirect TCP to CIDR catch-all).
	addCIDRNATRedirect(conn, table, natChain, allCIDRs, uids)

	// 4. Per-port FQDN REDIRECT rules.
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

	// 5. TCPForward REDIRECT rules.
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

	// 6. Catch-all TCP REDIRECT -> catch-all TCP listener.
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
		Name:     chainNATOutput,
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
//
// Each chain returns packets to 127.0.0.0/8 and ::1 to the NAT output
// chain before its ACCEPT rules. The filter output chain accepts those
// destinations before it evaluates the deny rules. TCP to loopback
// reaches the REDIRECT rules. So a deny CIDR that covers a loopback
// address never opens a direct path to an Envoy listener or to
// another local service.
//
// The NAT chains log nothing. The filter chain logs the packet when
// it drops the packet.
func addDenyCIDRNATAccept(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR, uids UIDs,
) {
	addDenyCIDRChainsWithVerdict(
		conn, table, parentChain, cidrs, uids, logEmitter{}, "deny_cidr_nat", expr.VerdictAccept, nil, true,
	)
}

// addLoopbackReturns adds to chain one RETURN rule for packets to
// 127.0.0.0/8 and one for packets to ::1. The chain must be one that
// the NAT output chain jumps to. The caller must add the ACCEPT rules
// of the chain after this call.
//
// The filter output chain accepts loopback destinations before it
// evaluates the deny rules ([addOutputBaseRules]). So an ACCEPT in
// NAT lets a packet reach its loopback destination. After a RETURN,
// the REDIRECT rules of the NAT output chain send loopback TCP to
// Envoy.
func addLoopbackReturns(conn Conn, table *nftables.Table, chain *nftables.Chain) {
	for _, loopback := range []string{"127.0.0.0/8", "::1/128"} {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchDstCIDR(mustParseCIDR(loopback)),
				verdictExprs(expr.VerdictReturn),
			),
		})
	}
}

// addDenyCIDRNATPreRoutingAccept creates per-rule deny CIDR chains
// for the NAT PREROUTING chain of VM mode and adds a jump to each
// chain from the parent chain. This mirrors [addDenyCIDRNATAccept]
// (NAT OUTPUT) for forwarded TCP. An ACCEPT in a jumped-to chain ends
// the parent chain before its per-port DNAT rules. The packet keeps
// its destination, so the FORWARD chain evaluates it and the deny
// CIDR chains of the filter ([addDenyCIDRChains]) DROP it.
//
// Each jump matches only IPv4 TCP that arrives on an interface other
// than loopback and has a destination address that the host does not
// own. The FORWARD chain never sees TCP to an address of the host.
// The jumps leave that TCP to the DNAT rules, because an ACCEPT for
// it opens a direct path from a container to the services of the
// host.
//
// The cidrs must be the IPv4 deny CIDRs, because the parent chain
// DNATs only IPv4. The chains log nothing. The filter chain logs the
// packet when it drops the packet.
func addDenyCIDRNATPreRoutingAccept(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	cidrs []config.ResolvedCIDR, uids UIDs,
) {
	addDenyCIDRChainsWithVerdict(
		conn, table, parentChain, cidrs, uids, logEmitter{}, "deny_cidr_nat_pre", expr.VerdictAccept,
		flatExprs(
			matchNotIIFName("lo"),
			matchNFProto(unix.NFPROTO_IPV4),
			matchL4Proto(unix.IPPROTO_TCP),
			matchNotLocalDst(),
		),
		false,
	)
}

// addDenyPortNATAccept creates the deny_port_nat chain for the TCP
// ports of port-only deny rules and adds a jump to it from the NAT
// output chain. This mirrors [addDenyPortRules] (filter) but in the
// NAT context. NAT fires before filter, and the filter chains never
// see the original destination port of a packet that NAT sent to an
// Envoy listener. An ACCEPT in the jumped-to chain ends the NAT output
// chain before its REDIRECT rules. The packet keeps its destination,
// and the deny port rules of the filter chain DROP it.
//
// The chain returns TCP to 127.0.0.0/8 and ::1 to the NAT output
// chain before its ACCEPT rules. The filter output chain accepts those
// destinations before it evaluates the deny rules. TCP to loopback
// reaches the REDIRECT rules, so a deny rule never opens a direct
// path to an Envoy listener or to another local service.
//
// The function adds no chain when no port-only deny rule matches TCP.
// The NAT rules log nothing. The filter chain logs the packet when it
// drops the packet.
func addDenyPortNATAccept(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	ports []config.ResolvedDenyPort, uids UIDs,
) {
	matches := denyPortNATMatches(ports)
	if len(matches) == 0 {
		return
	}

	chain := conn.AddChain(&nftables.Chain{
		Name:  chainDenyPortNAT,
		Table: table,
	})

	addLoopbackReturns(conn, table, chain)

	for _, match := range matches {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchFilteredTraffic(uids),
				match,
				verdictExprs(expr.VerdictAccept),
			),
		})
	}

	conn.AddRule(&nftables.Rule{
		Table: table, Chain: parentChain,
		Exprs: verdictExprs(expr.VerdictJump, chainDenyPortNAT),
	})
}

// denyPortNATMatches returns the match expressions of one NAT ACCEPT
// rule for each TCP port of the given port-only deny rules. The zero
// [config.ResolvedPortProto] matches every TCP port. UDP ports add no
// match, because the NAT chains send only TCP to Envoy.
func denyPortNATMatches(ports []config.ResolvedDenyPort) [][]expr.Any {
	var matches [][]expr.Any

	for _, dp := range ports {
		pp := dp.ResolvedPortProto

		var port []expr.Any

		switch {
		case pp.Port == 0 && pp.Protocol == "":
			// Wildcard: every TCP port.
		case pp.Protocol == config.ProtoTCP:
			port = matchDstPortOrRange(port16(pp.Port), port16(pp.EndPort))
		default:
			continue
		}

		matches = append(matches, flatExprs(matchL4Proto(unix.IPPROTO_TCP), port))
	}

	return matches
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
	prefix := matchFilteredTraffic(uids)
	redirect := redirectToPort(port16(config.CIDRCatchAllPort))

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
		// redirect.
		for _, rule := range group {
			if !cidrNeedsTCPRedirect(rule) {
				continue
			}

			for _, exc := range rule.Except {
				_, excNet, err := net.ParseCIDR(exc)
				if err != nil {
					continue
				}

				emitCIDRTCPRules(conn, table, chain, rule, prefix, excNet, verdictExprs(expr.VerdictReturn))
			}
		}

		// CIDR REDIRECT: send matching TCP to the CIDR catch-all
		// listener.
		for _, rule := range group {
			if !cidrNeedsTCPRedirect(rule) {
				continue
			}

			_, cidrNet, err := net.ParseCIDR(rule.CIDR)
			if err != nil {
				continue
			}

			emitCIDRTCPRules(conn, table, chain, rule, prefix, cidrNet, redirect)
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

// emitCIDRTCPRules emits nftables rules for a single CIDR rule's TCP
// ports, matching the given cidrNet and applying the terminal
// expression (a verdict or a redirect). A rule without ports emits
// one rule for all TCP. A rule with ports emits one rule for each
// eligible TCP port. Each emitted rule starts with the prefix
// expressions, such as the UID match of the NAT chains.
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
// convention in matchDstCIDR. In VM mode, the chain marks forwarded
// UDP for TPROXY interception. Forwarded IPv4 TCP to the ports of
// Envoy uses DNAT in NAT PREROUTING ([addNATPreRouting]) because
// br_netfilter's br_nf_pre_routing_finish only re-routes packets
// locally when DNAT changes the destination. The FORWARD chain
// evaluates other forwarded TCP.
//
// Forwarded IPv6 TCP to port 53 is the exception. In VM mode the
// chain marks it and sends it to the DNS proxy with TPROXY, as it
// does with forwarded IPv6 UDP to port 53. Policy routing delivers
// the marked packet locally, and the DNS proxy listens on port 53 of
// every IPv6 address. So the kernel finds the listener of the DNS
// proxy with the destination that the sender chose.
//
// Policy routing delivers the marked forwarded UDP to a local socket,
// so that UDP passes the INPUT hook and not the FORWARD hook. The
// INPUT chain ([addInputChain]) policy-evaluates it before Envoy
// receives it.
//
// In VM mode the chain marks each forwarded UDP datagram that travels
// in the original direction of its conntrack flow, in every conntrack
// state. So each datagram of a flow passes the policy rules of the
// INPUT chain and reaches Envoy, also after conntrack sees a reply.
// The chain accepts the replies of forwarded flows without a mark,
// and the kernel forwards them.
//
// Forwarded UDP to the CIDR of an allow rule also goes to Envoy. The
// policy rules of the INPUT chain match it against the CIDR and the
// ports of that rule.
//
// The bridge prerouting chain ([addBridgePreRoutingChain]) takes the
// UDP of a bridge-attached container away from the bridge. That UDP
// reaches this chain as a packet that the bridge port received.
// Under br_netfilter, a packet that this chain sees inside the bridge
// loses the socket that TPROXY assigns to it. UDP to port 53 stays
// with the bridge. TPROXY sends forwarded IPv6 DNS to the port that
// the sender chose, so the kernel finds the DNS proxy without the
// assigned socket.
func addManglePreRoutingChain(
	conn Conn, table *nftables.Table,
	udpPort uint16,
	denyCIDR4, denyCIDR6 []config.ResolvedCIDR,
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
		// Re-mark established TPROXY packets so policy routing
		// (table 100) delivers them locally to Envoy. Without
		// this, established packets arrive with fwmark=0, route
		// via the main table, and are forwarded instead of
		// delivered to the transparent socket.
		//
		// The socket lookup of this rule also finds a transparent
		// listener on the destination port of a packet. The IPv6
		// listeners of the DNS proxy are transparent and listen on
		// port 53 of every address. So this rule also marks the
		// first packet of forwarded IPv6 DNS when the DNS proxy
		// listens, before the rules for port 53 further down the
		// chain see it. The transparent listeners of Envoy listen
		// on their ports of every address, so this rule also marks
		// forwarded TCP to one of those ports.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				notMatchMark(guardMark),
				matchSocketTransparent(),
				markPacket(tproxyMark),
				verdictExprs(expr.VerdictAccept),
			),
		})

		// Accept the forwarded packets of established and related
		// flows before the marking rules, except UDP in the
		// original direction of its flow. The accepted packets
		// keep mark 0, so the kernel forwards them. They include
		// the replies of forwarded flows, such as the UDP reply
		// of a container to a client outside the VM. A mark on
		// such a reply sends it to Envoy and not to the client.
		//
		// The original direction of a flow is the direction of
		// its first packet. UDP in that direction passes on to
		// the marking rules in every conntrack state. A UDP flow
		// becomes established when conntrack sees a reply, such
		// as the reply that a transparent proxy sends from the
		// address of the destination. An accept for the later
		// datagrams of that flow forwards them to the destination
		// directly, past Envoy and past the policy rules of the
		// INPUT chain.
		//
		// The first rule accepts every protocol except UDP, and
		// the second rule accepts the replies of every protocol.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNotIIFName("lo"),
				matchNotLocalDst(),
				notMatchL4Proto(unix.IPPROTO_UDP),
				matchCtState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED),
				verdictExprs(expr.VerdictAccept),
			),
		})

		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNotIIFName("lo"),
				matchNotLocalDst(),
				matchCtState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED),
				matchCtDirectionReply(),
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

		// IPv6 forwarded TCP DNS: mark for TPROXY. The socket
		// transparent rule at the top of the chain marks this TCP
		// only when the DNS proxy listens. This rule marks it in
		// every case, so policy routing delivers it locally and no
		// resolver receives it when the DNS proxy does not listen.
		// Without the mark, the kernel forwards that TCP to the
		// resolver that the sender chose.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				notMatchMark(guardMark),
				matchNFProto(unix.NFPROTO_IPV6),
				matchNotIIFName("lo"),
				matchNotLocalDst(),
				matchL4Proto(unix.IPPROTO_TCP),
				matchDstPort(53),
				markPacket(tproxyMark),
			),
		})

		// Forwarded IPv4 TCP to the ports of Envoy uses DNAT in NAT
		// PREROUTING (addNATPreRouting) instead of TPROXY.
		// The kernel's br_nf_pre_routing_finish only re-routes
		// packets locally when DNAT changes the destination
		// address. TPROXY does not modify the IP header, so
		// bridge-forwarded packets would be L2-forwarded to the
		// original destination. IPv4 DNS (UDP + TCP) also uses DNAT.
		//
		// IPv6 DNS (UDP + TCP) uses TPROXY here because IPv6 has no
		// route_localnet. A bridge-attached container sends DNS for
		// an address outside its bridge to the bridge itself as the
		// L2 destination. The mark then routes the packet to a
		// local socket. The kernel looks that socket up with the
		// port that the sender chose, and the DNS proxy listens on
		// that port.

		// IPv6 DNS TPROXY (UDP + TCP port 53) to the DNS proxy.
		// These rules must appear before the generic UDP TPROXY
		// rules.
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

		// Deny CIDR: ACCEPT to skip TPROXY. The packet keeps its
		// mark, so it reaches the INPUT chain, and the deny rules
		// of the policy chain DROP it there.
		addForwardedDenyCIDRTPROXYSkip(conn, table, chain, denyCIDR4, unix.NFPROTO_IPV4)
		addForwardedDenyCIDRTPROXYSkip(conn, table, chain, denyCIDR6, unix.NFPROTO_IPV6)
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

// bridgeBroutePriority is the priority of the bridge prerouting chain.
// The chain must run before br_netfilter, whose prerouting hook has
// priority 0 (NF_BR_PRI_BRNF). The value is the "dstnat" priority of
// the bridge family.
const bridgeBroutePriority = -300

// addBridgePreRoutingChain adds a bridge-family table with a
// prerouting chain that takes the forwarded UDP of bridge-attached
// containers away from the bridge. Only VM mode uses the chain.
//
// With br_netfilter, the mangle PREROUTING chain
// ([addManglePreRoutingChain]) sees a frame of a bridge port inside
// the bridge. TPROXY assigns the socket of Envoy to the packet there.
// But the kernel drops that assignment when the bridge passes the
// packet to the network layer, and it does not run PREROUTING a
// second time. The kernel then looks for a socket on the port that
// the sender chose, finds none, and discards the datagram.
//
// The chain sets the broute flag on those frames before br_netfilter
// sees them. The kernel then passes each frame to the network layer
// as a packet that the bridge port received. So PREROUTING runs one
// time, outside the bridge, and the socket assignment of TPROXY lasts
// until the UDP layer delivers the datagram. The input interface of
// the packet is the bridge port and not the bridge.
//
// The chain matches UDP in frames that arrive on a container port of
// the bridge and whose destination MAC address is the address of the
// bridge device. Those frames hold the packets that the VM routes or
// receives for the container. A frame for another container of the
// same bridge stays with the bridge.
//
// A container port is a bridge port whose name is not in uplinks and
// whose device is a veth device or a TAP device. Container runtimes
// attach a container to a bridge with a veth device. A runtime that
// runs the container in a virtual machine, such as Kata Containers or
// Firecracker, attaches the machine with a TAP device, whose link
// kind is "tun".
//
// Frames from an uplink of the bridge stay with the bridge. An uplink
// connects the bridge to the network of the VM. Its frames hold UDP
// that the VM itself receives, such as the replies of upstream DNS
// servers and of DHCP servers. A socket that is bound to the bridge
// receives such a datagram only when its input interface is the
// bridge. The chain keeps the frames of these ports with the bridge:
//
//   - Every port whose device has another link kind or none, such as
//     a physical network interface, a bond, or a VLAN device.
//   - Every port that uplinks names. The policy lists in
//     [config.Config.BridgeUplinks] each uplink that is a veth or TAP
//     device.
//
// These packets of a container stay with the bridge as well:
//
//   - UDP to port 53. Forwarded IPv4 DNS uses DNAT, and the DNS proxy
//     receives forwarded IPv6 DNS on the port that the sender chose.
//   - IPv6 UDP to a link-local address. The kernel accepts a packet
//     for a link-local address of the bridge only from the bridge
//     device.
//
// A later fragment of a datagram has no UDP header, so the rule for
// port 53 does not match it. The chain takes it from the bridge, as
// it takes the first fragment of a datagram to another port. But the
// first fragment of a datagram to port 53 stays with the bridge. So
// the kernel never reassembles a fragmented datagram to port 53, and
// the DNS proxy does not receive it. DNS queries fit in one packet.
//
// The bridge port has no IPv4 address, so the kernel accepts the IPv4
// packets only when reverse path filtering is off for the port. See
// [SetupForwardRouting].
func addBridgePreRoutingChain(conn Conn, uplinks []string) {
	table := conn.AddTable(&nftables.Table{
		Name:   TableName,
		Family: nftables.TableFamilyBridge,
	})

	chain := conn.AddChain(&nftables.Chain{
		Name:     chainBridgePreRouting,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRef(bridgeBroutePriority),
	})

	// DNS stays with the bridge.
	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchL4Proto(unix.IPPROTO_UDP),
			matchDstPort(53),
			verdictExprs(expr.VerdictAccept),
		),
	})

	// The frames of a named uplink stay with the bridge.
	for _, uplink := range uplinks {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchIIFName(uplink),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}

	// The UDP of a container on a veth port or on a TAP port.
	for _, kind := range []string{"veth", "tun"} {
		// IPv4 UDP of a container that the VM routes or receives.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchPktTypeHost(),
				matchIIFKind(kind),
				matchEtherType(unix.ETH_P_IP),
				matchL4Proto(unix.IPPROTO_UDP),
				setBroute(),
			),
		})

		// IPv6 UDP of a container that the VM routes or receives.
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchPktTypeHost(),
				matchIIFKind(kind),
				matchEtherType(unix.ETH_P_IPV6),
				notMatchDstIPv6LinkLocal(),
				matchL4Proto(unix.IPPROTO_UDP),
				setBroute(),
			),
		})
	}
}

// addDenyICMPRules emits DROP rules for deny ICMP entries. When an
// entry has CIDRs (L3 scope from sibling selectors), a per-rule
// chain is created with CIDR-scoped DROPs and except RETURNs,
// mirroring [addDenyCIDRChains]. Standalone entries (nil CIDRs)
// are emitted flat on the parent chain. Deny ICMP rules are
// evaluated before allow ICMP rules (deny precedence). The emitter
// logs the first packet of each new flow that a DROP matches, with
// the RuleIndex of its entry. That RuleIndex is an index into
// egressDeny.
func addDenyICMPRules(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	icmps []config.ResolvedICMP, uids UIDs, emitter logEmitter,
) {
	addICMPVerdictRules(conn, table, parentChain, icmps, nil, uids, emitter, "deny_icmp", expr.VerdictDrop)
}

// addICMPRules emits ACCEPT rules for allow ICMP entries. When an
// entry has CIDRs (L3 scope from sibling selectors), a per-rule
// chain is created with CIDR-scoped ACCEPTs and except RETURNs,
// mirroring [addCIDRChains]. When an entry uses FQDN sets, an
// ESTABLISHED rule and set lookup rules are emitted. Standalone
// entries (nil CIDRs, no FQDN) are emitted flat on the parent chain.
// The emitter logs the first packet of each new flow that an ACCEPT
// matches, with the RuleIndex of its entry. That RuleIndex is an
// index into egress.
func addICMPRules(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	icmps []config.ResolvedICMP, icmpFQDNSets map[int]setRef, uids UIDs,
	emitter logEmitter,
) {
	addICMPVerdictRules(conn, table, parentChain, icmps, icmpFQDNSets, uids, emitter, "icmp", expr.VerdictAccept)
}

// addICMPVerdictRules is the shared implementation for
// [addDenyICMPRules] and [addICMPRules]. It emits per-entry rules
// with the given verdict kind. The chainPrefix names per-entry
// sub-chains for CIDR-scoped entries. When icmpFQDNSets is non-nil
// and an entry has UseFQDNSet, ESTABLISHED and set lookup rules are
// emitted instead of CIDR chain dispatch. The emitter logs the
// first packet of each new flow that a verdict rule matches, with the
// RuleIndex of its entry.
func addICMPVerdictRules(
	conn Conn, table *nftables.Table, parentChain *nftables.Chain,
	icmps []config.ResolvedICMP, icmpFQDNSets map[int]setRef, uids UIDs,
	emitter logEmitter, chainPrefix string, verdict expr.VerdictKind,
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

			emitter.verdict(conn, table, parentChain, verdict, icmp.RuleIndex,
				matchNFProto(nfProto),
				matchFilteredTraffic(uids),
				matchL4Proto(l4Proto),
				matchICMPType(icmp.Type),
				setLookupDst(set),
			)

			continue
		}

		if len(icmp.CIDRs) == 0 {
			emitter.verdict(conn, table, parentChain, verdict, icmp.RuleIndex,
				matchFilteredTraffic(uids),
				matchNFProto(nfProto),
				matchL4Proto(l4Proto),
				matchICMPType(icmp.Type),
			)

			continue
		}

		chainName := fmt.Sprintf("%s_%d", chainPrefix, chainIdx)
		chainIdx++

		chain := conn.AddChain(&nftables.Chain{
			Name:  chainName,
			Table: table,
		})

		addICMPCIDRRules(conn, table, chain, icmp, nfProto, l4Proto, uids, emitter, verdict)

		conn.AddRule(&nftables.Rule{
			Table: table, Chain: parentChain,
			Exprs: flatExprs(verdictExprs(expr.VerdictJump, chainName)),
		})
	}
}

// addICMPCIDRRules emits except RETURN and CIDR verdict rules for a
// single CIDR-scoped ICMP entry on the given chain. Used by both
// allow and deny ICMP rule generation. The emitter logs the first
// packet of each new flow that a verdict rule matches.
func addICMPCIDRRules(
	conn Conn, table *nftables.Table, chain *nftables.Chain,
	icmp config.ResolvedICMP, nfProto, l4Proto byte, uids UIDs,
	emitter logEmitter, verdict expr.VerdictKind,
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

		emitter.verdict(conn, table, chain, verdict, icmp.RuleIndex,
			matchFilteredTraffic(uids),
			matchNFProto(nfProto),
			matchL4Proto(l4Proto),
			matchICMPType(icmp.Type),
			matchDstCIDR(cidrNet),
		)
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
// The emitter logs the first packet of each new flow that a set lookup
// accepts, with the egress index of the rule.
func addCatchAllFQDNRules(
	conn Conn,
	table *nftables.Table,
	chain *nftables.Chain,
	rules []config.CatchAllFQDNRule,
	sets map[int]setRef,
	uids UIDs,
	emitter logEmitter,
) {
	for _, rule := range rules {
		ref := sets[rule.RuleIndex]

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
		emitter.accept(conn, table, chain, rule.EgressIndex,
			matchNFProto(unix.NFPROTO_IPV4),
			matchFilteredTraffic(uids),
			setLookupDst(ref.set4),
		)

		// Set lookup (v6) -- any port, any protocol.
		emitter.accept(conn, table, chain, rule.EgressIndex,
			matchNFProto(unix.NFPROTO_IPV6),
			matchFilteredTraffic(uids),
			setLookupDst(ref.set6),
		)
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
func addPostroutingGuard(conn Conn, table *nftables.Table, emitter logEmitter, uids UIDs) {
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

	emitter.emit(conn, table, chain, logprefix.KindLeak, -1,
		trafficMatch, notMatchOIFName("lo"))

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
// is also intercepted.
//
// After DNS rules, per-port DNAT rules redirect forwarded TCP from
// bridge containers to Envoy proxy ports. The local-dst restriction
// is intentionally omitted: br_netfilter's [br_nf_pre_routing_finish]
// only re-routes packets when DNAT changes the destination address,
// so non-local traffic must also be DNATted for Envoy to receive it.
// Per-port matching avoids intercepting SSH (port 22). Non-lo scoping
// prevents these rules from matching locally-generated TPROXY traffic
// re-entering PREROUTING on loopback.
//
// Before the per-port DNAT rules, the chain accepts forwarded TCP to
// the IPv4 CIDRs of deny rules ([addDenyCIDRNATPreRoutingAccept]) and
// to the ports of port-only deny rules ([denyPortNATMatches]). That
// TCP keeps its destination, so the FORWARD chain evaluates it and
// the deny rules DROP it.
//
// The ACCEPT rules match only TCP to an address that the host does
// not own. The FORWARD chain never sees TCP to an address of the
// host, so the ACCEPT rules leave that TCP to the DNAT rules. An
// ACCEPT for it opens a direct path from a container to the services
// of the host.
func addNATPreRouting(
	conn Conn, table *nftables.Table,
	resolvedPorts []int, tcpForwards []config.TCPForward,
	denyCIDR4 []config.ResolvedCIDR, denyPorts []config.ResolvedDenyPort, uids UIDs,
) {
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

	// Deny CIDR ACCEPT: forwarded TCP to the CIDRs of deny rules
	// skips the DNAT rules below.
	addDenyCIDRNATPreRoutingAccept(conn, table, chain, denyCIDR4, uids)

	// Deny port ACCEPT: forwarded TCP to the ports of port-only deny
	// rules skips the DNAT rules below. The kernel does not forward
	// TCP to an address of the host, so that TCP continues to the DNAT
	// rules.
	for _, match := range denyPortNATMatches(denyPorts) {
		conn.AddRule(&nftables.Rule{
			Table: table, Chain: chain,
			Exprs: flatExprs(
				matchNotIIFName("lo"),
				matchNFProto(unix.NFPROTO_IPV4),
				match,
				matchNotLocalDst(),
				verdictExprs(expr.VerdictAccept),
			),
		})
	}

	// Forwarded TCP DNAT: redirect bridge-container TCP to Envoy.
	bridgeGuard := flatExprs(
		matchNotIIFName("lo"),
		matchNFProto(unix.NFPROTO_IPV4),
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
// interception as [addNATPreRouting]. After DNS rules, per-port DNAT
// rules redirect forwarded TCP to Envoy (same non-local DNAT
// rationale as [addNATPreRouting]).
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

	// Forwarded TCP DNAT: redirect bridge-container TCP to Envoy.
	bridgeGuard := flatExprs(
		matchNotIIFName("lo"),
		matchNFProto(unix.NFPROTO_IPV4),
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
// family. Traffic that skips TPROXY keeps [tproxyMark], so policy
// routing still delivers it locally. It reaches the INPUT chain
// ([addInputChain]), where the deny rules of the policy chain DROP
// it. Mirrors [addDenyCIDRChainsWithVerdict] but scoped to
// TPROXY-marked forwarded traffic.
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

// addForwardChain creates a FORWARD chain for VM mode that
// policy-evaluates forwarded traffic. The chain handles established
// connections, ICMP RELATED, and jumps to the terrarium_output chain
// for new connection policy evaluation. Traffic not accepted by policy
// is dropped.
func addForwardChain(conn Conn, table *nftables.Table, terrariumChain *nftables.Chain) {
	policy := nftables.ChainPolicyDrop
	chain := conn.AddChain(&nftables.Chain{
		Name:     chainForward,
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

// addInputChain creates an INPUT chain for VM mode that
// policy-evaluates the forwarded UDP that TPROXY delivers to Envoy.
// The mangle PREROUTING chain marks that UDP with [tproxyMark], and
// policy routing delivers the marked packets to a local socket. So
// the packets pass the INPUT hook and never reach the FORWARD chain.
// The chain jumps to the terrarium_output chain for each of those
// packets, and that chain accepts or drops it. TPROXY leaves the
// destination of a packet unchanged, so the policy rules match the
// address and the port that the sender chose.
//
// The jump skips these kinds of packets, and the ACCEPT policy of the
// chain accepts them:
//
//   - Packets from the loopback interface. They are local UDP, which
//     the OUTPUT chain evaluated before policy routing sent it to
//     loopback.
//   - UDP to port 53. The mangle PREROUTING chain sends marked IPv6
//     DNS to the DNS proxy, not to Envoy.
//   - TCP. The mangle PREROUTING chain marks forwarded IPv6 TCP to
//     port 53 for the DNS proxy. Its socket transparent rule also
//     marks forwarded TCP to the port of a transparent listener of
//     Envoy or of the DNS proxy.
//   - Packets without [tproxyMark]. They are inbound traffic for the
//     VM, which the host firewall filters.
func addInputChain(conn Conn, table *nftables.Table, terrariumChain *nftables.Chain) {
	policy := nftables.ChainPolicyAccept
	chain := conn.AddChain(&nftables.Chain{
		Name:     chainInput,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})

	conn.AddRule(&nftables.Rule{
		Table: table, Chain: chain,
		Exprs: flatExprs(
			matchNotIIFName("lo"),
			matchMark(tproxyMark),
			matchL4Proto(unix.IPPROTO_UDP),
			notMatchDstPort(53),
			verdictExprs(expr.VerdictJump, terrariumChain.Name),
		),
	})
}

// addForwardChainUnrestricted creates a FORWARD chain for VM mode
// unrestricted policy that accepts all forwarded traffic after
// established/related checks.
func addForwardChainUnrestricted(conn Conn, table *nftables.Table) {
	policy := nftables.ChainPolicyDrop
	chain := conn.AddChain(&nftables.Chain{
		Name:     chainForward,
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
		Name:     chainForward,
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
