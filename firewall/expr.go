//go:build linux

package firewall

import (
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"go.jacobcolvin.com/terrarium/config"
)

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

func matchOIFName(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)},
	}
}

// notMatchOIFName matches packets whose output interface name is NOT
// the given name.
func notMatchOIFName(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(name)},
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

// notMatchL4Proto matches packets whose transport protocol is not the
// given protocol.
func notMatchL4Proto(proto byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{proto}},
	}
}

// ctDirReply is the IP_CT_DIR_REPLY value of the kernel, which names
// the reply direction of a conntrack flow. Neither the nftables
// library nor golang.org/x/sys/unix defines it.
const ctDirReply = 1

// matchCtDirectionReply matches packets that travel in the reply
// direction of their conntrack flow, as "ct direction reply" does.
// The original direction of a flow is the direction of its first
// packet, and the reply direction is the opposite one. A packet that
// conntrack does not track never matches.
func matchCtDirectionReply() []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeyDIRECTION, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{ctDirReply}},
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

// logGroupPrefix emits a `log group N prefix "..."` directive that
// pushes the matched packet onto nfnetlink_log group [group]. The
// userspace [nflog.Reader] binds to the same group. The prefix is the
// [logprefix] payload that decodes back to a [Kind] and rule index.
// Peer to [logPrefix] for syslog-bound emission.
func logGroupPrefix(group uint16, prefix string) []expr.Any {
	return []expr.Any{
		&expr.Log{
			Key:   1<<unix.NFTA_LOG_PREFIX | 1<<unix.NFTA_LOG_GROUP,
			Group: group,
			Data:  []byte(prefix),
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

// markPacket sets the packet fwmark to the given value, overwriting
// all bits. For bitwise OR (preserving existing bits), see [orMarkBit].
//
//nolint:unparam // mark is parameterized for symmetry with matchMark.
func markPacket(mark uint32) []expr.Any {
	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(mark),
		},
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			SourceRegister: true,
			Register:       1,
		},
	}
}

// orMarkBit sets a single fwmark bit via OR without clearing other
// bits. Uses the nftables Bitwise primitive: (mark & ~bit) ^ bit is
// equivalent to mark | bit. For full-overwrite marking, see
// [markPacket].
//
//nolint:unparam // bit is parameterized for symmetry with markPacket.
func orMarkBit(bit uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(^bit),
			Xor:            binaryutil.NativeEndian.PutUint32(bit),
		},
		&expr.Meta{
			Key:            expr.MetaKeyMARK,
			SourceRegister: true,
			Register:       1,
		},
	}
}

// matchMark matches packets that have the given fwmark bit(s) set,
// using bitmask matching: (mark & bit) != 0. This correctly identifies
// a mark bit regardless of other bits that may be set (e.g., [tproxyMark]
// 0x1 is matched even when [guardMark] 0x2 is also present: 0x3 & 0x1 != 0).
//
//nolint:unparam // mark is parameterized for symmetry with markPacket.
func matchMark(mark uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(mark),
			Xor:            make([]byte, 4),
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(0),
		},
	}
}

// notMatchMark matches packets that do NOT have the given fwmark
// bit(s) set: (mark & bit) == 0. Used to exclude locally-generated
// traffic (identified by [guardMark]) from TPROXY marking in
// mangle PREROUTING when br_netfilter re-enters the hook.
//
//nolint:unparam // mark is parameterized for symmetry with matchMark.
func notMatchMark(mark uint32) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(mark),
			Xor:            make([]byte, 4),
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(0),
		},
	}
}

// tproxyToPort applies TPROXY to redirect traffic to a local port.
// Requires per-AF rules (NFPROTO_IPV4 or NFPROTO_IPV6).
func tproxyToPort(family byte, port uint16) []expr.Any {
	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     binaryutil.BigEndian.PutUint16(port),
		},
		&expr.TProxy{
			Family:      family,
			TableFamily: family,
			RegPort:     1,
		},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}
}

// notMatchDstPort matches packets whose destination port is not the
// given value. Used to exclude DNS port 53 from TPROXY marking.
func notMatchDstPort(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2, // destination port
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
	}
}

// matchHasSocketOwner matches packets that have a socket owner (any
// UID). The meta skuid register load fails rule evaluation for
// packets without a socket owner (forwarded, kernel-originated). The
// CmpOpGte 0 comparison is structurally a no-op (all uint32 values
// are >= 0) but is required because a bare Meta load without a
// subsequent comparison leaves stale register state for later
// expressions.
func matchHasSocketOwner() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
		&expr.Cmp{Op: expr.CmpOpGte, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
	}
}

// matchSocketTransparent matches packets belonging to a socket with
// IP_TRANSPARENT set. TPROXY-established connections use transparent
// sockets; this identifies return/data packets that need re-marking
// for policy routing delivery to Envoy.
func matchSocketTransparent() []expr.Any {
	return []expr.Any{
		&expr.Socket{Key: expr.SocketKeyTransparent, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(1)},
	}
}

// dnatToLocal returns expressions that DNAT to 127.0.0.1 on the given
// port. IPv4 only -- there is no route_localnet equivalent for IPv6.
// Uses register 1 for the address and register 2 for the port.
func dnatToLocal(port uint16) []expr.Any {
	return []expr.Any{
		&expr.Immediate{
			Register: 1,
			Data:     net.IPv4(127, 0, 0, 1).To4(),
		},
		&expr.Immediate{
			Register: 2,
			Data:     binaryutil.BigEndian.PutUint16(port),
		},
		&expr.NAT{
			Type:        expr.NATTypeDestNAT,
			Family:      uint32(unix.NFPROTO_IPV4),
			RegAddrMin:  1,
			RegProtoMin: 2,
			Specified:   true,
		},
	}
}

// matchNotLocalDst matches packets whose destination address is not
// locally owned. Uses fib daddr type to check the address type
// against the routing table. Prevents intercepting container-to-host
// traffic in NAT PREROUTING.
func matchNotLocalDst() []expr.Any {
	return []expr.Any{
		&expr.Fib{
			Register:       1,
			FlagDADDR:      true,
			ResultADDRTYPE: true,
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     binaryutil.NativeEndian.PutUint32(unix.RTN_LOCAL),
		},
	}
}

// matchNotIIFName matches packets whose input interface name is not
// the given name. Used to scope rules to forwarded (non-loopback)
// traffic.
//
//nolint:unparam // name is parameterized for symmetry with matchOIFName.
func matchNotIIFName(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: ifname(name)},
	}
}

// metaKeyBridgeBroute is the NFT_META_BRI_BROUTE key of the kernel,
// which sets the broute flag of a frame. The key exists in kernels
// 6.4 and later. Neither the nftables library nor
// golang.org/x/sys/unix defines it.
const metaKeyBridgeBroute expr.MetaKey = 35

// matchPktTypeHost matches frames whose packet type is "host". In the
// prerouting hook of the bridge family, they are the frames whose
// destination MAC address is the address of the bridge device. A
// frame that arrives on any port of the bridge and holds a packet
// that the host routes or receives matches. A frame for another port
// of the bridge has the packet type "other host" and does not match.
func matchPktTypeHost() []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyPKTTYPE, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.PACKET_HOST}},
	}
}

// metaKeyIIFKind is the NFT_META_IIFKIND key of the kernel, which
// loads the link kind of the input interface. Neither the nftables
// library nor golang.org/x/sys/unix defines it.
const metaKeyIIFKind expr.MetaKey = 26

// matchIIFKind matches packets whose input interface has the given
// link kind, as "meta iifkind" does. The kernel gives a link kind to
// each device whose driver registers rtnl_link_ops, such as "veth"
// for a veth device and "tun" for a TAP device. A physical network
// interface has no link kind and never matches.
func matchIIFKind(kind string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: metaKeyIIFKind, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(kind)},
	}
}

// matchIIFName matches packets whose input interface has the given
// name.
func matchIIFName(name string) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)},
	}
}

// matchEtherType matches frames with the given EtherType, such as
// [unix.ETH_P_IP]. Bridge-family rules use it where inet-family rules
// use [matchNFProto], because the netfilter protocol of every frame
// in the bridge family is NFPROTO_BRIDGE.
func matchEtherType(etherType uint16) []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseLLHeader,
			Offset:       12, // EtherType
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(etherType)},
	}
}

// notMatchDstIPv6LinkLocal matches IPv6 packets whose destination
// address is outside fe80::/10. The caller must match the IPv6
// EtherType or protocol first.
func notMatchDstIPv6LinkLocal() []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       24, // destination address
			Len:          2,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            2,
			Mask:           []byte{0xff, 0xc0},
			Xor:            []byte{0x00, 0x00},
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0xfe, 0x80}},
	}
}

// matchIPv4Unfragmented matches IPv4 packets that hold a whole
// datagram, as "ip frag-off & 0x3fff == 0" does. A fragment has the
// "more fragments" flag or a fragment offset that is not zero. The
// caller must match the IPv4 EtherType or protocol first.
func matchIPv4Unfragmented() []expr.Any {
	return []expr.Any{
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       6, // flags and fragment offset
			Len:          2,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            2,
			Mask:           []byte{0x3f, 0xff},
			Xor:            []byte{0x00, 0x00},
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x00}},
	}
}

// matchIPv6Unfragmented matches IPv6 packets without a Fragment
// extension header, as "exthdr frag missing" does. Every fragment of
// a datagram has that header. The caller must match the IPv6
// EtherType or protocol first.
func matchIPv6Unfragmented() []expr.Any {
	return []expr.Any{
		&expr.Exthdr{
			DestRegister: 1,
			Type:         unix.IPPROTO_FRAGMENT,
			Len:          1,
			Flags:        unix.NFT_EXTHDR_F_PRESENT,
			Op:           expr.ExthdrOpIpv6,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
	}
}

// setBroute sets the broute flag of a frame, as "meta broute set 1"
// does. The bridge then does not handle the frame. The kernel passes
// it to the network layer as a packet that the bridge port received,
// and br_netfilter never sees it. Only the prerouting hook of the
// bridge family accepts this expression.
func setBroute() []expr.Any {
	return []expr.Any{
		&expr.Immediate{Register: 1, Data: []byte{1}},
		&expr.Meta{
			Key:            metaKeyBridgeBroute,
			SourceRegister: true,
			Register:       1,
		},
	}
}

// protoNum converts a protocol string to its IP protocol number.
func protoNum(proto string) byte {
	switch proto {
	case config.ProtoTCP:
		return unix.IPPROTO_TCP
	case config.ProtoUDP:
		return unix.IPPROTO_UDP
	default:
		return 0
	}
}
