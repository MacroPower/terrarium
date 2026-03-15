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
