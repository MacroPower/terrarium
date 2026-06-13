package nflog

import (
	"encoding/binary"
	"net/netip"

	"golang.org/x/sys/unix"
)

// fiveTuple is the IP/L4 view of a single packet captured by
// nfnetlink_log. [parsePacket] populates it from a raw
// `Attribute.Payload` byte slice; consumers map it onto an
// [eventstore.Event]. Source IP is omitted because terrarium events
// attribute by destination only, which saves an allocation per packet.
type fiveTuple struct {
	dst   netip.Addr
	sport uint16
	dport uint16
	proto uint8
	// Either 4 or 6. Disambiguates ICMP (1) from ICMPv6 (58)
	// for the [eventstore.Protocol] mapping.
	family uint8
}

// extWalkLimit caps IPv6 extension-header chain walks. The kernel
// allows at most six fixed extension headers, which covers any
// well-formed packet. The cap also bounds work on crafted payloads.
const extWalkLimit = 6

// parsePacket reads the L3+L4 header from a raw packet payload and
// returns the populated [fiveTuple]. Returns ok=false on truncation,
// bogus IP version, illegal IHL, or an unwalkable IPv6 extension
// chain.
//
// L4 ports are read only for TCP and UDP. ICMP/ICMPv6 sets
// sport=dport=0; the [fiveTuple.family] field then distinguishes
// IPv4 ICMP from IPv6 ICMPv6. Other L4 protocols (SCTP, GRE, ESP,
// or any unrecognized value) also leave both ports zero.
func parsePacket(payload []byte) (fiveTuple, bool) {
	if len(payload) < 1 {
		return fiveTuple{}, false
	}

	switch payload[0] >> 4 {
	case 4:
		return parseIPv4(payload)
	case 6:
		return parseIPv6(payload)
	default:
		return fiveTuple{}, false
	}
}

func parseIPv4(payload []byte) (fiveTuple, bool) {
	if len(payload) < 20 {
		return fiveTuple{}, false
	}

	ihl := payload[0] & 0x0F
	if ihl < 5 {
		return fiveTuple{}, false
	}

	headerLen := int(ihl) * 4
	if len(payload) < headerLen {
		return fiveTuple{}, false
	}

	t := fiveTuple{
		family: 4,
		proto:  payload[9],
		dst:    netip.AddrFrom4([4]byte{payload[16], payload[17], payload[18], payload[19]}),
	}

	t.sport, t.dport = readL4Ports(payload[headerLen:], t.proto)

	return t, true
}

func parseIPv6(payload []byte) (fiveTuple, bool) {
	if len(payload) < 40 {
		return fiveTuple{}, false
	}

	var dst [16]byte

	copy(dst[:], payload[24:40])

	t := fiveTuple{
		family: 6,
		proto:  payload[6],
		dst:    netip.AddrFrom16(dst),
	}

	off := 40

	for range extWalkLimit {
		if !isIPv6ExtHeader(t.proto) {
			break
		}

		if off+2 > len(payload) {
			return t, true
		}

		var (
			next       = payload[off]
			extHdrLen  = payload[off+1]
			advance    int
			recognized = true
		)

		switch t.proto {
		case unix.IPPROTO_HOPOPTS, unix.IPPROTO_ROUTING, unix.IPPROTO_DSTOPTS:
			advance = (int(extHdrLen) + 1) * 8
		case unix.IPPROTO_FRAGMENT:
			advance = 8
		case unix.IPPROTO_AH:
			advance = (int(extHdrLen) + 2) * 4
		default:
			recognized = false
		}

		if !recognized {
			return t, true
		}

		if off+advance > len(payload) {
			return t, true
		}

		t.proto = next
		off += advance
	}

	t.sport, t.dport = readL4Ports(payload[off:], t.proto)

	return t, true
}

// isIPv6ExtHeader reports whether p is an IPv6 extension header that
// the chain walker recognizes. ESP (50) and any other unknown
// next-header are treated as terminal: the parser returns the current
// `proto` with sport=dport=0 rather than reading potentially encrypted
// or reserved bytes as L4 ports.
func isIPv6ExtHeader(p uint8) bool {
	switch p {
	case unix.IPPROTO_HOPOPTS,
		unix.IPPROTO_ROUTING,
		unix.IPPROTO_FRAGMENT,
		unix.IPPROTO_DSTOPTS,
		unix.IPPROTO_AH:
		return true
	}

	return false
}

// readL4Ports extracts source and destination ports from a TCP or UDP
// header. For other L4 protocols both ports are zero (ICMP/ICMPv6 has
// no port concept; SCTP, GRE, ESP, and unknown protocols are not
// parsed).
func readL4Ports(l4 []byte, proto uint8) (uint16, uint16) {
	if proto != unix.IPPROTO_TCP && proto != unix.IPPROTO_UDP {
		return 0, 0
	}

	if len(l4) < 4 {
		return 0, 0
	}

	return binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
}
