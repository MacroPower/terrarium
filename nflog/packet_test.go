package nflog_test

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.jacobcolvin.com/terrarium/nflog"
)

// makeIPv4 builds an IPv4 packet header (no options, IHL=5) with the
// given proto byte. l4 is appended after the 20-byte header.
func makeIPv4(_ *testing.T, proto byte, l4 []byte) []byte {
	hdr := []byte{
		0x45,                  // version 4, IHL 5
		0x00,                  // dscp/ecn
		0x00, 0x00,            // total length
		0x00, 0x00,            // id
		0x00, 0x00,            // flags / frag
		0x40,                  // TTL
		proto,                 // protocol
		0x00, 0x00,            // checksum
		1, 1, 1, 1,            // src 1.1.1.1
		8, 8, 8, 8,            // dst 8.8.8.8
	}

	return append(hdr, l4...)
}

// makeIPv4Options builds an IPv4 header with `optBytes` of options
// (must be a multiple of 4) — IHL = 5 + optBytes/4.
func makeIPv4Options(t *testing.T, proto byte, optBytes int, l4 []byte) []byte {
	t.Helper()

	require.Zero(t, optBytes%4, "optBytes must be 4-byte aligned")

	ihl := 5 + optBytes/4
	require.LessOrEqual(t, ihl, 15, "IHL exceeds 4-bit field")

	hdr := []byte{
		0x40 | byte(ihl),
		0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0x40,
		proto,
		0x00, 0x00,
		10, 0, 0, 1,
		10, 0, 0, 2,
	}

	hdr = append(hdr, make([]byte, optBytes)...)

	return append(hdr, l4...)
}

// makeIPv6 builds an IPv6 packet header followed by l4.
func makeIPv6(_ *testing.T, nextHdr byte, l4 []byte) []byte {
	hdr := []byte{
		0x60, 0x00, 0x00, 0x00, // version 6 + flow label
		0x00, 0x00, // payload length
		nextHdr,
		0x40, // hop limit
		// src ::1
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		// dst 2001:db8::1
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
	}

	return append(hdr, l4...)
}

func tcpUDPHeader(sport, dport uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:2], sport)
	binary.BigEndian.PutUint16(b[2:4], dport)

	return b
}

func TestParsePacketIPv4(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		proto     byte
		l4        []byte
		family    uint8
		sport     uint16
		dport     uint16
		wantOK    bool
		wantDst   netip.Addr
		wantProto uint8
	}{
		"TCP": {
			proto:     unix.IPPROTO_TCP,
			l4:        tcpUDPHeader(54321, 80),
			wantOK:    true,
			family:    4,
			sport:     54321,
			dport:     80,
			wantDst:   netip.AddrFrom4([4]byte{8, 8, 8, 8}),
			wantProto: unix.IPPROTO_TCP,
		},
		"UDP": {
			proto:     unix.IPPROTO_UDP,
			l4:        tcpUDPHeader(33333, 53),
			wantOK:    true,
			family:    4,
			sport:     33333,
			dport:     53,
			wantDst:   netip.AddrFrom4([4]byte{8, 8, 8, 8}),
			wantProto: unix.IPPROTO_UDP,
		},
		"ICMP zeroed ports": {
			proto:     unix.IPPROTO_ICMP,
			l4:        []byte{0x08, 0x00, 0x00, 0x00},
			wantOK:    true,
			family:    4,
			sport:     0,
			dport:     0,
			wantDst:   netip.AddrFrom4([4]byte{8, 8, 8, 8}),
			wantProto: unix.IPPROTO_ICMP,
		},
		"SCTP zeroed ports": {
			proto:     132,
			l4:        []byte{0x00, 0x50, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00},
			wantOK:    true,
			family:    4,
			sport:     0,
			dport:     0,
			wantDst:   netip.AddrFrom4([4]byte{8, 8, 8, 8}),
			wantProto: 132,
		},
		"GRE zeroed ports": {
			proto:     47,
			l4:        []byte{0, 0, 0, 0},
			wantOK:    true,
			family:    4,
			sport:     0,
			dport:     0,
			wantProto: 47,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pkt := makeIPv4(t, tt.proto, tt.l4)

			got, ok := nflog.ParsePacket(pkt)
			assert.Equal(t, tt.wantOK, ok)

			if !ok {
				return
			}

			assert.Equal(t, tt.family, got.Family)
			assert.Equal(t, tt.sport, got.Sport)
			assert.Equal(t, tt.dport, got.Dport)
			assert.Equal(t, tt.wantProto, got.Proto)
		})
	}
}

func TestParsePacketIPv4Options(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		optBytes int
	}{
		"IHL=6 (4 byte option)":    {optBytes: 4},
		"IHL=15 (40 byte options)": {optBytes: 40},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pkt := makeIPv4Options(t, unix.IPPROTO_TCP, tt.optBytes, tcpUDPHeader(1111, 443))

			got, ok := nflog.ParsePacket(pkt)
			require.True(t, ok)
			assert.Equal(t, uint8(4), got.Family)
			assert.Equal(t, uint16(1111), got.Sport)
			assert.Equal(t, uint16(443), got.Dport)
		})
	}
}

func TestParsePacketIPv4IllegalIHL(t *testing.T) {
	t.Parallel()

	hdr := make([]byte, 20)
	hdr[0] = 0x44 // version 4, IHL 4 (illegal — minimum is 5)

	_, ok := nflog.ParsePacket(hdr)
	assert.False(t, ok, "IHL<5 must be rejected")
}

func TestParsePacketBogusVersion(t *testing.T) {
	t.Parallel()

	hdr := make([]byte, 20)
	hdr[0] = 0x70 // version 7

	_, ok := nflog.ParsePacket(hdr)
	assert.False(t, ok)
}

func TestParsePacketTruncatedAtBoundaries(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		payload []byte
		wantOK  bool
	}{
		"empty":              {payload: nil, wantOK: false},
		"too short for IPv4": {payload: []byte{0x45}, wantOK: false},
		"IPv4 hdr only no L4": {
			// IPv4 header with truncated L4 still returns ok=true
			// (best-effort) but with zero ports.
			payload: makeIPv4(nil, unix.IPPROTO_TCP, []byte{0x00}),
			wantOK:  true,
		},
		"IPv6 too short for header": {payload: []byte{0x60, 0x00}, wantOK: false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, ok := nflog.ParsePacket(tt.payload)

			assert.Equal(t, tt.wantOK, ok)

			if name == "IPv4 hdr only no L4" && ok {
				assert.Zero(t, got.Sport)
				assert.Zero(t, got.Dport)
			}
		})
	}
}

func TestParsePacketIPv6NoExtensions(t *testing.T) {
	t.Parallel()

	pkt := makeIPv6(t, unix.IPPROTO_TCP, tcpUDPHeader(40000, 22))

	got, ok := nflog.ParsePacket(pkt)
	require.True(t, ok)
	assert.Equal(t, uint8(6), got.Family)
	assert.Equal(t, uint16(40000), got.Sport)
	assert.Equal(t, uint16(22), got.Dport)
	assert.Equal(t, uint8(unix.IPPROTO_TCP), got.Proto)
}

func TestParsePacketIPv6ExtensionHeaders(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		buildPayload func(t *testing.T) []byte
		wantOK       bool
		wantProto    uint8
		wantPort     uint16
	}{
		"Hop-by-Hop -> TCP": {
			buildPayload: func(t *testing.T) []byte {
				t.Helper()

				ext := []byte{unix.IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0}

				return append(makeIPv6(t, unix.IPPROTO_HOPOPTS, ext), tcpUDPHeader(0, 443)...)
			},
			wantOK:    true,
			wantProto: unix.IPPROTO_TCP,
			wantPort:  443,
		},
		"Fragment -> UDP": {
			buildPayload: func(t *testing.T) []byte {
				t.Helper()

				ext := []byte{unix.IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0}

				return append(makeIPv6(t, unix.IPPROTO_FRAGMENT, ext), tcpUDPHeader(0, 53)...)
			},
			wantOK:    true,
			wantProto: unix.IPPROTO_UDP,
			wantPort:  53,
		},
		"Authentication Header -> TCP": {
			buildPayload: func(t *testing.T) []byte {
				t.Helper()

				ext := make([]byte, 12)
				ext[0] = unix.IPPROTO_TCP
				ext[1] = 1

				return append(makeIPv6(t, unix.IPPROTO_AH, ext), tcpUDPHeader(0, 8080)...)
			},
			wantOK:    true,
			wantProto: unix.IPPROTO_TCP,
			wantPort:  8080,
		},
		"ESP terminates walk": {
			buildPayload: func(t *testing.T) []byte {
				t.Helper()

				return append(makeIPv6(t, unix.IPPROTO_ESP, nil), 0, 0, 0, 0)
			},
			wantOK:    true,
			wantProto: unix.IPPROTO_ESP,
			wantPort:  0,
		},
		"Unknown extension terminates walk": {
			buildPayload: func(t *testing.T) []byte {
				t.Helper()

				return append(makeIPv6(t, 250, nil), 1, 2, 3, 4)
			},
			wantOK:    true,
			wantProto: 250,
			wantPort:  0,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pkt := tt.buildPayload(t)

			got, ok := nflog.ParsePacket(pkt)
			assert.Equal(t, tt.wantOK, ok)

			if !ok {
				return
			}

			assert.Equal(t, uint8(6), got.Family)
			assert.Equal(t, tt.wantProto, got.Proto)
			assert.Equal(t, tt.wantPort, got.Dport)
		})
	}
}

func TestParsePacketIPv6BoundedExtensionWalk(t *testing.T) {
	t.Parallel()

	buildChain := func(t *testing.T, depth int) []byte {
		t.Helper()

		hdr := makeIPv6(t, unix.IPPROTO_HOPOPTS, nil)

		for i := range depth - 1 {
			next := byte(unix.IPPROTO_HOPOPTS)
			if i == depth-2 {
				next = unix.IPPROTO_TCP
			}

			hdr = append(hdr, next, 0, 0, 0, 0, 0, 0, 0)
		}

		hdr = append(hdr, unix.IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0)

		return append(hdr, tcpUDPHeader(0, 443)...)
	}

	pkt := buildChain(t, nflog.ExtWalkLimit)
	got, ok := nflog.ParsePacket(pkt)
	require.True(t, ok)
	assert.Equal(t, uint8(unix.IPPROTO_TCP), got.Proto)

	pkt = buildChain(t, nflog.ExtWalkLimit+2)
	got, ok = nflog.ParsePacket(pkt)
	require.True(t, ok)
	assert.Equal(t, uint8(unix.IPPROTO_HOPOPTS), got.Proto)
	assert.Zero(t, got.Dport)
}

func TestParsePacketIPv6ExtensionRunsOffEnd(t *testing.T) {
	t.Parallel()

	ext := []byte{unix.IPPROTO_TCP, 50}
	pkt := append(makeIPv6(t, unix.IPPROTO_HOPOPTS, ext), tcpUDPHeader(0, 0)...)

	_, ok := nflog.ParsePacket(pkt)
	assert.True(t, ok, "graceful early stop, not an error")
}
