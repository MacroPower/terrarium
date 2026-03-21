package config

import (
	"context"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
)

// ProxyPortBase is the base port added to destination ports to derive
// the Envoy proxy listen port. Ports above MaxProxyablePort overflow
// uint16 when offset and are rejected at validation time.
const ProxyPortBase = 15000

// MaxProxyablePort is the maximum port number that can be offset by
// ProxyPortBase without overflowing uint16.
const MaxProxyablePort = 65535 - ProxyPortBase

// CatchAllProxyPort is the Envoy listener port that handles TCP
// traffic not matched by any specialized per-port listener.
// Follows the Istio convention for port 15001.
const CatchAllProxyPort = 15001

// CatchAllUDPProxyPort is the Envoy listener port that handles UDP
// traffic via TPROXY. Unlike TCP (which uses NAT REDIRECT and
// SO_ORIGINAL_DST), UDP requires TPROXY to preserve the original
// destination address in the socket itself.
const CatchAllUDPProxyPort = 15002

// CIDRCatchAllPort is the Envoy listener port that handles CIDR TCP
// traffic. Unlike the main catch-all ([CatchAllProxyPort]) which
// rejects non-policy traffic via a blackhole cluster, this listener
// forwards to the original destination via the ORIGINAL_DST cluster.
// The TLS inspector extracts SNI for access log visibility.
const CIDRCatchAllPort = 15003

const (
	// ProtoTCP is the canonical protocol string for TCP.
	ProtoTCP = "TCP"
	// ProtoUDP is the canonical protocol string for UDP.
	ProtoUDP = "UDP"
	// ProtoSCTP is the canonical protocol string for SCTP.
	ProtoSCTP = "SCTP"
	// ProtoAny is the canonical protocol string for ANY (matches
	// TCP, UDP, and SCTP). Empty protocol is normalized to this value.
	ProtoAny = "ANY"
)

// isSvcName reports whether s is a valid IANA service name per RFC
// 6335: 1-15 characters, alphanumeric with non-consecutive hyphens,
// containing at least one letter. Matches Cilium's pkg/iana.IsSvcName.
func isSvcName(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}

	hasLetter := false
	prevHyphen := false

	for i, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			hasLetter = true
			prevHyphen = false

		case c >= '0' && c <= '9':
			prevHyphen = false
		case c == '-':
			if i == 0 || i == len(s)-1 || prevHyphen {
				return false
			}

			prevHyphen = true

		default:
			return false
		}
	}

	return hasLetter
}

// kubernetesPortAliases maps Kubernetes naming conventions to port
// numbers for service names not present in the IANA registry
// (/etc/services). These are checked as a fallback when
// [net.LookupPort] finds no match.
var kubernetesPortAliases = map[string]uint16{
	"dns":     53, // IANA name is "domain"
	"dns-tcp": 53, // Kubernetes convention for DNS over TCP
}

// ResolvePort converts a port string to a number. It accepts numeric
// strings ("443") and IANA service names ("https"). Named ports are
// resolved via [net.LookupPort] using the system's /etc/services
// file, which covers the full IANA registry. Names not found in
// /etc/services fall back to [kubernetesPortAliases] for common
// Kubernetes conventions. Container images without /etc/services
// (e.g. scratch) must use numeric ports.
//
// Uses base 10 (not base 0) because terrarium reads YAML config
// files, not Kubernetes API objects, so hex/octal/binary port literals
// are not meaningful.
func ResolvePort(ctx context.Context, s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err == nil {
		return uint16(n), nil
	}

	if !isSvcName(s) {
		return 0, fmt.Errorf("invalid port name syntax %q", s)
	}

	lower := strings.ToLower(s)

	port, lookupErr := net.DefaultResolver.LookupPort(ctx, "", lower)
	if lookupErr == nil && port >= 0 && port <= math.MaxUint16 {
		//nolint:gosec // G115: port is bounds-checked above.
		return uint16(port), nil
	}

	if n, ok := kubernetesPortAliases[lower]; ok {
		return n, nil
	}

	return 0, fmt.Errorf("unknown service name %q", s)
}

// normalizeProtocol converts a protocol string to the canonical form.
// Valid input is already uppercase (validated by [validProtocols]), so
// this mainly handles empty strings (mapped to [ProtoAny]). Under
// Cilium semantics, an omitted or ANY protocol means TCP, UDP, and
// SCTP (per SupportedProtocols(), which returns all three
// unconditionally).
func normalizeProtocol(proto string) string {
	switch proto {
	case ProtoTCP:
		return ProtoTCP
	case ProtoUDP:
		return ProtoUDP
	case ProtoSCTP:
		return ProtoSCTP
	case "", ProtoAny:
		return ProtoAny
	default:
		return ProtoAny
	}
}
