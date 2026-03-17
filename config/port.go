package config

import (
	"fmt"
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

const (
	// ProtoTCP is the canonical protocol string for TCP after YAML
	// normalization (uppercase).
	ProtoTCP = "TCP"
	// ProtoUDP is the canonical protocol string for UDP after YAML
	// normalization (uppercase).
	ProtoUDP = "UDP"
	// ProtoSCTP is the canonical protocol string for SCTP after YAML
	// normalization (uppercase).
	ProtoSCTP = "SCTP"
	// ProtoAny is the canonical protocol string for ANY (matches
	// TCP, UDP, and SCTP). Empty protocol is normalized to this value.
	ProtoAny = "ANY"
)

// wellKnownPorts maps IANA service names to their standard port
// numbers. Cilium resolves named ports dynamically from Kubernetes
// pod specs (containerPort.name); terrarium uses this static map
// instead since there are no pods to query.
var wellKnownPorts = map[string]uint16{
	"domain":     53,
	"dns":        53,
	"dns-tcp":    53, // Kubernetes naming convention, not IANA
	"ftp":        21,
	"ssh":        22,
	"smtp":       25,
	"http":       80,
	"ntp":        123,
	"ldap":       389,
	"https":      443,
	"ldaps":      636,
	"mysql":      3306,
	"postgresql": 5432,
	"redis":      6379,
	"syslog":     514,
}

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

// ResolvePort converts a port string to a number. It accepts numeric
// strings ("443") and well-known IANA service names ("https"). Cilium
// resolves named ports dynamically from Kubernetes pod specs; the
// terrarium uses a static [wellKnownPorts] map instead. Returns an error
// for unknown names, invalid syntax, or values outside 0-65535.
//
// Uses base 10 (not base 0) because terrarium reads YAML config
// files, not Kubernetes API objects, so hex/octal/binary port literals
// are not meaningful.
func ResolvePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err == nil {
		return uint16(n), nil
	}

	if !isSvcName(s) {
		return 0, fmt.Errorf("invalid port name syntax %q", s)
	}

	if n, ok := wellKnownPorts[strings.ToLower(s)]; ok {
		return n, nil
	}

	return 0, fmt.Errorf("unknown service name %q", s)
}

// normalizeProtocol converts a protocol string to the canonical
// uppercase form. Input is already uppercased by [normalizeEgressRule]
// so this mainly handles empty strings (mapped to [ProtoAny]).
// Under Cilium semantics, an omitted or ANY protocol means TCP, UDP,
// and SCTP (per SupportedProtocols(), which returns all three
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
