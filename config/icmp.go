package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ICMP address family constants used in [ICMPField.Family] and
// [ResolvedICMP.Family].
const (
	// FamilyIPv4 is the IPv4 address family for ICMP rules.
	FamilyIPv4 = "IPv4"
	// FamilyIPv6 is the IPv6 address family for ICMP rules.
	FamilyIPv6 = "IPv6"
)

// icmpIPv4TypeNameToCode maps CamelCase ICMPv4 type names to their
// numeric codes. icmpIPv6TypeNameToCode maps CamelCase ICMPv6 type
// names. Both are copied from Cilium's pkg/policy/api/icmp.go.
var (
	icmpIPv4TypeNameToCode = map[string]uint8{
		"EchoReply":              0,
		"DestinationUnreachable": 3,
		"Redirect":               5,
		"Echo":                   8,
		"EchoRequest":            8,
		"RouterAdvertisement":    9,
		"RouterSelection":        10,
		"RouterSolicitation":     10,
		"TimeExceeded":           11,
		"ParameterProblem":       12,
		"Timestamp":              13,
		"TimestampReply":         14,
		"Photuris":               40,
		"ExtendedEchoRequest":    42,
		"ExtendedEchoReply":      43,
	}

	icmpIPv6TypeNameToCode = map[string]uint8{
		"DestinationUnreachable":                 1,
		"PacketTooBig":                           2,
		"TimeExceeded":                           3,
		"ParameterProblem":                       4,
		"EchoRequest":                            128,
		"EchoReply":                              129,
		"MulticastListenerQuery":                 130,
		"MulticastListenerReport":                131,
		"MulticastListenerDone":                  132,
		"RouterSolicitation":                     133,
		"RouterAdvertisement":                    134,
		"NeighborSolicitation":                   135,
		"NeighborAdvertisement":                  136,
		"RedirectMessage":                        137,
		"RouterRenumbering":                      138,
		"ICMPNodeInformationQuery":               139,
		"ICMPNodeInformationResponse":            140,
		"InverseNeighborDiscoverySolicitation":   141,
		"InverseNeighborDiscoveryAdvertisement":  142,
		"HomeAgentAddressDiscoveryRequest":       144,
		"HomeAgentAddressDiscoveryReply":         145,
		"MobilePrefixSolicitation":               146,
		"MobilePrefixAdvertisement":              147,
		"DuplicateAddressRequestCodeSuffix":      157,
		"DuplicateAddressConfirmationCodeSuffix": 158,
		"ExtendedEchoRequest":                    160,
		"ExtendedEchoReply":                      161,
	}
)

// resolveICMPType converts a type name or numeric string to a uint8
// code for the given address family. Family must be [FamilyIPv4] or
// [FamilyIPv6] (already normalized by the caller).
func resolveICMPType(family, typeName string) (uint8, error) {
	// Try numeric first.
	n, err := strconv.ParseUint(typeName, 10, 8)
	if err == nil {
		return uint8(n), nil
	}

	var nameMap map[string]uint8

	switch family {
	case FamilyIPv4:
		nameMap = icmpIPv4TypeNameToCode
	case FamilyIPv6:
		nameMap = icmpIPv6TypeNameToCode
	default:
		return 0, fmt.Errorf("%w: %q", ErrICMPInvalidFamily, family)
	}

	code, ok := nameMap[typeName]
	if !ok {
		return 0, fmt.Errorf("%w: %q for %s", ErrICMPInvalidType, typeName, family)
	}

	return code, nil
}

// normalizeICMPFamily converts a case-insensitive family string to the
// canonical form ([FamilyIPv4] or [FamilyIPv6]). Empty input defaults
// to [FamilyIPv4].
func normalizeICMPFamily(family string) (string, error) {
	switch strings.ToLower(family) {
	case "", "ipv4":
		return FamilyIPv4, nil
	case "ipv6":
		return FamilyIPv6, nil
	default:
		return "", fmt.Errorf("%w: %q", ErrICMPInvalidFamily, family)
	}
}
