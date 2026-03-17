package config

import "errors"

var (
	// ErrFQDNSelectorEmpty is returned when an [FQDNSelector] has neither
	// matchName nor matchPattern set.
	ErrFQDNSelectorEmpty = errors.New("FQDN selector must have matchName or matchPattern")

	// ErrFQDNSelectorAmbiguous is returned when an [FQDNSelector] has both
	// matchName and matchPattern set. Cilium requires exactly one.
	ErrFQDNSelectorAmbiguous = errors.New("FQDN selector must have exactly one of matchName or matchPattern, not both")

	// ErrPortEmpty is returned when a [Port] has an empty port string.
	ErrPortEmpty = errors.New("port must not be empty")

	// ErrPortInvalid is returned when a [Port] has a non-numeric, out-of-range
	// (must be 0-65535), or unknown service name port string.
	ErrPortInvalid = errors.New("port must be 0-65535 or a known service name")

	// ErrProtocolInvalid is returned when a [Port] has an unrecognized
	// protocol. Valid values are TCP, UDP, SCTP, ANY, or empty (defaults
	// to ANY). Under Cilium semantics, ANY expands to TCP, UDP, and
	// SCTP (per SupportedProtocols(), which returns all three
	// unconditionally).
	ErrProtocolInvalid = errors.New("invalid protocol: must be TCP, UDP, SCTP, ANY, or empty")

	// ErrEndPortInvalid is returned when a [Port] has an endPort that
	// exceeds 65535 or is less than the port.
	ErrEndPortInvalid = errors.New("endPort must be >= port and <= 65535")

	// ErrCIDREmpty is returned when a [CIDRRule] in toCIDRSet has an
	// empty cidr string. This catches both explicit cidr: "" and
	// toCIDRSet: [{}] (where cidr defaults to empty). Cilium's
	// CIDRRule.sanitize() validates that exactly one of cidr,
	// cidrGroupRef, or cidrGroupSelector is set.
	ErrCIDREmpty = errors.New("toCIDRSet entry has empty cidr")

	// ErrCIDRInvalid is returned when a CIDR string cannot be parsed.
	ErrCIDRInvalid = errors.New("invalid CIDR")

	// ErrTCPForwardRequiresEgress is returned when a [TCPForward] is
	// specified but egress is blocked (empty list with no rules).
	ErrTCPForwardRequiresEgress = errors.New("tcpForwards requires egress rules or unrestricted egress")

	// ErrPathInvalidRegex is returned when a path in an [HTTPRule] is not
	// a valid regular expression.
	ErrPathInvalidRegex = errors.New("path must be a valid regex")

	// ErrMethodInvalidRegex is returned when a method in an [HTTPRule] is
	// not a valid regular expression.
	ErrMethodInvalidRegex = errors.New("method must be a valid regex")

	// ErrHostInvalidRegex is returned when a host in an [HTTPRule] is
	// not a valid regular expression.
	ErrHostInvalidRegex = errors.New("host must be a valid regex")

	// ErrHTTPHeaderEmpty is returned when an [HTTPRule] Headers entry
	// is an empty string.
	ErrHTTPHeaderEmpty = errors.New("HTTP header name must not be empty")

	// ErrHeaderMatchNameEmpty is returned when a [HeaderMatch] has an
	// empty Name field.
	ErrHeaderMatchNameEmpty = errors.New("headerMatch name must not be empty")

	// ErrHeaderMatchMismatchAction is returned when a [HeaderMatch]
	// sets a Mismatch action. Terrarium cannot enforce request
	// modification semantics (LOG, ADD, DELETE, REPLACE).
	ErrHeaderMatchMismatchAction = errors.New("headerMatch mismatch actions are not supported by terrarium")

	// ErrHeaderMatchSecret is returned when a [HeaderMatch] sets
	// a Secret field. Cilium uses this to reference Kubernetes
	// Secrets for populating header values. Terrarium does not run
	// inside Kubernetes and cannot resolve Secret references.
	ErrHeaderMatchSecret = errors.New(
		"headerMatch secret references are not supported by terrarium",
	)

	// ErrPortExceedsProxyRange is returned when a port exceeds the
	// maximum value that can be offset by [ProxyPortBase] without
	// overflowing uint16. Ports above 50535 produce proxy listen
	// ports above 65535.
	ErrPortExceedsProxyRange = errors.New("port exceeds proxy range (max 50535)")

	// ErrInvalidTCPForward is returned when a [TCPForward] entry has a
	// non-positive port or empty host.
	ErrInvalidTCPForward = errors.New("invalid tcp forward: port must be positive and host must be non-empty")

	// ErrDuplicateTCPForwardPort is returned when two [TCPForward] entries
	// specify the same port.
	ErrDuplicateTCPForwardPort = errors.New("duplicate tcp forward port")

	// ErrFQDNRequiresPorts is returned when an [EgressRule] has toFQDNs
	// with L7 HTTP rules but no toPorts with non-empty ports. L7
	// inspection requires explicit ports because Envoy needs per-port
	// listeners. FQDN rules without L7 are allowed without toPorts
	// (catch-all IP-level enforcement via ipsets).
	ErrFQDNRequiresPorts = errors.New(
		"toFQDNs with L7 rules require explicit toPorts with non-empty ports (Envoy needs per-port listeners)",
	)

	// ErrFQDNWildcardPort is returned when an [EgressRule] with toFQDNs
	// and L7 HTTP rules contains a wildcard port (port 0). L7
	// inspection requires concrete ports for Envoy proxy binding.
	// FQDN rules without L7 treat port 0 as catch-all (allow all
	// ports via ipsets).
	ErrFQDNWildcardPort = errors.New(
		"toFQDNs with L7 rules require explicit ports; wildcard port 0 is not supported",
	)

	// ErrExceptNotSubnet is returned when an except CIDR is not a subnet
	// of its parent CIDR. Cilium requires except entries to be contained
	// within the parent range.
	ErrExceptNotSubnet = errors.New("except CIDR must be a subnet of the parent CIDR")

	// ErrExceptAddressFamilyMismatch is returned when an except CIDR's
	// address family differs from its parent CIDR. An IPv6 except on an
	// IPv4 parent (or vice versa) can never match any address in the
	// parent range and silently has no effect.
	ErrExceptAddressFamilyMismatch = errors.New(
		"except CIDR address family must match parent CIDR",
	)

	// ErrL7RequiresL3 is returned when L7 rules are specified on a rule
	// without any L3 selectors. L7 HTTP rules require either toFQDNs
	// (for MITM inspection) or toCIDR/toCIDRSet (for plain HTTP
	// filtering). A toPorts-only rule with L7 has no routing context.
	ErrL7RequiresL3 = errors.New("L7 rules require toFQDNs or toCIDR/toCIDRSet selectors")

	// ErrFQDNPortRangeTooLarge is returned when a toFQDNs rule has a
	// port range (endPort) that would create too many Envoy listeners.
	// Each port in the range requires a separate listener, and large
	// ranges risk exhausting the proxy port space ([MaxProxyablePort]).
	ErrFQDNPortRangeTooLarge = errors.New(
		"toFQDNs port range too large: endPort - port must not exceed 100 (terrarium constraint: each port needs an Envoy listener)",
	)

	// ErrCIDRL7WithServerNames is returned when L7 HTTP rules are
	// combined with toCIDR/toCIDRSet and serverNames on the same rule.
	// ServerNames implies TLS traffic, and MITM for CIDR destinations
	// without known domain names is not feasible.
	ErrCIDRL7WithServerNames = errors.New(
		"L7 HTTP rules with toCIDR/toCIDRSet cannot use serverNames (implies TLS; use toFQDNs for TLS L7)",
	)

	// ErrL7RequiresTCP is returned when L7 HTTP rules are paired with
	// a non-TCP protocol. Envoy's HTTP connection manager requires TCP
	// streams; UDP, SCTP, and ANY are invalid with L7 HTTP rules.
	// Empty protocol is allowed (implies TCP). Cilium's
	// PortRule.sanitize() rejects empty too (it normalizes to ANY
	// first), but terrarium intentionally permits it to reduce
	// boilerplate.
	ErrL7RequiresTCP = errors.New("L7 HTTP rules can only apply to TCP")

	// ErrL7WithWildcardPort is returned when L7 rules are used with
	// port 0 (wildcard). Cilium rejects this combination because L7
	// inspection requires a concrete port for proxy binding.
	ErrL7WithWildcardPort = errors.New("L7 rules cannot be used when port is 0")

	// ErrPortsTooMany is returned when a [PortRule] has more than
	// [maxPorts] entries. Cilium enforces this limit via
	// +kubebuilder:validation:MaxItems=40 on PortRule.Ports.
	ErrPortsTooMany = errors.New("too many ports: maximum 40 per port rule")

	// ErrEndPortNegative is returned when a [Port] has a negative
	// endPort value. Cilium uses int32 with +kubebuilder:validation:Minimum=0
	// to reject negative values at admission.
	ErrEndPortNegative = errors.New("endPort must not be negative")

	// ErrPartialWildcardWithL7 is returned when a matchPattern with
	// wildcards in non-leading positions (or bare wildcards like "*",
	// "**") is used with L7 HTTP rules. MITM certificate generation
	// requires a wildcard-free suffix for the SAN (RFC 6125 only
	// supports *.suffix form). Patterns like "api.*.example.com",
	// "*.ci*.io", and "*.*.cilium.io" all have wildcards in the
	// suffix after stripping any leading "*." or "**." prefix.
	ErrPartialWildcardWithL7 = errors.New(
		"matchPattern with non-leading wildcards cannot be used with L7 HTTP rules; MITM certs require a wildcard-free suffix",
	)

	// ErrFQDNNameInvalidChars is returned when a matchName contains
	// characters outside the DNS allowlist [a-z0-9._-]. Matches
	// Cilium's allowedMatchNameChars validation.
	ErrFQDNNameInvalidChars = errors.New(
		"matchName contains invalid characters: only a-z, 0-9, '.', '-', and '_' are allowed",
	)

	// ErrFQDNPatternInvalidChars is returned when a matchPattern
	// contains characters outside the pattern allowlist [a-z0-9._*-].
	// Matches Cilium's allowedPatternChars validation.
	ErrFQDNPatternInvalidChars = errors.New(
		"matchPattern contains invalid characters: only a-z, 0-9, '.', '-', '_', and '*' are allowed",
	)

	// ErrFQDNTooLong is returned when a matchName or matchPattern
	// exceeds 255 characters. Matches Cilium's MaxFQDNLength constant
	// and kubebuilder MaxLength validation.
	ErrFQDNTooLong = errors.New("FQDN selector exceeds maximum length of 255 characters")

	// ErrFQDNPatternCompile is returned when a matchPattern or
	// matchName produces an anchored regex that fails to compile.
	// The restricted character allowlist makes this extremely
	// unlikely, but compiling during validation provides
	// defense-in-depth against panics in [Config.CompileFQDNPatterns].
	ErrFQDNPatternCompile = errors.New("FQDN pattern produces invalid regex")

	// ErrFQDNWithCIDR is returned when an [EgressRule] combines toFQDNs
	// with toCIDR or toCIDRSet. Under CiliumNetworkPolicy semantics,
	// toFQDNs is mutually exclusive with other L3 selectors within a
	// single rule; use separate rules instead.
	ErrFQDNWithCIDR = errors.New(
		"toFQDNs cannot be combined with toCIDR or toCIDRSet in the same rule; use separate rules",
	)

	// ErrCIDRAndCIDRSetMixed is returned when an [EgressRule] combines
	// toCIDR with toCIDRSet. These must be in separate rules.
	//
	// In Cilium, EgressCommonRule.sanitize() calls l3Members() to build
	// a map of all L3 selector fields (ToCIDR, ToCIDRSet, ToEndpoints,
	// ToEntities, ToServices, ToGroups, ToNodes) with their counts,
	// then performs a pairwise mutual-exclusivity check: if any two
	// different L3 fields both have count >0, Cilium rejects the rule
	// with "combining <field1> and <field2> is not supported yet".
	// See pkg/policy/api/egress.go (EgressCommonRule.sanitize, l3Members).
	//
	// Because our [EgressRule] only supports ToCIDR and ToCIDRSet as L3
	// selectors (we have no ToEndpoints, ToEntities, ToServices, ToGroups,
	// or ToNodes), the ToCIDR + ToCIDRSet pair is the only combination
	// that can trigger this check. ToFQDNs is handled separately by
	// [ErrFQDNWithCIDR] before we reach this point; Cilium includes
	// ToFQDNs in the same unified l3Members() pairwise check, but
	// the outcome is equivalent since both reject the combination.
	//
	// Note: Cilium's l3Members() uses countNonGeneratedCIDRRules for
	// ToCIDRSet and countNonGeneratedEndpoints for ToEndpoints, so that
	// auto-generated entries (from ToServices/ToFQDNs expansion at
	// runtime) do not count toward the mutual-exclusivity check. The
	// terrarium has no equivalent of Generated entries since we never
	// perform ToServices expansion or runtime identity resolution, so
	// this distinction is irrelevant here.
	ErrCIDRAndCIDRSetMixed = errors.New(
		"toCIDR and toCIDRSet cannot be combined in the same rule; use separate rules",
	)

	// ErrTCPForwardPortConflict is returned when a [TCPForward] port
	// overlaps with a resolved port.
	ErrTCPForwardPortConflict = errors.New("tcp forward port conflicts with resolved ports")

	// ErrServerNamesRequiresL3 is returned when serverNames is used on
	// a toPorts entry without an L3 selector (toCIDR, toCIDRSet, or
	// toFQDNs) on the same rule. With toFQDNs, serverNames is
	// accepted but ignored since FQDN rules already control allowed
	// domains via their own SNI filter chain.
	ErrServerNamesRequiresL3 = errors.New(
		"serverNames requires toCIDR, toCIDRSet, or toFQDNs on the same rule",
	)

	// ErrServerNamesRequiresTCP is returned when serverNames is used
	// with a non-TCP protocol. SNI inspection requires TCP.
	ErrServerNamesRequiresTCP = errors.New("serverNames requires TCP protocol")

	// ErrServerNamesEmpty is returned when a serverNames entry is an
	// empty string. Cilium's PortRule.sanitize() explicitly checks for
	// empty server names via [slices.Contains].
	ErrServerNamesEmpty = errors.New("serverNames must not contain empty strings")

	// ErrServerNamesInvalidHostname is returned when a serverNames
	// entry contains invalid hostname characters.
	ErrServerNamesInvalidHostname = errors.New(
		"serverNames entry contains invalid characters: only a-z, 0-9, '.', '-', '_', and '*' are allowed",
	)

	// ErrServerNamesInvalidWildcard is returned when a serverNames
	// entry uses a bare wildcard ("*") without a dot-separated suffix.
	// Bare wildcards have no meaningful SNI matching semantics.
	ErrServerNamesInvalidWildcard = errors.New(
		"serverNames entry must not be a bare wildcard; use a pattern like *.example.com",
	)

	// ErrICMPInvalidType is returned when an [ICMPField] Type is not
	// a valid numeric code (0-255) or recognized CamelCase name for
	// the specified address family.
	ErrICMPInvalidType = errors.New("invalid ICMP type")

	// ErrICMPInvalidFamily is returned when an [ICMPField] Family is
	// not "IPv4", "IPv6", or empty.
	ErrICMPInvalidFamily = errors.New("invalid ICMP family: must be IPv4, IPv6, or empty")

	// ErrICMPWithToPorts is returned when an [EgressRule] or
	// [EgressDenyRule] combines icmps with toPorts. Cilium rejects
	// this combination (rule_validation.go:328-330).
	ErrICMPWithToPorts = errors.New("icmps and toPorts cannot be combined in the same rule")

	// ErrICMPFieldsTooMany is returned when an [ICMPRule] has more
	// than 40 fields. Matches Cilium's +kubebuilder:validation:MaxItems=40.
	ErrICMPFieldsTooMany = errors.New("too many ICMP fields: maximum 40 per ICMP rule")

	// ErrICMPTypeRequired is returned when an [ICMPField] has an
	// empty Type string.
	ErrICMPTypeRequired = errors.New("ICMP type must not be empty")

	// ErrICMPWithFQDNs is returned when an [EgressRule] combines icmps
	// with toFQDNs. In Cilium's BPF datapath, ICMP would be AND'd with
	// FQDN-resolved IPs, but terrarium cannot implement this because
	// FQDN ipsets are designed for TCP/UDP port-based filtering and
	// ICMP has no ports. Use separate rules instead.
	ErrICMPWithFQDNs = errors.New("icmps and toFQDNs cannot be combined in the same rule")

	// ErrDenyRuleToFQDNs is returned when an [EgressDenyRule] contains
	// toFQDNs. Cilium's EgressDenyRule type structurally lacks a
	// ToFQDNs field; deny rules cannot target FQDNs. The stub field
	// on [EgressDenyRule] exists to capture the YAML and produce this
	// targeted error instead of a generic unknown-field parse error.
	ErrDenyRuleToFQDNs = errors.New(
		"deny rules do not support FQDN selectors: Cilium's EgressDenyRule has no ToFQDNs field",
	)

	// ErrDenyRuleServerNames is returned when an [EgressDenyRule]
	// contains serverNames on a toPorts entry. Deny CIDR chains do
	// not perform SNI inspection, so serverNames on deny rules would
	// be silently ignored. Reject to avoid misconfiguration.
	ErrDenyRuleServerNames = errors.New("egressDeny rules do not support serverNames")

	// ErrDenyRuleL7 is returned when an [EgressDenyRule] contains L7
	// rules in toPorts. Cilium's egressDeny does not support L7.
	ErrDenyRuleL7 = errors.New("egressDeny rules do not support L7 rules")

	// ErrDenyRulePortsEmpty is returned when an [EgressDenyRule] has
	// a toPorts entry with an empty Ports list. Unlike allow rules
	// (where an empty Ports list can imply a wildcard via L7 rules),
	// deny rules have no L7 layer, so an empty Ports list has no
	// meaningful scope.
	ErrDenyRulePortsEmpty = errors.New("egressDeny toPorts entry must have at least one port")

	// ErrDenyRuleWildcardPort is returned when an [EgressDenyRule]
	// uses port 0 (wildcard). The semantic intent of a wildcard deny
	// port is ambiguous; use explicit port ranges or toCIDR without
	// toPorts for broad deny rules.
	ErrDenyRuleWildcardPort = errors.New("egressDeny rules do not support wildcard port 0")

	// ErrDenyEntitiesMixedL3 is returned when an [EgressDenyRule]
	// combines toEntities with another L3 selector (toCIDR or
	// toCIDRSet). Use separate rules instead.
	ErrDenyEntitiesMixedL3 = errors.New(
		"egressDeny toEntities cannot be combined with toCIDR or toCIDRSet in the same rule; use separate rules",
	)

	// ErrEntitiesMixedL3 is returned when an [EgressRule] combines
	// toEntities with another L3 selector (toCIDR, toCIDRSet, or
	// toFQDNs). Cilium's EgressCommonRule.sanitize() rejects any
	// rule combining two different L3 selector fields; use separate
	// rules instead.
	ErrEntitiesMixedL3 = errors.New(
		"toEntities cannot be combined with toCIDR, toCIDRSet, or toFQDNs in the same rule; use separate rules",
	)

	// ErrUnsupportedEntity is returned when a [EgressRule] has a
	// toEntities value that terrarium does not support. Only "world",
	// "world-ipv4", "world-ipv6", and "all" are supported; other
	// Cilium entities (host, cluster, kube-apiserver, etc.) require
	// cluster infrastructure.
	ErrUnsupportedEntity = errors.New(
		"unsupported entity: only 'world', 'world-ipv4', 'world-ipv6', and 'all' are supported by terrarium",
	)

	// ErrEndpointsMixedL3 is returned when an [EgressRule] or
	// [EgressDenyRule] combines toEndpoints: [{}] (wildcard) with
	// another L3 selector (toCIDR, toCIDRSet, or toFQDNs). Use
	// separate rules instead.
	ErrEndpointsMixedL3 = errors.New(
		"toEndpoints cannot be combined with toCIDR, toCIDRSet, or toFQDNs in the same rule; use separate rules",
	)

	// ErrUnsupportedSelector is returned when an [EgressRule] contains a
	// CiliumNetworkPolicy selector that terrarium does not implement.
	// Terrarium only supports toFQDNs, toPorts, toCIDR, and toCIDRSet.
	// Cilium selectors like toEndpoints, toEntities, toServices, toNodes,
	// and toGroups require cluster identity infrastructure that does not
	// exist in terrarium.
	ErrUnsupportedSelector = errors.New("unsupported egress selector")

	// ErrUnsupportedFeature is returned when a type contains a
	// Cilium feature field that terrarium does not implement.
	// The field is parsed from YAML to produce a clear error instead
	// of an opaque "unknown field" parse failure.
	ErrUnsupportedFeature = errors.New("unsupported feature")

	// ErrDNSRuleRequiresPort53 is returned when a DNS L7 rule appears
	// on a toPorts entry that does not include port 53. Cilium requires
	// rules.dns only on port-53 entries.
	ErrDNSRuleRequiresPort53 = errors.New(
		"DNS L7 rules require port 53 in the toPorts entry",
	)

	// ErrDNSRulePortRange is returned when a toPorts entry with DNS
	// L7 rules has a port entry where endPort > port. Cilium's
	// PortProtocol.sanitize() rejects port ranges on DNS rules.
	ErrDNSRulePortRange = errors.New("DNS rules do not support port ranges")

	// ErrL7MutualExclusivity is returned when a toPorts entry has both
	// rules.http and rules.dns set. Cilium's L7Rules.sanitize() counts
	// L7 rule types and rejects any PortRule with more than one type.
	ErrL7MutualExclusivity = errors.New(
		"only one L7 rule type (HTTP or DNS) is allowed per toPorts entry",
	)

	// ErrDNSRuleSelectorEmpty is returned when a [DNSRule] has neither
	// matchName nor matchPattern set.
	ErrDNSRuleSelectorEmpty = errors.New("DNS rule must have matchName or matchPattern")

	// ErrDNSRuleSelectorAmbiguous is returned when a [DNSRule] has both
	// matchName and matchPattern set. Exactly one must be specified.
	ErrDNSRuleSelectorAmbiguous = errors.New("DNS rule must have exactly one of matchName or matchPattern, not both")

	// ErrInvalidEnvoyLogLevel is returned when [EnvoySettings.LogLevel]
	// is not one of the values accepted by Envoy's --log-level flag.
	ErrInvalidEnvoyLogLevel = errors.New(
		"envoy logLevel must be one of: trace, debug, info, warning, error, critical, off",
	)

	// ErrInvalidEnvoyDrainTimeout is returned when
	// [EnvoySettings.DrainTimeout] is negative.
	ErrInvalidEnvoyDrainTimeout = errors.New("envoy drainTimeout must not be negative")

	// ErrInvalidEnvoyStartupTimeout is returned when
	// [EnvoySettings.StartupTimeout] is negative.
	ErrInvalidEnvoyStartupTimeout = errors.New("envoy startupTimeout must not be negative")

	// ErrInvalidEnvoyMaxConnections is returned when
	// [EnvoySettings.MaxDownstreamConnections] is negative.
	ErrInvalidEnvoyMaxConnections = errors.New("envoy maxDownstreamConnections must not be negative")
)
