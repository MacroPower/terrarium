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
	// protocol. Valid values are TCP, UDP, ANY, or empty (defaults
	// to ANY).
	ErrProtocolInvalid = errors.New("invalid protocol: must be TCP, UDP, ANY, or empty")

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

	// ErrHeaderMatchNameEmpty is returned when a [HeaderMatch] has an
	// empty Name field.
	ErrHeaderMatchNameEmpty = errors.New("headerMatch name must not be empty")

	// ErrHeaderMatchMismatchInvalid is returned when a [HeaderMatch]
	// sets a Mismatch action that is not one of the recognized values
	// (LOG, ADD, DELETE, REPLACE).
	ErrHeaderMatchMismatchInvalid = errors.New(
		"headerMatch mismatch must be one of LOG, ADD, DELETE, REPLACE",
	)

	// ErrHeaderMatchMismatchTooMany is returned when the HTTP rules
	// that one request can match hold more than 8 [HeaderMatch] entries
	// with the [MismatchADD], [MismatchDELETE], or [MismatchLOG]
	// action. One [HTTPRule] with more than 8 of these entries gives
	// the same error. A [MismatchDELETE] entry without a value does not
	// count. The number of Envoy routes for the rules doubles with each
	// entry that counts. See [MismatchRuleSets] for the rules that one
	// request can match.
	ErrHeaderMatchMismatchTooMany = errors.New(
		"too many headerMatches with mismatch ADD, DELETE, or LOG in the http rules that one request can match: the maximum is 8 (terrarium constraint: each one doubles the Envoy routes of the rules)",
	)

	// ErrHeaderMatchMismatchReservedHeader is returned when a
	// [HeaderMatch] names the Host header or a header whose name
	// starts with ":", and its Mismatch action changes the header. The
	// actions that change the header are [MismatchADD],
	// [MismatchREPLACE], and [MismatchDELETE] with a value. Envoy does
	// not load a route that adds or removes one of these headers.
	ErrHeaderMatchMismatchReservedHeader = errors.New(
		"headerMatch mismatch must not change the Host header or a header that starts with \":\" (terrarium constraint: an Envoy route cannot add or remove these headers)",
	)

	// ErrHeaderMatchMismatchAfterChange is returned when a
	// [HeaderMatch] logs or changes a header that an earlier entry of
	// the same [HTTPRule] changes. The actions that change the header
	// are [MismatchADD], [MismatchREPLACE], and [MismatchDELETE] with a
	// value, and [MismatchLOG] logs it. Cilium compares the later entry
	// with the header as the earlier entry left it. Terrarium compares
	// every entry with the request that the client sent.
	ErrHeaderMatchMismatchAfterChange = errors.New(
		"headerMatch mismatch must not log or change a header that an earlier headerMatch of the http rule changes (terrarium constraint: every headerMatch sees the request that the client sent)",
	)

	// ErrHeaderMatchMismatchAcrossRules is returned when a
	// [HeaderMatch] changes a header that another [HTTPRule] reads, and
	// one request can match both rules. Both rules have a Mismatch
	// action. The other rule reads each header that it requires. It
	// also reads each header that one of its [HeaderMatch] entries
	// compares to deny, log, or change the request. Cilium runs the
	// rules one after the other, so the later rule compares the header
	// as the earlier rule left it. Terrarium compares every rule with
	// the request that the client sent. Two [MismatchREPLACE] entries
	// with one name and one value give the same result in both, so
	// they pass.
	ErrHeaderMatchMismatchAcrossRules = errors.New(
		"headerMatch mismatch must not change a header that another http rule with a mismatch action reads when one request can match both rules (terrarium constraint: every http rule sees the request that the client sent)",
	)

	// ErrHTTPRuleMismatchPaths is returned when two [HTTPRule] entries
	// with a Mismatch action have different Path patterns, and one
	// request can match both rules. Cilium applies the actions of both
	// rules to such a request. One Envoy route applies the actions of a
	// request, and a route matches one path pattern. Two rules count as
	// rules that one request can match unless terrarium proves
	// otherwise. See [MismatchRuleSets] for the proof.
	ErrHTTPRuleMismatchPaths = errors.New(
		"http rules with a headerMatch mismatch action must not match one request through different path patterns (terrarium constraint: an Envoy route matches one path pattern, and two rules count as rules that one request can match unless terrarium proves otherwise)",
	)

	// ErrHTTPRuleMismatchTooMany is returned when one request can match
	// more than 4 [HTTPRule] entries with a Mismatch action. Terrarium
	// builds Envoy routes for each combination of these rules. See
	// [MismatchRuleSets] for the rules that one request can match.
	ErrHTTPRuleMismatchTooMany = errors.New(
		"too many http rules with a headerMatch mismatch action that one request can match: the maximum is 4 (terrarium constraint: each one doubles the Envoy route sets of the others)",
	)

	// ErrHTTPRuleMismatchRoutesTooMany is returned when the [HTTPRule]
	// entries with a Mismatch action for one domain and one port need
	// more than 1024 route combinations for the requests that match two
	// or more of them. Terrarium counts 2^n combinations for each set of
	// two or more of these rules that one request can match, where n is
	// the number of [HeaderMatch] entries of the set with the
	// [MismatchADD] or [MismatchLOG] action, or with the
	// [MismatchDELETE] action and a value. See [MismatchRuleSets] for
	// the sets.
	ErrHTTPRuleMismatchRoutesTooMany = errors.New(
		"too many Envoy routes for the requests that match two or more http rules with a headerMatch mismatch action: the maximum is 1024 route combinations for one domain and one port (terrarium constraint: each set of rules that one request can match gets routes of its own)",
	)

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

	// ErrInvalidBridgeUplink is returned when an entry of
	// [Config.BridgeUplinks] is not a valid Linux interface name.
	ErrInvalidBridgeUplink = errors.New(
		`invalid bridge uplink: name must have 1 to 15 bytes, must not be "." or "..", ` +
			"and must not hold a slash, colon, whitespace, or NUL byte",
	)

	// ErrDuplicateBridgeUplink is returned when two entries of
	// [Config.BridgeUplinks] name the same interface.
	ErrDuplicateBridgeUplink = errors.New("duplicate bridge uplink")

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

	// ErrCIDRL7RequiresHTTPPort is returned when a rule without
	// toFQDNs has L7 HTTP rules on a port other than 80, and no other
	// rule allows every connection to that port. Envoy handles each
	// such port with a TLS listener, which terminates TLS only for a
	// server name of the policy. A rule without toFQDNs names no
	// server, so the listener cannot apply its HTTP rules.
	ErrCIDRL7RequiresHTTPPort = errors.New(
		"L7 HTTP rules without toFQDNs can only apply to port 80 or to an open port",
	)

	// ErrFQDNPortRangeTooLarge is returned when a toFQDNs rule has a
	// port range (endPort) that would create too many Envoy listeners.
	// Each port in the range requires a separate listener, and large
	// ranges risk exhausting the proxy port space ([MaxProxyablePort]).
	ErrFQDNPortRangeTooLarge = errors.New(
		"toFQDNs port range too large: endPort - port must not exceed 100 (terrarium constraint: each port needs an Envoy listener)",
	)

	// ErrL7WithServerNames is returned when L7 rules (HTTP or DNS) are
	// combined with serverNames on the same port rule. Cilium rejects
	// this combination unless terminatingTLS is set; terrarium does not
	// support terminatingTLS, so the rejection is unconditional.
	ErrL7WithServerNames = errors.New(
		"L7 rules cannot use serverNames without TLS termination",
	)

	// ErrL7RequiresTCP is returned when L7 HTTP rules are paired with
	// a non-TCP protocol. Envoy's HTTP connection manager requires TCP
	// streams; UDP and ANY are invalid with L7 HTTP rules.
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
	// characters outside the DNS allowlist [a-zA-Z0-9._-]. Matches
	// Cilium's allowedMatchNameChars validation.
	ErrFQDNNameInvalidChars = errors.New(
		"matchName contains invalid characters: only a-z, A-Z, 0-9, '.', '-', and '_' are allowed",
	)

	// ErrFQDNPatternInvalidChars is returned when a matchPattern
	// contains characters outside the pattern allowlist
	// [a-zA-Z0-9._*-]. Matches Cilium's allowedPatternChars
	// validation.
	ErrFQDNPatternInvalidChars = errors.New(
		"matchPattern contains invalid characters: only a-z, A-Z, 0-9, '.', '-', '_', and '*' are allowed",
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
	// toFQDNs) on the same rule. With toFQDNs, serverNames replaces
	// the FQDN domains as the Envoy SNI allowlist; DNS resolution
	// still uses the FQDN matchName/matchPattern values.
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

	// ErrServerNamesTooLong is returned when a serverNames entry
	// exceeds 255 characters, the maximum length enforced by the
	// Cilium CRD kubebuilder maxLength constraint.
	ErrServerNamesTooLong = errors.New("serverNames entry exceeds 255 characters")

	// ErrServerNamesInvalidHostname is returned when a serverNames
	// entry contains invalid characters or structure. Matches the
	// Cilium CRD kubebuilder pattern ^([-a-zA-Z0-9_*]+[.]?)+$,
	// which allows DNS-safe characters and wildcards but disallows
	// leading dots and consecutive dots.
	ErrServerNamesInvalidHostname = errors.New(
		"serverNames entry contains invalid characters or structure",
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

	// ErrDNSPatternCompile is returned when a DNS L7 rule matchPattern
	// or matchName produces an anchored regex that fails to compile.
	// The restricted character allowlist makes this extremely unlikely,
	// but compiling during validation provides defense-in-depth.
	ErrDNSPatternCompile = errors.New("DNS pattern produces invalid regex")

	// ErrInvalidLogFormat is returned when a log format value is not
	// "logfmt" or "json".
	ErrInvalidLogFormat = errors.New("invalid log format")

	// ErrInvalidEnvoyLogLevel is returned when the Envoy log level
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

	// ErrStatsPathNotAbsolute is returned when [Stats.Path] is set to
	// a relative path.
	ErrStatsPathNotAbsolute = errors.New("stats.path must be absolute")

	// ErrStatsSocketNotAbsolute is returned when [Stats.Socket] is set
	// to a relative path.
	ErrStatsSocketNotAbsolute = errors.New("stats.socket must be absolute")

	// ErrStatsRetentionInvalid is returned when a retention bound is
	// negative.
	ErrStatsRetentionInvalid = errors.New("stats retention bound must not be negative")

	// ErrEnvoyAccessLogRemoved is returned when a config carries the
	// retired `logging.envoy.accessLog` block. The replacement is
	// the top-level `stats:` block, which records every egress
	// decision into an embedded SQLite event store readable via
	// `terrarium stats`.
	ErrEnvoyAccessLogRemoved = errors.New(
		"logging.envoy.accessLog has been removed; configure access events " +
			"via the top-level `stats` block",
	)
)
