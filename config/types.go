// Package config provides configuration types and parsing for the
// terrarium firewall. It reads a YAML config file and produces
// structured rule sets consumed by Envoy, nftables, and DNS proxy
// generators.
package config

import "regexp"

// Config is the top-level YAML configuration for terrarium firewall.
//
// The Egress field uses CiliumNetworkPolicy semantics:
//
//   - nil (absent from YAML): no egress enforcement (unrestricted).
//
//   - empty slice (egress: []): no effect, equivalent to omitting the
//     field (unrestricted); an empty list never activates enforcement.
//
//   - non-empty slice: rules apply; non-matching traffic is dropped
//     (default-deny is always active when rules are present).
//
//   - a slice containing an empty EgressRule{}: deny-all; empty selectors
//     match nothing. This matches Cilium's canonical deny-all pattern
//     described in the "Ingress/Egress Default Deny" section of the policy
//     language docs. An empty EgressRule{} has no L3 selectors (toEndpoints,
//     toCIDR, toCIDRSet, toFQDNs) and no L4/L7 selectors (toPorts), so it
//     whitelists zero traffic. The allow-all pattern in Cilium is structurally
//     different: it requires toEndpoints: [{}], where the empty
//     EndpointSelector is the wildcard that matches all endpoints.
//     See [Ingress/Egress Default Deny].
//
// [Ingress/Egress Default Deny]: https://docs.cilium.io/en/stable/security/policy/language/#ingress-egress-default-deny
type Config struct {
	// Egress lists egress rules with FQDN, port, and CIDR selectors.
	// A nil pointer means the field was absent from YAML (unrestricted).
	// An empty slice is equivalent to nil; Cilium infers default-deny
	// from rule presence, so an empty list never activates enforcement.
	Egress *[]EgressRule `yaml:"egress,omitempty"`
	// TCPForwards lists non-TLS TCP port-to-host mappings. Each entry
	// creates a plain TCP proxy listener forwarding to the specified host.
	TCPForwards []TCPForward `yaml:"tcpForwards,omitempty"`
	// Logging enables Envoy access logs and iptables LOG targets.
	Logging bool `yaml:"logging"`
}

// EgressRules returns the egress rules slice, or nil when Egress is absent.
func (c *Config) EgressRules() []EgressRule {
	if c.Egress == nil {
		return nil
	}

	return *c.Egress
}

// IsDefaultDenyEnabled reports whether default-deny is active for egress.
// Returns true when egress rules are present (non-nil, non-empty list).
func (c *Config) IsDefaultDenyEnabled() bool {
	return c.Egress != nil && len(c.EgressRules()) > 0
}

// IsEgressUnrestricted reports whether egress is unrestricted,
// meaning no egress filtering should be applied.
func (c *Config) IsEgressUnrestricted() bool {
	return c.Egress == nil || len(c.EgressRules()) == 0
}

// IsEgressBlocked reports whether all egress is blocked: default-deny
// is active and every rule has empty selectors (matching nothing).
// This is the deny-all pattern (e.g. egress: [{}]).
//
// An empty EgressRule{} contains no L3 selectors (ToFQDNs, ToCIDR, ToCIDRSet)
// and no L4 selectors (ToPorts). With no selectors present, the rule
// whitelists nothing -- it does not act as a wildcard. Cilium's own
// documentation uses egress: [{}] as the canonical deny-all example
// in the [Ingress/Egress Default Deny] section.
//
// The allow-all pattern in Cilium is structurally different and
// requires a toEndpoints selector with an empty EndpointSelector:
//
//	egress:
//	  - toEndpoints:
//	      - {}
//
// The empty EndpointSelector{} (matchLabels: {}) is the actual
// wildcard -- it matches all endpoints. This lives in Cilium's
// EgressCommonRule.ToEndpoints field (pkg/policy/api/egress.go),
// which terrarium does not implement. The validation logic in
// pkg/policy/api/rule_validation.go (sanitize methods) confirms
// that an EgressRule with zero selectors is valid but matches no
// traffic.
//
// This method checks that every rule in the egress list has all
// selector fields empty, which is the structural equivalent of
// Cilium's deny-all.
//
// [Ingress/Egress Default Deny]: https://docs.cilium.io/en/stable/security/policy/language/#ingress-egress-default-deny
func (c *Config) IsEgressBlocked() bool {
	if !c.IsDefaultDenyEnabled() {
		return false
	}

	rules := c.EgressRules()
	for i := range rules {
		// Unsupported selectors (ToEndpoints, ToEntities, etc.) are not
		// checked here because Validate() rejects them before this point.
		if len(rules[i].ToFQDNs) > 0 || len(rules[i].ToPorts) > 0 ||
			len(rules[i].ToCIDR) > 0 || len(rules[i].ToCIDRSet) > 0 {
			return false
		}
	}

	return true
}

// EgressRule defines an egress policy with optional FQDN, port, and CIDR
// selectors. Under CiliumNetworkPolicy semantics, ToFQDNs is mutually
// exclusive with ToCIDR and ToCIDRSet within a single rule; split them
// into separate rules in the egress array. ToCIDR and ToCIDRSet are
// mutually exclusive within a single rule; split them into separate
// rules. L4 selectors (ToPorts) are AND'd with the L3 result. L7 rules
// (HTTP inspection) require ToFQDNs. MatchName and MatchPattern values
// in ToFQDNs are normalized to lowercase with trailing dots stripped.
//
// An EgressRule with no selectors set (all fields empty/nil) whitelists
// nothing, because there is no L3/L4/L7 predicate to match against.
// This is a common source of confusion: an empty rule is not a wildcard.
// In Cilium, the allow-all pattern is an EgressRule containing a
// toEndpoints selector with an empty EndpointSelector (i.e.,
// toEndpoints: [{}]), which acts as a wildcard matching all endpoints.
// Terrarium does not implement toEndpoints; using it produces an
// [ErrUnsupportedSelector] validation error. The distinction matters
// for understanding why egress: [{}] means deny-all rather than
// allow-all. See Cilium's EgressRule and EgressCommonRule structs in
// pkg/policy/api/egress.go.
//
// Unsupported Cilium selectors (toEndpoints, toEntities, toServices,
// toNodes, toGroups, toRequires, icmps, authentication) are parsed
// into stub fields and rejected during [Config.Validate]. Additionally,
// [parseConfigRaw] enables [yaml.DisallowUnknownField] so that any
// field not present in the struct (including future Cilium additions)
// produces a parse error rather than silent data loss.
type EgressRule struct {
	// ToFQDNs selects traffic by destination hostname.
	ToFQDNs []FQDNSelector `yaml:"toFQDNs,omitempty"`
	// ToPorts restricts allowed destination ports and optional L7 rules.
	ToPorts []PortRule `yaml:"toPorts,omitempty"`
	// ToCIDR allows traffic to simple IP ranges in CIDR notation.
	ToCIDR []string `yaml:"toCIDR,omitempty"`
	// ToCIDRSet allows traffic to IP ranges with optional exceptions.
	ToCIDRSet []CIDRRule `yaml:"toCIDRSet,omitempty"`

	// Unsupported Cilium selectors. These fields exist so that the YAML
	// decoder captures them instead of relying solely on strict mode.
	// [Config.Validate] rejects any rule where these are populated, producing
	// an actionable error message. The types are []any or any to avoid
	// replicating Cilium's full type hierarchy.
	//
	// See Cilium's EgressCommonRule and EgressRule in
	// pkg/policy/api/egress.go for the canonical definitions.

	// Authentication is a Cilium field for mutual authentication.
	// Terrarium does not support authentication policy.
	Authentication any `yaml:"authentication,omitempty"`
	// ToEndpoints is a Cilium L3 selector matching endpoints by label.
	// Terrarium has no endpoint identity system.
	ToEndpoints []any `yaml:"toEndpoints,omitempty"`
	// ToEntities is a Cilium L3 selector matching special entities
	// (world, cluster, host, etc). Terrarium has no entity resolution.
	ToEntities []any `yaml:"toEntities,omitempty"`
	// ToServices is a Cilium L3 selector matching Kubernetes services.
	// Terrarium has no service discovery.
	ToServices []any `yaml:"toServices,omitempty"`
	// ToNodes is a Cilium L3 selector matching nodes by label.
	// Terrarium has no node identity system.
	ToNodes []any `yaml:"toNodes,omitempty"`
	// ToGroups is a Cilium L3 selector matching cloud provider groups.
	// Terrarium has no cloud provider integration.
	ToGroups []any `yaml:"toGroups,omitempty"`
	// ToRequires is a deprecated Cilium field. Rejected unconditionally.
	ToRequires []any `yaml:"toRequires,omitempty"`
	// ICMPs is a Cilium selector for ICMP type filtering.
	// Terrarium does not support ICMP-level policy.
	ICMPs []any `yaml:"icmps,omitempty"`
}

// CIDRRule specifies an IP range to allow, with optional exceptions.
type CIDRRule struct {
	// CIDRGroupSelector is a Cilium field for label-based CIDR group
	// selection. Terrarium has no CRD-based CIDR group resolution.
	CIDRGroupSelector any `yaml:"cidrGroupSelector,omitempty"`
	// CIDR is the IP range in CIDR notation (e.g. "10.0.0.0/8").
	CIDR string `yaml:"cidr"`
	// CIDRGroupRef is a Cilium field referencing a CiliumCIDRGroup.
	// Terrarium has no CRD-based CIDR group resolution.
	CIDRGroupRef string `yaml:"cidrGroupRef,omitempty"`
	// Except lists sub-ranges of CIDR to exclude.
	Except []string `yaml:"except,omitempty"`
}

// FQDNSelector matches traffic by destination hostname. Exactly one of
// MatchName or MatchPattern should be set.
type FQDNSelector struct {
	// MatchName matches an exact hostname.
	MatchName string `yaml:"matchName,omitempty"`
	// MatchPattern matches hostnames using wildcard patterns (e.g. "*.example.com").
	MatchPattern string `yaml:"matchPattern,omitempty"`
}

// PortRule restricts traffic to specific ports with optional L7 rules.
type PortRule struct {
	// Unsupported Cilium fields. These exist so the YAML decoder
	// captures them instead of producing opaque parse errors.
	// [Config.Validate] rejects any rule where these are populated.
	// See Cilium's PortRule in pkg/policy/api/rule.go.

	// TerminatingTLS is a Cilium field for TLS termination context.
	// Terrarium does not support TLS policy contexts.
	TerminatingTLS any `yaml:"terminatingTLS,omitempty"`
	// OriginatingTLS is a Cilium field for TLS origination context.
	// Terrarium does not support TLS policy contexts.
	OriginatingTLS any `yaml:"originatingTLS,omitempty"`
	// Listener is a Cilium field for Envoy listener references.
	// Terrarium manages its own Envoy config and does not support
	// user-specified listeners.
	Listener any `yaml:"listener,omitempty"`
	// Rules specifies optional L7 inspection rules.
	Rules *L7Rules `yaml:"rules,omitempty"`
	// Ports lists allowed destination ports.
	Ports []Port `yaml:"ports,omitempty"`
	// ServerNames is a Cilium field for SNI-based filtering on ports.
	// Terrarium handles SNI via Envoy filter chains, not port rules.
	ServerNames []any `yaml:"serverNames,omitempty"`
}

// Port specifies a destination port number with optional protocol and range.
type Port struct {
	// Port is the port number or IANA service name (e.g. "443", "https").
	Port string `yaml:"port"`
	// Protocol is the transport protocol: "TCP", "UDP", "SCTP", "ANY",
	// or empty (defaults to ANY when omitted). "ANY" matches TCP, UDP,
	// and SCTP.
	Protocol string `yaml:"protocol,omitempty"`
	// EndPort specifies the upper bound of a port range. When set, the
	// rule matches ports from Port to EndPort inclusive. Valid with CIDR
	// and open-port rules (toPorts without L3 selectors); not supported
	// with toFQDNs (Envoy needs individual listeners). Open-port TCP
	// ranges bypass Envoy via direct iptables ACCEPT.
	EndPort int `yaml:"endPort,omitempty"`
}

// L7Rules contains protocol-specific inspection rules.
type L7Rules struct {
	// HTTP specifies HTTP-level rules for MITM inspection.
	HTTP []HTTPRule `yaml:"http,omitempty"`

	// Unsupported Cilium L7 protocol fields. See Cilium's L7Rules
	// in pkg/policy/api/l7.go.

	// Kafka is a Cilium field for Kafka protocol rules (deprecated).
	// Terrarium only supports HTTP L7 inspection.
	Kafka []any `yaml:"kafka,omitempty"`
	// DNS is a Cilium field for DNS protocol rules.
	// Terrarium handles DNS via its own DNS proxy, not L7 rules.
	DNS []any `yaml:"dns,omitempty"`
	// L7Proto is a Cilium field specifying a custom L7 protocol parser.
	// Terrarium does not support custom L7 protocol parsers.
	L7Proto string `yaml:"l7proto,omitempty"`
	// L7 is a Cilium field for generic key-value L7 rules.
	// Terrarium does not support custom L7 protocol rules.
	L7 []any `yaml:"l7,omitempty"`
}

// HTTPRule specifies an allowed HTTP method, path, host, and/or
// header constraints.
type HTTPRule struct {
	// Method restricts the allowed HTTP method as an extended POSIX
	// regex (e.g. "GET", "GET|POST").
	Method string `yaml:"method,omitempty"`
	// Path restricts the allowed URL path as an extended POSIX regex
	// matched against the full path (e.g. "/v1/.*", "/api/v[12]/.*").
	Path string `yaml:"path,omitempty"`
	// Host restricts the allowed HTTP host as an extended POSIX regex
	// matched against the Host header (e.g. "api\\.example\\.com",
	// ".*\\.example\\.com").
	Host string `yaml:"host,omitempty"`
	// Headers is a list of header names that must be present in the
	// request (presence check). Each entry is a header field name;
	// the value is not inspected.
	Headers []string `yaml:"headers,omitempty"`
	// HeaderMatches specifies header name/value constraints. The
	// request must contain the named header with the specified value
	// or it is denied.
	HeaderMatches []HeaderMatch `yaml:"headerMatches,omitempty"`
}

// HeaderMatch specifies a header name/value constraint. The request
// header must have the specified value or the request is denied.
//
// Cilium also supports a Mismatch field (LOG, ADD, DELETE, REPLACE)
// for request modification instead of denial. Terrarium rejects
// configs that set Mismatch since it cannot enforce modification
// semantics.
type HeaderMatch struct {
	// Mismatch defines the action when the header value does not
	// match. Terrarium rejects any non-empty value.
	Mismatch MismatchAction `yaml:"mismatch,omitempty"`
	// Name is the header field name to match.
	Name string `yaml:"name"`
	// Value is the expected header value.
	Value string `yaml:"value,omitempty"`
}

// MismatchAction defines what happens when a [HeaderMatch] value does
// not match. Terrarium does not support mismatch actions and rejects
// configs that set one.
type MismatchAction string

const (
	// MismatchLOG logs when the header value does not match.
	MismatchLOG MismatchAction = "LOG"
	// MismatchADD adds a header when the value does not match.
	MismatchADD MismatchAction = "ADD"
	// MismatchDELETE deletes the header when it does not match.
	MismatchDELETE MismatchAction = "DELETE"
	// MismatchREPLACE replaces the header value on mismatch.
	MismatchREPLACE MismatchAction = "REPLACE"
)

// TCPForward maps a TCP port to a specific upstream host. Unlike egress
// rules (which use TLS SNI or HTTP Host filtering against the domain
// allowlist), TCP forwards create plain TCP proxy listeners with
// STRICT_DNS routing to a single host.
type TCPForward struct {
	// Host is the upstream hostname to forward traffic to.
	Host string `yaml:"host"`
	// Port is the TCP port to forward.
	Port int `yaml:"port"`
}

// ResolvedHTTPRule is a single HTTP match pattern with an optional
// method and path. Under CiliumNetworkPolicy semantics, multiple HTTP
// rules within a toPorts entry are OR'd -- each is an independent
// match, not a cross-product.
type ResolvedHTTPRule struct {
	Method        string        // empty = any method
	Path          string        // empty = any path
	Host          string        // empty = any host
	Headers       []string      // presence-check header names
	HeaderMatches []HeaderMatch // name/value constraints (deny on mismatch)
}

// ResolvedRule bridges between the Cilium-shaped config and Envoy-shaped
// output. Each ResolvedRule represents a single domain with optional
// HTTP-level restrictions.
type ResolvedRule struct {
	Domain    string
	HTTPRules []ResolvedHTTPRule // nil = unrestricted (no L7 filtering)
}

// IsRestricted reports whether this rule requires HTTP-level inspection
// (MITM on TLS). A rule is restricted when it has non-nil HTTPRules,
// meaning L7 filtering is active.
func (r ResolvedRule) IsRestricted() bool {
	return r.HTTPRules != nil
}

// ResolvedPortProto is a resolved port with protocol and optional range.
type ResolvedPortProto struct {
	Protocol string // "tcp", "udp", "" = any (no -p flag)
	Port     int
	EndPort  int // 0 = no range
}

// ResolvedCIDR is a port-aware resolved CIDR entry. Each entry
// represents a direct IP-level allow rule that bypasses the Envoy
// proxy. Ports are inherited from the parent [EgressRule]'s toPorts;
// an empty Ports slice means any port (no L4 restriction).
// RuleIndex tracks which egress rule this CIDR came from, enabling
// per-rule iptables chains that preserve Cilium's OR semantics
// across rules.
type ResolvedCIDR struct {
	CIDR      string
	Except    []string
	Ports     []ResolvedPortProto
	RuleIndex int
}

// ResolvedOpenPort is a resolved open port with its normalized protocol.
type ResolvedOpenPort struct {
	Protocol string
	Port     int
	EndPort  int // 0 = no range
}

// FQDNRulePorts groups resolved non-TCP ports for a single FQDN
// egress rule. Each rule gets its own ipset pair, matching Cilium's
// per-selector isolation semantics.
type FQDNRulePorts struct {
	Ports     []ResolvedOpenPort
	RuleIndex int
}

// FQDNPattern pairs an FQDN selector with its compiled regex for DNS
// response filtering. Patterns follow Cilium's matchpattern semantics:
// [FQDNSelector.MatchName] compiles to an exact match, single "*"
// matches one DNS label, "**." prefix matches one or more labels.
//
// For FQDN-form regexes (with trailing dot). For SNI/Host regexes
// without trailing dot, see wildcardToSNIRegex and wildcardToHostRegex
// in the envoy package.
type FQDNPattern struct {
	Regex     *regexp.Regexp
	Original  string
	RuleIndex int
}
