// Package config provides configuration types and parsing for the
// terrarium firewall. It reads a YAML config file and produces
// structured rule sets consumed by Envoy, nftables, and DNS proxy
// generators.
package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

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
	// EgressDeny lists egress deny rules with CIDR and port selectors.
	// Deny rules take precedence over allow rules (evaluated first in
	// nftables). Only L3 (toCIDR, toCIDRSet) and L4 (toPorts) are
	// supported; L7 rules and toFQDNs are not valid on deny rules.
	// A nil pointer means the field was absent from YAML.
	EgressDeny *[]EgressDenyRule `yaml:"egressDeny,omitempty"`
	// Envoy configures Envoy proxy runtime behavior (log level,
	// timeouts, connection limits). A nil pointer means the field
	// was absent from YAML; all defaults apply. See [EnvoySettings].
	Envoy *EnvoySettings `yaml:"envoy,omitempty"`
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
	// ToEntities is a Cilium L3 selector matching special entities.
	// Only "world" is supported (expanded to 0.0.0.0/0 and ::/0
	// during validation); other values (host, cluster, etc.) are
	// rejected with [ErrUnsupportedEntity].
	ToEntities []string `yaml:"toEntities,omitempty"`
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

// EgressDenyRules returns the egress deny rules slice, or nil when
// EgressDeny is absent.
func (c *Config) EgressDenyRules() []EgressDenyRule {
	if c.EgressDeny == nil {
		return nil
	}

	return *c.EgressDeny
}

// EgressDenyRule defines an egress deny policy with CIDR and port
// selectors. Deny rules support only L3 (ToCIDR, ToCIDRSet) and L4
// (ToPorts) selectors. L7 rules and toFQDNs are not permitted on
// deny rules, matching Cilium's EgressDenyRule semantics.
// Deny rules take precedence over allow rules.
type EgressDenyRule struct {
	// ToCIDR denies traffic to IP ranges in CIDR notation.
	ToCIDR []string `yaml:"toCIDR,omitempty"`
	// ToCIDRSet denies traffic to IP ranges with optional exceptions.
	ToCIDRSet []CIDRRule `yaml:"toCIDRSet,omitempty"`
	// ToPorts restricts denied destination ports.
	ToPorts []PortRule `yaml:"toPorts,omitempty"`
	// ToEntities denies traffic to special entities. Only "world"
	// and "all" are supported, expanded to dual-stack CIDRs
	// (0.0.0.0/0 and ::/0) during validation.
	ToEntities []string `yaml:"toEntities,omitempty"`
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
	// ServerNames restricts TLS destinations by SNI. Requires
	// toCIDR or toCIDRSet on the same rule and TCP protocol on all
	// ports. CIDR rules with serverNames are routed through Envoy
	// for SNI inspection instead of direct ACCEPT.
	ServerNames []string `yaml:"serverNames,omitempty"`
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

// L7Rules contains protocol-specific inspection rules. HTTP rules
// provide MITM-based request filtering; DNS rules restrict which
// queries the DNS proxy forwards, merging into the same domain
// allowlist as toFQDNs.
type L7Rules struct {
	// HTTP specifies HTTP-level rules for MITM inspection.
	HTTP []HTTPRule `yaml:"http,omitempty"`
	// DNS specifies DNS-level rules restricting which queries the
	// DNS proxy forwards. Each entry's matchName/matchPattern is
	// merged into the domain allowlist alongside toFQDNs entries.
	// DNS rules must appear on port-53 toPorts entries only.
	DNS []DNSRule `yaml:"dns,omitempty"`

	// Unsupported Cilium L7 protocol fields. See Cilium's L7Rules
	// in pkg/policy/api/l7.go.

	// Kafka is a Cilium field for Kafka protocol rules (deprecated).
	// Terrarium only supports HTTP and DNS L7 inspection.
	Kafka []any `yaml:"kafka,omitempty"`
	// L7Proto is a Cilium field specifying a custom L7 protocol parser.
	// Terrarium does not support custom L7 protocol parsers.
	L7Proto string `yaml:"l7proto,omitempty"`
	// L7 is a Cilium field for generic key-value L7 rules.
	// Terrarium does not support custom L7 protocol rules.
	L7 []any `yaml:"l7,omitempty"`
}

// DNSRule restricts which DNS queries the DNS proxy forwards.
// Exactly one of MatchName or MatchPattern should be set, using
// the same syntax as [FQDNSelector]. DNS rules merge into the
// domain allowlist alongside toFQDNs entries via
// [dnsproxy.CollectDomains].
type DNSRule struct {
	// MatchName matches an exact DNS query name.
	MatchName string `yaml:"matchName,omitempty"`
	// MatchPattern matches DNS query names using wildcard patterns
	// (e.g. "*.example.com").
	MatchPattern string `yaml:"matchPattern,omitempty"`
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
	Protocol string // "TCP", "UDP", "SCTP", or "ANY"
	Port     int
	EndPort  int // 0 = no range
}

// ResolvedCIDR is a port-aware resolved CIDR entry. Ports are
// inherited from the parent [EgressRule]'s toPorts; an empty Ports
// slice means any port (no L4 restriction). RuleIndex tracks which
// egress rule this CIDR came from, enabling per-rule iptables chains
// that preserve Cilium's OR semantics across rules. When ServerNames
// is non-empty, the CIDR rule is routed through Envoy for SNI
// inspection instead of direct ACCEPT.
type ResolvedCIDR struct {
	CIDR        string
	Except      []string
	Ports       []ResolvedPortProto
	ServerNames []string
	RuleIndex   int
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

// UserFlags holds the CLI flag names for each [User] field. Override
// individual names before calling [User.RegisterFlags] to customize
// the flag interface. Create instances with [NewUser].
type UserFlags struct {
	UID             string
	GID             string
	EnvoyUID        string
	Username        string
	HomeDir         string
	ConfigPath      string
	CertsDir        string
	CADir           string
	EnvoyConfigPath string
	ReadyFile       string
}

// User holds identity and path values for the terrarium container user.
// These values are passed from the CLI entrypoint so library packages
// have no baked-in assumptions. Create instances with [NewUser].
type User struct {
	UID             string
	GID             string
	EnvoyUID        string
	Username        string
	HomeDir         string
	ConfigPath      string
	CertsDir        string
	CADir           string
	EnvoyConfigPath string
	ReadyFile       string
	Flags           UserFlags
}

// NewUser creates a new [*User] with default flag names.
func NewUser() *User {
	return &User{
		Flags: UserFlags{
			UID:             "uid",
			GID:             "gid",
			EnvoyUID:        "envoy-uid",
			Username:        "username",
			HomeDir:         "home-dir",
			ConfigPath:      "config",
			CertsDir:        "certs-dir",
			CADir:           "ca-dir",
			EnvoyConfigPath: "envoy-config",
			ReadyFile:       "ready-file",
		},
	}
}

// RegisterFlags registers CLI flags for all [User] fields on the given
// flag set. Default values follow XDG Base Directory conventions with
// container-appropriate fallbacks.
func (u *User) RegisterFlags(flags *pflag.FlagSet) {
	flags.StringVar(&u.UID, u.Flags.UID, "1000", "terrarium user UID")
	flags.StringVar(&u.GID, u.Flags.GID, "1000", "terrarium user GID")
	flags.StringVar(&u.EnvoyUID, u.Flags.EnvoyUID, "1001", "Envoy process UID")
	flags.StringVar(&u.Username, u.Flags.Username, "dev", "terrarium username")
	flags.StringVar(&u.HomeDir, u.Flags.HomeDir,
		userHomeDir(), "terrarium user home directory")
	flags.StringVar(&u.ConfigPath, u.Flags.ConfigPath,
		filepath.Join(userConfigDir(), "terrarium", "config.yaml"), "terrarium config file path")
	flags.StringVar(&u.CertsDir, u.Flags.CertsDir,
		filepath.Join(userDataDir(), "terrarium", "certs"), "MITM leaf certificate directory")
	flags.StringVar(&u.CADir, u.Flags.CADir,
		filepath.Join(userDataDir(), "terrarium", "ca"), "CA cert and key directory")
	flags.StringVar(&u.EnvoyConfigPath, u.Flags.EnvoyConfigPath,
		envoyConfigDefault(), "Envoy config output path")
	flags.StringVar(&u.ReadyFile, u.Flags.ReadyFile,
		"", "path to create when init is ready")
}

// RegisterCompletions registers shell completions for [User] flags.
// Currently a no-op since none of the user flags have enumerable values.
func (u *User) RegisterCompletions(_ *cobra.Command) error {
	return nil
}

// Envoy default constants.
const (
	// DefaultEnvoyLogLevel is the Envoy --log-level flag value used
	// when [EnvoySettings.LogLevel] is empty.
	DefaultEnvoyLogLevel = "warning"

	// DefaultEnvoyDrainTimeout is the maximum time to wait for Envoy
	// to exit after SIGTERM when [EnvoySettings.DrainTimeout] is zero.
	DefaultEnvoyDrainTimeout = 5 * time.Second

	// DefaultEnvoyStartupTimeout is the maximum time to wait for
	// Envoy to begin accepting connections when
	// [EnvoySettings.StartupTimeout] is zero.
	DefaultEnvoyStartupTimeout = 10 * time.Second

	// DefaultEnvoyMaxDownstreamConnections is the Envoy overload
	// manager connection limit when
	// [EnvoySettings.MaxDownstreamConnections] is zero.
	DefaultEnvoyMaxDownstreamConnections = 65535

	// DefaultEnvoyUDPIdleTimeout is the idle timeout for UDP proxy
	// sessions in Envoy when [EnvoySettings.UDPIdleTimeout] is zero.
	DefaultEnvoyUDPIdleTimeout = 60 * time.Second
)

// validEnvoyLogLevels lists the log levels accepted by Envoy's
// --log-level flag.
var validEnvoyLogLevels = map[string]bool{
	"trace": true, "debug": true, "info": true, "warning": true,
	"error": true, "critical": true, "off": true,
}

// ValidEnvoyLogLevels returns the set of accepted Envoy log level
// strings, suitable for help text and error messages.
func ValidEnvoyLogLevels() []string {
	return []string{"trace", "debug", "info", "warning", "error", "critical", "off"}
}

// EnvoySettings controls Envoy proxy runtime behavior. All fields are
// optional; zero values mean "use default." Use [Config.EnvoyDefaults]
// to obtain a fully populated copy with defaults applied.
type EnvoySettings struct {
	// LogLevel sets the Envoy --log-level flag. Valid values are
	// trace, debug, info, warning, error, critical, off.
	LogLevel string `yaml:"logLevel,omitempty"`
	// DrainTimeout is the maximum duration to wait for Envoy to exit
	// after SIGTERM before proceeding with shutdown.
	DrainTimeout Duration `yaml:"drainTimeout,omitempty"`
	// StartupTimeout is the maximum duration to wait for Envoy to
	// begin accepting connections after launch.
	StartupTimeout Duration `yaml:"startupTimeout,omitempty"`
	// MaxDownstreamConnections limits the number of active downstream
	// connections Envoy will accept. Zero means use the default (65535).
	MaxDownstreamConnections int `yaml:"maxDownstreamConnections,omitempty"`
	// UDPIdleTimeout is the idle timeout for UDP proxy sessions.
	// Sessions with no traffic for this duration are closed.
	UDPIdleTimeout Duration `yaml:"udpIdleTimeout,omitempty"`
}

// EnvoyDefaults returns an [EnvoySettings] with defaults applied for
// any fields not set in the YAML config. When [Config.Envoy] is nil,
// all defaults apply.
func (c *Config) EnvoyDefaults() EnvoySettings {
	s := EnvoySettings{
		LogLevel:                 DefaultEnvoyLogLevel,
		DrainTimeout:             Duration{DefaultEnvoyDrainTimeout},
		StartupTimeout:           Duration{DefaultEnvoyStartupTimeout},
		MaxDownstreamConnections: DefaultEnvoyMaxDownstreamConnections,
		UDPIdleTimeout:           Duration{DefaultEnvoyUDPIdleTimeout},
	}

	if c.Envoy == nil {
		return s
	}

	if c.Envoy.LogLevel != "" {
		s.LogLevel = c.Envoy.LogLevel
	}

	if c.Envoy.DrainTimeout.Duration != 0 {
		s.DrainTimeout = c.Envoy.DrainTimeout
	}

	if c.Envoy.StartupTimeout.Duration != 0 {
		s.StartupTimeout = c.Envoy.StartupTimeout
	}

	if c.Envoy.MaxDownstreamConnections != 0 {
		s.MaxDownstreamConnections = c.Envoy.MaxDownstreamConnections
	}

	if c.Envoy.UDPIdleTimeout.Duration != 0 {
		s.UDPIdleTimeout = c.Envoy.UDPIdleTimeout
	}

	return s
}

// Duration wraps [time.Duration] with YAML string unmarshaling.
// Values are parsed with [time.ParseDuration] (e.g. "5s", "1m30s").
type Duration struct {
	time.Duration
}

// UnmarshalYAML implements the goccy/go-yaml InterfaceUnmarshaler
// interface to parse duration strings.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string

	err := unmarshal(&s)
	if err != nil {
		return err
	}

	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("parsing duration %q: %w", s, err)
	}

	d.Duration = dur

	return nil
}

// MarshalYAML returns the duration as a Go duration string.
// Returns an empty string for zero durations.
func (d Duration) MarshalYAML() (any, error) {
	if d.Duration == 0 {
		return "", nil
	}

	return d.Duration.String(), nil
}

// String returns the duration as a Go duration string.
func (d Duration) String() string {
	return d.Duration.String()
}

// normalizeEnvoySettings lowercases the log level so users can write
// "Warning" or "WARNING" and it works.
func normalizeEnvoySettings(c *Config) {
	if c.Envoy != nil && c.Envoy.LogLevel != "" {
		c.Envoy.LogLevel = strings.ToLower(c.Envoy.LogLevel)
	}
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
