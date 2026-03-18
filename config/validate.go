package config

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

const maxFQDNLength = 255

// maxPorts is the maximum number of port entries allowed in a single
// [PortRule]. Matches Cilium's +kubebuilder:validation:MaxItems=40
// on PortRule.Ports.
const maxPorts = 40

// maxFQDNEndPortRange is the maximum number of ports in an endPort
// range for toFQDNs rules. Each port requires a separate Envoy
// listener, and large ranges risk exhausting the proxy port space.
const maxFQDNEndPortRange = 100

// maxRegexLen is the maximum allowed length for path and method
// regex patterns. Envoy uses RE2 with a default max program size
// of 100; extremely long patterns could pass Go validation but
// fail in RE2.
const maxRegexLen = 1000

var (
	// allowedMatchNameChars validates that a matchName contains only
	// DNS-safe characters. Matches Cilium's allowedMatchNameChars
	// (pkg/policy/api/fqdn.go:18). Includes uppercase letters to match
	// Cilium's definition; normalizeEgressRule lowercases as a
	// convenience, but these regexes do not depend on that ordering.
	allowedMatchNameChars = regexp.MustCompile(`^[-a-zA-Z0-9_.]+$`)

	// allowedMatchPatternChars validates that a matchPattern contains
	// only DNS-safe characters plus the wildcard '*'. Matches Cilium's
	// allowedPatternChars (pkg/fqdn/matchpattern/matchpattern.go:33).
	// Includes uppercase letters to match Cilium's definition;
	// normalization lowercases as a convenience, not a prerequisite.
	allowedMatchPatternChars = regexp.MustCompile(`^[-a-zA-Z0-9_.*]+$`)

	// validProtocols lists the supported transport protocols. Cilium
	// also supports ICMP, ICMPv6, VRRP, and IGMP, but these are
	// IP-layer protocols without ports and cannot be expressed in the
	// terrarium's port-based model.
	validProtocols = map[string]bool{
		"": true, ProtoTCP: true, ProtoUDP: true, ProtoSCTP: true, ProtoAny: true,
	}

	// entityCIDRs maps each supported toEntities value to the CIDRs
	// it expands into. "world" and "all" expand to dual-stack CIDRs
	// (0.0.0.0/0 and ::/0). "world-ipv4" and "world-ipv6" expand to
	// a single address family. In Cilium's non-Kubernetes context,
	// "all" is functionally identical to "world".
	entityCIDRs = map[string][]string{
		"world":      {"0.0.0.0/0", "::/0"},
		"all":        {"0.0.0.0/0", "::/0"},
		"world-ipv4": {"0.0.0.0/0"},
		"world-ipv6": {"::/0"},
	}
)

// Validate checks that the config is internally consistent.
func (c *Config) Validate() error {
	for i := range c.EgressRules() {
		// Expand supported entities (e.g. "world" -> dual-stack
		// CIDRs) before rejecting unsupported selectors.
		err := expandAndValidateEntities(&(*c.Egress)[i], i)
		if err != nil {
			return err
		}

		// Expand toEndpoints: [{}] (wildcard) into dual-stack
		// CIDRs before rejecting unsupported selectors. An empty
		// endpoint selector {} matches all destinations, equivalent
		// to toEntities: [world] in Cilium's LabelSelector semantics.
		err = expandAndValidateEndpoints(&(*c.Egress)[i], i)
		if err != nil {
			return err
		}

		// Reject unsupported Cilium selectors before any other
		// processing. This prevents silent data loss from fields
		// like toEndpoints being ignored.
		// The unsupported fields don't need normalization, so this
		// can safely run first.
		err = validateUnsupportedSelectors((*c.Egress)[i], i)
		if err != nil {
			return err
		}

		// Normalize before validation so that e.g. "tcp" passes
		// the uppercase protocol check and "GitHub.COM." passes
		// FQDN validation as "github.com".
		err = normalizeEgressRule(c, i)
		if err != nil {
			return err
		}

		rule := (*c.Egress)[i]

		// An empty EgressRule{} is valid: it triggers default-deny
		// with empty selectors (deny-all pattern).
		err = validateFQDNSelectors(rule, i)
		if err != nil {
			return err
		}

		hasFQDNs := len(rule.ToFQDNs) > 0

		err = validateFQDNConstraints(rule, i, hasFQDNs)
		if err != nil {
			return err
		}

		// L3 mutual exclusivity: Cilium's EgressCommonRule.sanitize()
		// rejects any rule combining two different L3 selector fields.
		// ToEntities is checked in expandAndValidateEntities (before
		// expansion), and ToFQDNs in validateFQDNConstraints. The
		// remaining pair is ToCIDR + ToCIDRSet.
		if len(rule.ToCIDR) > 0 && len(rule.ToCIDRSet) > 0 {
			return fmt.Errorf("%w: rule %d", ErrCIDRAndCIDRSetMixed, i)
		}

		err = validatePorts(rule, i)
		if err != nil {
			return err
		}

		for _, cidr := range rule.ToCIDR {
			_, _, parseErr := net.ParseCIDR(cidr)
			if parseErr != nil {
				return fmt.Errorf("%w: rule %d cidr %q", ErrCIDRInvalid, i, cidr)
			}
		}

		err = validateL7Rules(rule, i, hasFQDNs)
		if err != nil {
			return err
		}

		err = validateDNSRules(rule, i)
		if err != nil {
			return err
		}

		err = validateCIDRSets(rule, i)
		if err != nil {
			return err
		}

		err = validateICMPRules(rule.ICMPs, rule.ToPorts, "rule", i)
		if err != nil {
			return err
		}

		if len(rule.ICMPs) > 0 && len(rule.ToFQDNs) > 0 {
			return fmt.Errorf("%w: rule %d", ErrICMPWithFQDNs, i)
		}
	}

	// Validate egressDeny rules.
	err := c.validateEgressDenyRules()
	if err != nil {
		return err
	}

	// TCPForwards require egress rules to route traffic. If egress is
	// blocked, forwards would silently do nothing.
	if c.IsEgressBlocked() && len(c.TCPForwards) > 0 {
		return ErrTCPForwardRequiresEgress
	}

	resolvedPorts := c.ResolvePorts()

	portsSet := make(map[int]bool, len(resolvedPorts))
	for _, p := range resolvedPorts {
		if p > MaxProxyablePort {
			return fmt.Errorf("%w: %d", ErrPortExceedsProxyRange, p)
		}

		portsSet[p] = true
	}

	seen := make(map[int]bool)
	for _, fwd := range c.TCPForwards {
		if fwd.Port <= 0 || fwd.Host == "" {
			return fmt.Errorf("%w: port=%d host=%q", ErrInvalidTCPForward, fwd.Port, fwd.Host)
		}

		if fwd.Port > MaxProxyablePort {
			return fmt.Errorf("%w: %d", ErrPortExceedsProxyRange, fwd.Port)
		}

		if seen[fwd.Port] {
			return fmt.Errorf("%w: %d", ErrDuplicateTCPForwardPort, fwd.Port)
		}

		seen[fwd.Port] = true
		if portsSet[fwd.Port] {
			return fmt.Errorf("%w: %d", ErrTCPForwardPortConflict, fwd.Port)
		}
	}

	normalizeEnvoySettings(c)

	return c.validateEnvoySettings()
}

// validateEnvoySettings checks that envoy settings contain valid values.
func (c *Config) validateEnvoySettings() error {
	if c.Envoy == nil {
		return nil
	}

	if c.Envoy.LogLevel != "" && !validEnvoyLogLevels[c.Envoy.LogLevel] {
		return fmt.Errorf("%w: %q", ErrInvalidEnvoyLogLevel, c.Envoy.LogLevel)
	}

	if c.Envoy.DrainTimeout.Duration < 0 {
		return fmt.Errorf("%w: %v", ErrInvalidEnvoyDrainTimeout, c.Envoy.DrainTimeout)
	}

	if c.Envoy.StartupTimeout.Duration < 0 {
		return fmt.Errorf("%w: %v", ErrInvalidEnvoyStartupTimeout, c.Envoy.StartupTimeout)
	}

	if c.Envoy.MaxDownstreamConnections < 0 {
		return fmt.Errorf("%w: %d", ErrInvalidEnvoyMaxConnections, c.Envoy.MaxDownstreamConnections)
	}

	return nil
}

// validateUnsupportedSelectors checks whether any Cilium selectors that
// terrarium does not implement are present in the rule. Returns an
// error for the first unsupported selector found, with the rule index
// and field name for diagnostics.
func validateUnsupportedSelectors(rule EgressRule, ruleIdx int) error {
	type field struct {
		name string
		set  bool
	}

	fields := []field{
		{"toEndpoints", len(rule.ToEndpoints) > 0},
		{"toServices", len(rule.ToServices) > 0},
		{"toNodes", len(rule.ToNodes) > 0},
		{"toGroups", len(rule.ToGroups) > 0},
		{"toRequires", len(rule.ToRequires) > 0},
		{"authentication", rule.Authentication != nil},
	}

	for _, f := range fields {
		if f.set {
			return fmt.Errorf(
				"%w: rule %d has %s, which is not implemented by terrarium",
				ErrUnsupportedSelector, ruleIdx, f.name,
			)
		}
	}

	return nil
}

// maxICMPFields is the maximum number of field entries allowed in a
// single [ICMPRule]. Matches Cilium's +kubebuilder:validation:MaxItems=40
// on ICMPRule.Fields.
const maxICMPFields = 40

// validateICMPRules checks that ICMP rules are well-formed: valid
// families, valid type names or codes, no mixing with toPorts, and
// field count limits.
func validateICMPRules(icmps []ICMPRule, toPorts []PortRule, prefix string, ruleIdx int) error {
	if len(icmps) == 0 {
		return nil
	}

	// Cilium rejects combining icmps with toPorts on the same rule
	// (rule_validation.go:328-330).
	if len(toPorts) > 0 {
		return fmt.Errorf("%w: %s %d", ErrICMPWithToPorts, prefix, ruleIdx)
	}

	for i, icmp := range icmps {
		if len(icmp.Fields) > maxICMPFields {
			return fmt.Errorf("%w: %s %d icmps[%d] has %d fields",
				ErrICMPFieldsTooMany, prefix, ruleIdx, i, len(icmp.Fields))
		}

		for j, f := range icmp.Fields {
			if f.Type == "" {
				return fmt.Errorf("%w: %s %d icmps[%d] fields[%d]",
					ErrICMPTypeRequired, prefix, ruleIdx, i, j)
			}

			family, err := normalizeICMPFamily(f.Family)
			if err != nil {
				return fmt.Errorf("%w: %s %d icmps[%d] fields[%d] family %q",
					ErrICMPInvalidFamily, prefix, ruleIdx, i, j, f.Family)
			}

			_, err = resolveICMPType(family, f.Type)
			if err != nil {
				return fmt.Errorf("%w: %s %d icmps[%d] fields[%d] type %q",
					ErrICMPInvalidType, prefix, ruleIdx, i, j, f.Type)
			}
		}
	}

	return nil
}

// validateUnsupportedDenySelectors checks whether any Cilium selectors
// that terrarium does not implement are present in an egress deny rule.
// toFQDNs is checked separately with a targeted error because Cilium's
// EgressDenyRule type structurally lacks a ToFQDNs field (unlike the
// generic unsupported selectors which exist in Cilium but require
// cluster infrastructure).
func validateUnsupportedDenySelectors(rule EgressDenyRule, ruleIdx int) error {
	// toFQDNs gets a targeted error distinct from the generic
	// unsupported-selector message, because the structural absence
	// of ToFQDNs on Cilium's EgressDenyRule is a deliberate design
	// constraint, not a terrarium limitation.
	if len(rule.ToFQDNs) > 0 {
		return fmt.Errorf(
			"%w: egressDeny rule %d",
			ErrDenyRuleToFQDNs, ruleIdx,
		)
	}

	type field struct {
		name string
		set  bool
	}

	fields := []field{
		{"toEndpoints", len(rule.ToEndpoints) > 0},
		{"toServices", len(rule.ToServices) > 0},
		{"toNodes", len(rule.ToNodes) > 0},
		{"toGroups", len(rule.ToGroups) > 0},
		{"toRequires", len(rule.ToRequires) > 0},
		{"authentication", rule.Authentication != nil},
	}

	for _, f := range fields {
		if f.set {
			return fmt.Errorf(
				"%w: egressDeny rule %d has %s, which is not implemented by terrarium",
				ErrUnsupportedSelector, ruleIdx, f.name,
			)
		}
	}

	return nil
}

// validateUnsupportedPortRuleFeatures checks for Cilium-only fields on
// a [PortRule] that terrarium does not implement.
func validateUnsupportedPortRuleFeatures(pr PortRule, ruleIdx int) error {
	type field struct {
		name string
		set  bool
	}

	fields := []field{
		{"terminatingTLS", pr.TerminatingTLS != nil},
		{"originatingTLS", pr.OriginatingTLS != nil},
		{"listener", pr.Listener != nil},
	}

	for _, f := range fields {
		if f.set {
			return fmt.Errorf(
				"%w: rule %d toPorts has %s, which is not supported by terrarium",
				ErrUnsupportedFeature, ruleIdx, f.name,
			)
		}
	}

	return nil
}

// validateUnsupportedL7Features checks for Cilium-only L7 protocol
// fields on [L7Rules] that terrarium does not implement.
func validateUnsupportedL7Features(rules *L7Rules, ruleIdx int) error {
	if rules == nil {
		return nil
	}

	type field struct {
		name string
		set  bool
	}

	fields := []field{
		{"kafka", len(rules.Kafka) > 0},
		{"l7proto", rules.L7Proto != ""},
		{"l7", len(rules.L7) > 0},
	}

	for _, f := range fields {
		if f.set {
			return fmt.Errorf(
				"%w: rule %d toPorts rules has %s, which is not supported by terrarium",
				ErrUnsupportedFeature, ruleIdx, f.name,
			)
		}
	}

	// Cilium's L7Rules.sanitize() counts HTTP, DNS, and L7Proto rule
	// types and rejects any PortRule with more than one L7 type.
	if len(rules.HTTP) > 0 && len(rules.DNS) > 0 {
		return fmt.Errorf("%w: rule %d", ErrL7MutualExclusivity, ruleIdx)
	}

	return nil
}

// validateUnsupportedCIDRRuleFeatures checks for Cilium-only fields on
// a [CIDRRule] that terrarium does not implement.
func validateUnsupportedCIDRRuleFeatures(cr CIDRRule, ruleIdx int) error {
	if cr.CIDRGroupRef != "" {
		return fmt.Errorf(
			"%w: rule %d toCIDRSet has cidrGroupRef, which is not supported by terrarium",
			ErrUnsupportedFeature, ruleIdx,
		)
	}

	if cr.CIDRGroupSelector != nil {
		return fmt.Errorf(
			"%w: rule %d toCIDRSet has cidrGroupSelector, which is not supported by terrarium",
			ErrUnsupportedFeature, ruleIdx,
		)
	}

	return nil
}

// validateFQDNSelectors checks that each FQDN selector in a rule has
// exactly one of matchName or matchPattern, and that patterns use only
// leading wildcards. Cilium supports three wildcard forms:
//
//   - "*"        -- match all FQDNs
//   - "*.suffix" -- single-label wildcard (one subdomain level)
//   - "**.suffix" -- multi-label wildcard (arbitrary subdomain depth)
//
// Cilium treats 2+ stars identically ([*]{2,} in its regex), so runs
// of 3+ stars are normalized to ** before validation.
func validateFQDNSelectors(rule EgressRule, ruleIdx int) error {
	for j, fqdn := range rule.ToFQDNs {
		if fqdn.MatchName == "" && fqdn.MatchPattern == "" {
			return fmt.Errorf("%w: rule %d selector %d", ErrFQDNSelectorEmpty, ruleIdx, j)
		}

		if fqdn.MatchName != "" && fqdn.MatchPattern != "" {
			return fmt.Errorf("%w: rule %d selector %d", ErrFQDNSelectorAmbiguous, ruleIdx, j)
		}

		// Character and length validation, matching Cilium's
		// FQDNSelector.sanitize() and matchpattern.prevalidate().
		if fqdn.MatchName != "" {
			if len(fqdn.MatchName) > maxFQDNLength {
				return fmt.Errorf("%w: rule %d selector %d name %q (%d chars)",
					ErrFQDNTooLong, ruleIdx, j, fqdn.MatchName, len(fqdn.MatchName))
			}

			if !allowedMatchNameChars.MatchString(fqdn.MatchName) {
				return fmt.Errorf("%w: rule %d selector %d name %q",
					ErrFQDNNameInvalidChars, ruleIdx, j, fqdn.MatchName)
			}
		}

		if fqdn.MatchPattern != "" {
			if len(fqdn.MatchPattern) > maxFQDNLength {
				return fmt.Errorf("%w: rule %d selector %d pattern %q (%d chars)",
					ErrFQDNTooLong, ruleIdx, j, fqdn.MatchPattern, len(fqdn.MatchPattern))
			}

			if !allowedMatchPatternChars.MatchString(fqdn.MatchPattern) {
				return fmt.Errorf("%w: rule %d selector %d pattern %q",
					ErrFQDNPatternInvalidChars, ruleIdx, j, fqdn.MatchPattern)
			}
		}

		// Compile the anchored regex as defense-in-depth. The
		// character allowlist makes failure extremely unlikely, but
		// catching it here avoids a panic from regexp.MustCompile
		// in CompileFQDNPatterns during resolution.
		var (
			value       string
			isMatchName bool
		)

		if fqdn.MatchName != "" {
			value = fqdn.MatchName
			isMatchName = true
		} else {
			value = fqdn.MatchPattern
		}

		regex := patternToAnchoredRegex(value, isMatchName)
		_, err := regexp.Compile(regex)
		if err != nil {
			return fmt.Errorf("%w: rule %d selector %d: %w", ErrFQDNPatternCompile, ruleIdx, j, err)
		}
	}

	return nil
}

// validateFQDNConstraints checks cross-selector constraints when a rule
// has toFQDNs: no CIDR mixing, and port constraints for L7 rules.
// FQDN rules without toPorts are allowed (catch-all IP-level
// enforcement via ipsets, matching Cilium's default behavior).
// FQDN rules with L7 HTTP rules still require explicit ports because
// Envoy needs per-port listeners for HTTP inspection.
func validateFQDNConstraints(rule EgressRule, ruleIdx int, hasFQDNs bool) error {
	if !hasFQDNs {
		return nil
	}

	if len(rule.ToCIDR) > 0 || len(rule.ToCIDRSet) > 0 {
		return fmt.Errorf("%w: rule %d", ErrFQDNWithCIDR, ruleIdx)
	}

	hasL7 := ruleHasL7(rule)

	hasExplicitPorts := false
	for _, pr := range rule.ToPorts {
		if len(pr.Ports) > 0 {
			hasExplicitPorts = true

			break
		}
	}

	// L7 rules require explicit ports for Envoy listeners.
	if hasL7 && !hasExplicitPorts {
		return fmt.Errorf("%w: rule %d", ErrFQDNRequiresPorts, ruleIdx)
	}

	// Without toPorts (or only L7-only toPorts with empty Ports),
	// the rule is a catch-all: allow all ports via FQDN ipsets.
	if !hasExplicitPorts {
		return nil
	}

	for _, pr := range rule.ToPorts {
		for _, p := range pr.Ports {
			if p.Port == "0" {
				// Wildcard port 0 with L7 is rejected (Envoy
				// needs concrete ports). Without L7, port 0 is
				// treated as catch-all.
				if hasL7 {
					return fmt.Errorf("%w: rule %d", ErrFQDNWildcardPort, ruleIdx)
				}

				return nil
			}

			// Limit FQDN port ranges to prevent creating thousands
			// of Envoy listeners and exhausting proxy port space.
			if p.EndPort > 0 {
				n, err := ResolvePort(p.Port)
				if err == nil && p.EndPort-int(n) > maxFQDNEndPortRange {
					return fmt.Errorf(
						"%w: rule %d port %s endPort %d (range %d)",
						ErrFQDNPortRangeTooLarge, ruleIdx,
						p.Port, p.EndPort, p.EndPort-int(n),
					)
				}
			}
		}
	}

	return nil
}

// validatePorts checks that each port entry has a valid port number,
// protocol, and endPort configuration.
func validatePorts(rule EgressRule, ruleIdx int) error {
	for _, pr := range rule.ToPorts {
		err := validateUnsupportedPortRuleFeatures(pr, ruleIdx)
		if err != nil {
			return err
		}

		err = validateUnsupportedL7Features(pr.Rules, ruleIdx)
		if err != nil {
			return err
		}

		err = validateServerNames(pr, rule, ruleIdx)
		if err != nil {
			return err
		}

		if len(pr.Ports) > maxPorts {
			return fmt.Errorf("%w: rule %d has %d ports",
				ErrPortsTooMany, ruleIdx, len(pr.Ports))
		}

		hasWildcardPort := false

		for _, p := range pr.Ports {
			if p.Port == "" {
				return fmt.Errorf("%w: rule %d", ErrPortEmpty, ruleIdx)
			}

			n, err := ResolvePort(p.Port)
			if err != nil {
				return fmt.Errorf("%w: rule %d port %q", ErrPortInvalid, ruleIdx, p.Port)
			}

			if n == 0 {
				hasWildcardPort = true
			}

			if !validProtocols[p.Protocol] {
				return fmt.Errorf("%w: rule %d port %q protocol %q", ErrProtocolInvalid, ruleIdx, p.Port, p.Protocol)
			}

			err = validateEndPort(p, int(n), ruleIdx)
			if err != nil {
				return err
			}
		}

		err = validateHTTPRules(pr, ruleIdx)
		if err != nil {
			return err
		}

		// Cilium's PortRule.sanitize() rejects L7 rules with port 0:
		// "L7 rules can not be used when a port is 0". This applies
		// to all L7 rule types (DNS, HTTP).
		hasL7 := pr.Rules != nil &&
			(len(pr.Rules.HTTP) > 0 || len(pr.Rules.DNS) > 0)
		if hasL7 && hasWildcardPort {
			return fmt.Errorf("%w: rule %d", ErrL7WithWildcardPort, ruleIdx)
		}

		if pr.Rules != nil && len(pr.Rules.HTTP) > 0 {
			if len(pr.Ports) == 0 {
				return fmt.Errorf("%w: rule %d", ErrL7WithWildcardPort, ruleIdx)
			}

			for _, p := range pr.Ports {
				if p.Protocol != "" && p.Protocol != ProtoTCP {
					return fmt.Errorf("%w: rule %d port %s protocol %s",
						ErrL7RequiresTCP, ruleIdx, p.Port, p.Protocol)
				}
			}
		}
	}

	return nil
}

// validateEndPort checks endPort constraints for a single port entry.
// EndPort with named ports or wildcard port 0 is silently ignored,
// matching Cilium's behavior.
func validateEndPort(p Port, portNum, ruleIdx int) error {
	if p.EndPort == 0 {
		return nil
	}

	if p.EndPort < 0 {
		return fmt.Errorf("%w: rule %d endPort %d", ErrEndPortNegative, ruleIdx, p.EndPort)
	}

	// Cilium silently ignores endPort with named ports and wildcard
	// port 0. Match that behavior rather than rejecting.
	if isSvcName(p.Port) || portNum == 0 {
		return nil
	}

	if p.EndPort > 65535 {
		return fmt.Errorf("%w: rule %d endPort %d exceeds 65535", ErrEndPortInvalid, ruleIdx, p.EndPort)
	}

	if p.EndPort < portNum {
		return fmt.Errorf("%w: rule %d port %q endPort %d", ErrEndPortInvalid, ruleIdx, p.Port, p.EndPort)
	}

	return nil
}

// validateHTTPRules checks that HTTP rule path and method patterns are
// valid regular expressions.
func validateHTTPRules(pr PortRule, ruleIdx int) error {
	if pr.Rules == nil {
		return nil
	}

	for _, h := range pr.Rules.HTTP {
		for i, hm := range h.HeaderMatches {
			if hm.Name == "" {
				return fmt.Errorf("%w: rule %d headerMatches[%d]", ErrHeaderMatchNameEmpty, ruleIdx, i)
			}

			if hm.Mismatch != "" {
				switch hm.Mismatch {
				case MismatchLOG, MismatchADD, MismatchDELETE, MismatchREPLACE:
				default:
					return fmt.Errorf(
						"%w: rule %d headerMatches[%d] mismatch %q",
						ErrHeaderMatchMismatchInvalid, ruleIdx, i, hm.Mismatch,
					)
				}

				if (hm.Mismatch == MismatchADD || hm.Mismatch == MismatchREPLACE) && hm.Value == "" {
					return fmt.Errorf(
						"%w: rule %d headerMatches[%d]",
						ErrHeaderMatchMismatchValue, ruleIdx, i,
					)
				}
			}

			if hm.Secret != nil {
				return fmt.Errorf(
					"%w: rule %d headerMatches[%d]",
					ErrHeaderMatchSecret, ruleIdx, i,
				)
			}
		}

		if h.Path != "" {
			if len(h.Path) > maxRegexLen {
				return fmt.Errorf(
					"%w: rule %d path too long (%d > %d)",
					ErrPathInvalidRegex,
					ruleIdx,
					len(h.Path),
					maxRegexLen,
				)
			}

			_, err := regexp.Compile(h.Path)
			if err != nil {
				return fmt.Errorf("%w: rule %d path %q", ErrPathInvalidRegex, ruleIdx, h.Path)
			}
		}

		if h.Method != "" {
			if len(h.Method) > maxRegexLen {
				return fmt.Errorf(
					"%w: rule %d method too long (%d > %d)",
					ErrMethodInvalidRegex,
					ruleIdx,
					len(h.Method),
					maxRegexLen,
				)
			}

			_, err := regexp.Compile(h.Method)
			if err != nil {
				return fmt.Errorf("%w: rule %d method %q", ErrMethodInvalidRegex, ruleIdx, h.Method)
			}
		}
	}

	return nil
}

// validateL7Rules checks that L7 rules have an appropriate L3 selector
// and that wildcard matchPatterns are not combined with L7 rules.
// L7 HTTP rules are allowed with:
//   - toFQDNs: MITM-based HTTP inspection (existing behavior).
//   - toCIDR/toCIDRSet: plain HTTP filtering via catch-all Envoy
//     virtual hosts. ServerNames must not be present (implies TLS,
//     and MITM without known domains is not feasible).
func validateL7Rules(rule EgressRule, ruleIdx int, hasFQDNs bool) error {
	hasCIDR := len(rule.ToCIDR) > 0 || len(rule.ToCIDRSet) > 0
	hasL7 := false

	for _, pr := range rule.ToPorts {
		if pr.Rules != nil && len(pr.Rules.HTTP) > 0 {
			if !hasFQDNs && !hasCIDR {
				return fmt.Errorf("%w: rule %d", ErrL7RequiresL3, ruleIdx)
			}

			hasL7 = true
		}
	}

	if !hasL7 {
		return nil
	}

	// CIDR+L7 with serverNames is rejected: serverNames implies TLS,
	// and MITM without domain names is not feasible.
	if hasCIDR {
		for _, pr := range rule.ToPorts {
			if len(pr.ServerNames) > 0 {
				return fmt.Errorf("%w: rule %d", ErrCIDRL7WithServerNames, ruleIdx)
			}
		}
	}

	// MITM cert generation requires a wildcard-free suffix. Patterns
	// are L7-incompatible if, after stripping any leading "*." or
	// "**." prefix, the remainder still contains "*". This catches:
	//   - bare wildcards: "*", "**"
	//   - non-leading wildcards: "api.*.example.com"
	//   - suffix wildcards: "*.ci*.io", "*.*.cilium.io"
	// Simple prefix wildcards ("*.example.com", "**.example.com")
	// are allowed: Go x509 supports wildcard SANs.
	if hasFQDNs {
		for j, fqdn := range rule.ToFQDNs {
			if fqdn.MatchPattern != "" && isL7IncompatibleWildcard(fqdn.MatchPattern) {
				return fmt.Errorf("%w: rule %d selector %d pattern %q",
					ErrPartialWildcardWithL7, ruleIdx, j, fqdn.MatchPattern)
			}
		}
	}

	return nil
}

// validateCIDRSets checks that each CIDR set entry is valid and that
// except entries are subnets of the parent CIDR.
func validateCIDRSets(rule EgressRule, ruleIdx int) error {
	return validateCIDRSetEntries(rule.ToCIDRSet, "rule", ruleIdx)
}

// validateCIDRSetEntries validates a list of [CIDRRule] entries,
// checking unsupported features, CIDR format, address family
// consistency, and except subnet containment. The prefix parameter
// (e.g. "rule" or "egressDeny rule") is used in error messages.
func validateCIDRSetEntries(cidrs []CIDRRule, prefix string, idx int) error {
	for _, cidr := range cidrs {
		if cidr.CIDR == "" {
			return fmt.Errorf("%w: %s %d", ErrCIDREmpty, prefix, idx)
		}

		err := validateUnsupportedCIDRRuleFeatures(cidr, idx)
		if err != nil {
			return err
		}

		_, parentNet, err := net.ParseCIDR(cidr.CIDR)
		if err != nil {
			return fmt.Errorf("%w: %s %d cidr %q", ErrCIDRInvalid, prefix, idx, cidr.CIDR)
		}

		parentIsV6 := cidrIsIPv6(cidr.CIDR)
		parentOnes, _ := parentNet.Mask.Size()

		for _, exc := range cidr.Except {
			_, excNet, excErr := net.ParseCIDR(exc)
			if excErr != nil {
				return fmt.Errorf("%w: %s %d except %q", ErrCIDRInvalid, prefix, idx, exc)
			}

			if cidrIsIPv6(exc) != parentIsV6 {
				return fmt.Errorf(
					"%w: %s %d except %q (%s) does not match parent %q (%s)",
					ErrExceptAddressFamilyMismatch,
					prefix, idx,
					exc, familyLabel(cidrIsIPv6(exc)),
					cidr.CIDR, familyLabel(parentIsV6),
				)
			}

			excOnes, _ := excNet.Mask.Size()
			if !parentNet.Contains(excNet.IP) || excOnes < parentOnes {
				return fmt.Errorf(
					"%w: %s %d except %q not in %q",
					ErrExceptNotSubnet, prefix, idx, exc, cidr.CIDR,
				)
			}
		}
	}

	return nil
}

// familyLabel returns "IPv6" or "IPv4" for use in error messages.
func familyLabel(isV6 bool) string {
	if isV6 {
		return "IPv6"
	}

	return "IPv4"
}

// validateDNSRules checks that DNS L7 rules are well-formed and appear
// only on port-53 toPorts entries. Each DNS rule must have at least one
// of matchName or matchPattern, using the same character and wildcard
// constraints as [FQDNSelector]. When both are set they are evaluated
// with OR semantics.
func validateDNSRules(rule EgressRule, ruleIdx int) error {
	for _, pr := range rule.ToPorts {
		if pr.Rules == nil || len(pr.Rules.DNS) == 0 {
			continue
		}

		// DNS rules must be on a toPorts entry that includes port 53.
		if !portRuleIncludesPort53(pr) {
			return fmt.Errorf("%w: rule %d", ErrDNSRuleRequiresPort53, ruleIdx)
		}

		// Cilium's PortProtocol.sanitize() rejects port ranges on
		// DNS rules ("DNS rules do not support port ranges").
		for _, p := range pr.Ports {
			if p.EndPort == 0 {
				continue
			}

			n, err := ResolvePort(p.Port)
			if err != nil {
				continue
			}

			if p.EndPort > int(n) {
				return fmt.Errorf("%w: rule %d port %s endPort %d",
					ErrDNSRulePortRange, ruleIdx, p.Port, p.EndPort)
			}
		}

		for j, dns := range pr.Rules.DNS {
			if dns.MatchName == "" && dns.MatchPattern == "" {
				return fmt.Errorf("%w: rule %d dns %d", ErrDNSRuleSelectorEmpty, ruleIdx, j)
			}

			if dns.MatchName != "" {
				if len(dns.MatchName) > maxFQDNLength {
					return fmt.Errorf("%w: rule %d dns %d name %q (%d chars)",
						ErrFQDNTooLong, ruleIdx, j, dns.MatchName, len(dns.MatchName))
				}

				if !allowedMatchNameChars.MatchString(dns.MatchName) {
					return fmt.Errorf("%w: rule %d dns %d name %q",
						ErrFQDNNameInvalidChars, ruleIdx, j, dns.MatchName)
				}
			}

			if dns.MatchPattern != "" {
				if len(dns.MatchPattern) > maxFQDNLength {
					return fmt.Errorf("%w: rule %d dns %d pattern %q (%d chars)",
						ErrFQDNTooLong, ruleIdx, j, dns.MatchPattern, len(dns.MatchPattern))
				}

				if !allowedMatchPatternChars.MatchString(dns.MatchPattern) {
					return fmt.Errorf("%w: rule %d dns %d pattern %q",
						ErrFQDNPatternInvalidChars, ruleIdx, j, dns.MatchPattern)
				}

				err := validateDNSWildcardPattern(dns.MatchPattern, ruleIdx, j)
				if err != nil {
					return err
				}
			}

			// Compile anchored regexes as defense-in-depth. The
			// character allowlist makes failure extremely unlikely, but
			// catching it here avoids a downstream failure during
			// resolution.
			if dns.MatchName != "" {
				regex := patternToAnchoredRegex(dns.MatchName, true)
				_, err := regexp.Compile(regex)
				if err != nil {
					return fmt.Errorf(
						"%w: rule %d dns %d: %w",
						ErrDNSPatternCompile, ruleIdx, j, err,
					)
				}
			}

			if dns.MatchPattern != "" {
				regex := patternToAnchoredRegex(dns.MatchPattern, false)
				_, err := regexp.Compile(regex)
				if err != nil {
					return fmt.Errorf(
						"%w: rule %d dns %d: %w",
						ErrDNSPatternCompile, ruleIdx, j, err,
					)
				}
			}
		}
	}

	return nil
}

// validateDNSWildcardPattern validates wildcard patterns in DNS rules.
// All wildcard positions are valid; the character allowlist already
// ensures only valid DNS and wildcard characters, and
// patternToAnchoredRegex handles any position correctly.
func validateDNSWildcardPattern(_ string, _, _ int) error {
	return nil
}

// validateServerNames checks that serverNames entries are valid
// hostnames and that the containing rule uses an L3 selector with
// TCP protocol. ServerNames with toFQDNs is accepted for Cilium
// policy portability but is a no-op: the FQDN SNI filter chain
// already controls allowed domains.
func validateServerNames(pr PortRule, rule EgressRule, ruleIdx int) error {
	if len(pr.ServerNames) == 0 {
		return nil
	}

	// serverNames requires an L3 selector.
	hasL3 := len(rule.ToCIDR) > 0 || len(rule.ToCIDRSet) > 0 || len(rule.ToFQDNs) > 0
	if !hasL3 {
		return fmt.Errorf("%w: rule %d", ErrServerNamesRequiresL3, ruleIdx)
	}

	// All ports must be TCP.
	for _, p := range pr.Ports {
		if p.Protocol != "" && p.Protocol != ProtoTCP {
			return fmt.Errorf("%w: rule %d port %s protocol %s",
				ErrServerNamesRequiresTCP, ruleIdx, p.Port, p.Protocol)
		}
	}

	// Validate hostname characters. All wildcard positions are valid;
	// the RBAC regex approach handles arbitrary positions for SNI
	// matching. Bare wildcards are already filtered during
	// normalization (treated as omitting serverNames).
	for _, name := range pr.ServerNames {
		if !allowedMatchPatternChars.MatchString(name) {
			return fmt.Errorf("%w: rule %d name %q",
				ErrServerNamesInvalidHostname, ruleIdx, name)
		}
	}

	return nil
}

// validateEgressDenyRules checks that all egress deny rules are
// well-formed: valid CIDRs, valid ports, and no L7 rules. Empty deny
// rules (no selectors) are expanded to deny-all (0.0.0.0/0 + ::/0),
// matching Cilium's acceptance of empty [EgressDenyRule].
func (c *Config) validateEgressDenyRules() error {
	denyRules := c.EgressDenyRules()
	for i := range denyRules {
		// Expand toEndpoints: [{}] wildcard before rejecting
		// unsupported selectors.
		err := expandAndValidateDenyEndpoints(&(*c.EgressDeny)[i], i)
		if err != nil {
			return err
		}

		// Reject unsupported Cilium selectors before any other
		// processing.
		err = validateUnsupportedDenySelectors(denyRules[i], i)
		if err != nil {
			return err
		}

		// Expand entities before normalization and the empty-rule
		// check so expanded CIDRs satisfy selectors.
		err = expandAndValidateDenyEntities(&(*c.EgressDeny)[i], i)
		if err != nil {
			return err
		}

		normalizeEgressDenyRule(c, i)

		rule := denyRules[i]

		// An empty deny rule (no selectors) is interpreted as
		// deny-all, matching Cilium's EgressDenyRule.sanitize()
		// which accepts empty deny rules. Expand to dual-stack
		// CIDRs covering all destinations.
		if len(rule.ToCIDR) == 0 && len(rule.ToCIDRSet) == 0 && len(rule.ToPorts) == 0 && len(rule.ICMPs) == 0 {
			(*c.EgressDeny)[i].ToCIDR = append((*c.EgressDeny)[i].ToCIDR, "0.0.0.0/0", "::/0")
			rule = (*c.EgressDeny)[i]
		}

		if len(rule.ToCIDR) > 0 && len(rule.ToCIDRSet) > 0 {
			return fmt.Errorf("%w: egressDeny rule %d", ErrCIDRAndCIDRSetMixed, i)
		}

		for _, cidr := range rule.ToCIDR {
			_, _, parseErr := net.ParseCIDR(cidr)
			if parseErr != nil {
				return fmt.Errorf("%w: egressDeny rule %d cidr %q", ErrCIDRInvalid, i, cidr)
			}
		}

		for _, pr := range rule.ToPorts {
			if pr.Rules != nil {
				return fmt.Errorf("%w: egressDeny rule %d", ErrDenyRuleL7, i)
			}

			if len(pr.ServerNames) > 0 {
				return fmt.Errorf("%w: egressDeny rule %d", ErrDenyRuleServerNames, i)
			}

			err = validateUnsupportedPortRuleFeatures(pr, i)
			if err != nil {
				return err
			}

			if len(pr.Ports) == 0 {
				return fmt.Errorf("%w: egressDeny rule %d", ErrDenyRulePortsEmpty, i)
			}

			if len(pr.Ports) > maxPorts {
				return fmt.Errorf("%w: egressDeny rule %d has %d ports",
					ErrPortsTooMany, i, len(pr.Ports))
			}

			for _, p := range pr.Ports {
				if p.Port == "" {
					return fmt.Errorf("%w: egressDeny rule %d", ErrPortEmpty, i)
				}

				n, err := ResolvePort(p.Port)
				if err != nil {
					return fmt.Errorf(
						"%w: egressDeny rule %d port %q",
						ErrPortInvalid, i, p.Port,
					)
				}

				if n == 0 {
					return fmt.Errorf("%w: egressDeny rule %d", ErrDenyRuleWildcardPort, i)
				}

				if !validProtocols[p.Protocol] {
					return fmt.Errorf(
						"%w: egressDeny rule %d port %q protocol %q",
						ErrProtocolInvalid, i, p.Port, p.Protocol,
					)
				}

				err = validateEndPort(p, int(n), i)
				if err != nil {
					return err
				}
			}
		}

		err = validateCIDRSetEntries(rule.ToCIDRSet, "egressDeny rule", i)
		if err != nil {
			return err
		}

		err = validateICMPRules(rule.ICMPs, rule.ToPorts, "egressDeny rule", i)
		if err != nil {
			return err
		}
	}

	return nil
}

// expandAndValidateEntities processes toEntities on an egress rule.
// Supported entities are expanded into CIDRs appended to ToCIDR:
// "world" and "all" expand to dual-stack (0.0.0.0/0 and ::/0),
// "world-ipv4" to 0.0.0.0/0 only, and "world-ipv6" to ::/0 only.
// Unsupported values are rejected with [ErrUnsupportedEntity]. After
// processing, ToEntities is cleared so downstream L3 mutual-exclusivity
// checks operate on the expanded CIDRs.
func expandAndValidateEntities(rule *EgressRule, ruleIdx int) error {
	if len(rule.ToEntities) == 0 {
		return nil
	}

	// L3 mutual exclusivity: Cilium rejects any rule combining two
	// different L3 selector fields. Check before expansion so the
	// original user intent is visible in the error.
	if len(rule.ToCIDR) > 0 || len(rule.ToCIDRSet) > 0 || len(rule.ToFQDNs) > 0 {
		return fmt.Errorf("%w: rule %d", ErrEntitiesMixedL3, ruleIdx)
	}

	for _, entity := range rule.ToEntities {
		cidrs, ok := entityCIDRs[strings.ToLower(entity)]
		if !ok {
			return fmt.Errorf("%w: rule %d has %q", ErrUnsupportedEntity, ruleIdx, entity)
		}

		rule.ToCIDR = append(rule.ToCIDR, cidrs...)
	}

	rule.ToEntities = nil

	return nil
}

// expandAndValidateDenyEntities processes toEntities on an egress deny
// rule. Supported entities are expanded into CIDRs appended to ToCIDR.
// Unsupported values are rejected with [ErrUnsupportedEntity]. After
// processing, ToEntities is cleared.
func expandAndValidateDenyEntities(rule *EgressDenyRule, ruleIdx int) error {
	if len(rule.ToEntities) == 0 {
		return nil
	}

	// L3 mutual exclusivity: deny rules with entities cannot also
	// have toCIDR or toCIDRSet.
	if len(rule.ToCIDR) > 0 || len(rule.ToCIDRSet) > 0 {
		return fmt.Errorf("%w: egressDeny rule %d", ErrDenyEntitiesMixedL3, ruleIdx)
	}

	for _, entity := range rule.ToEntities {
		cidrs, ok := entityCIDRs[strings.ToLower(entity)]
		if !ok {
			return fmt.Errorf("%w: egressDeny rule %d has %q", ErrUnsupportedEntity, ruleIdx, entity)
		}

		rule.ToCIDR = append(rule.ToCIDR, cidrs...)
	}

	rule.ToEntities = nil

	return nil
}

// expandAndValidateEndpoints processes toEndpoints on an egress rule.
// In Cilium, an empty EndpointSelector {} (no matchLabels constraints)
// matches all endpoints, following standard Kubernetes LabelSelector
// semantics. Terrarium expands toEndpoints: [{}] into dual-stack CIDRs
// (0.0.0.0/0 and ::/0), equivalent to toEntities: [world].
//
// An empty list (toEndpoints: []) selects nothing per Cilium's
// documented behavior and is treated as omitting the field.
//
// Non-empty label selectors (e.g., [{matchLabels: {k: v}}]) are left
// in place for [validateUnsupportedSelectors] to reject with
// [ErrUnsupportedSelector].
func expandAndValidateEndpoints(rule *EgressRule, ruleIdx int) error {
	if len(rule.ToEndpoints) == 0 {
		return nil
	}

	// Check each endpoint selector. An empty map (or nil) is the
	// wildcard; anything with keys is a label selector we cannot
	// support.
	allEmpty := true
	for _, ep := range rule.ToEndpoints {
		m, ok := ep.(map[string]any)
		if !ok || len(m) > 0 {
			allEmpty = false
			break
		}
	}

	if !allEmpty {
		// Leave non-empty selectors for validateUnsupportedSelectors
		// to reject with ErrUnsupportedSelector.
		return nil
	}

	// All entries are empty selectors: wildcard match-all.
	// L3 mutual exclusivity: cannot combine with other L3 selectors.
	if len(rule.ToCIDR) > 0 || len(rule.ToCIDRSet) > 0 || len(rule.ToFQDNs) > 0 {
		return fmt.Errorf("%w: rule %d", ErrEndpointsMixedL3, ruleIdx)
	}

	rule.ToCIDR = append(rule.ToCIDR, "0.0.0.0/0", "::/0")
	rule.ToEndpoints = nil

	return nil
}

// expandAndValidateDenyEndpoints processes toEndpoints on an egress
// deny rule, following the same logic as [expandAndValidateEndpoints].
func expandAndValidateDenyEndpoints(rule *EgressDenyRule, ruleIdx int) error {
	if len(rule.ToEndpoints) == 0 {
		return nil
	}

	allEmpty := true
	for _, ep := range rule.ToEndpoints {
		m, ok := ep.(map[string]any)
		if !ok || len(m) > 0 {
			allEmpty = false
			break
		}
	}

	if !allEmpty {
		return nil
	}

	if len(rule.ToCIDR) > 0 || len(rule.ToCIDRSet) > 0 {
		return fmt.Errorf("%w: egressDeny rule %d", ErrEndpointsMixedL3, ruleIdx)
	}

	rule.ToCIDR = append(rule.ToCIDR, "0.0.0.0/0", "::/0")
	rule.ToEndpoints = nil

	return nil
}

// isL7IncompatibleWildcard reports whether a matchPattern cannot be
// used with L7 HTTP rules. MITM cert generation requires a
// wildcard-free suffix (RFC 6125 only supports *.suffix form). A
// pattern is incompatible if, after stripping any leading "*." or
// "**." prefix, the remainder still contains "*".
func isL7IncompatibleWildcard(pattern string) bool {
	suffix := pattern
	if strings.HasPrefix(suffix, "**.") {
		suffix = suffix[3:]
	} else if strings.HasPrefix(suffix, "*.") {
		suffix = suffix[2:]
	}

	return strings.Contains(suffix, "*")
}

// portRuleIncludesPort53 reports whether a [PortRule] includes port 53.
// An empty Ports list does not match; Cilium requires an explicit port
// 53 entry for DNS rules.
func portRuleIncludesPort53(pr PortRule) bool {
	for _, p := range pr.Ports {
		resolved, err := ResolvePort(p.Port)
		if err != nil {
			continue
		}

		n := int(resolved)

		if n == 53 {
			return true
		}

		if p.EndPort > 0 && 53 >= n && 53 <= p.EndPort {
			return true
		}
	}

	return false
}
