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

// maxRegexLen is the maximum allowed length for path and method
// regex patterns. Envoy uses RE2 with a default max program size
// of 100; extremely long patterns could pass Go validation but
// fail in RE2.
const maxRegexLen = 1000

var (
	// allowedMatchNameChars validates that a matchName contains only
	// DNS-safe characters. Matches Cilium's allowedMatchNameChars
	// (pkg/policy/api/fqdn.go) but uses only lowercase since
	// normalizeEgressRule lowercases before validation.
	allowedMatchNameChars = regexp.MustCompile(`^[-a-z0-9_.]+$`)

	// allowedMatchPatternChars validates that a matchPattern contains
	// only DNS-safe characters plus the wildcard '*'. Matches Cilium's
	// allowedPatternChars (pkg/fqdn/matchpattern/matchpattern.go).
	allowedMatchPatternChars = regexp.MustCompile(`^[-a-z0-9_.*]+$`)

	// validProtocols lists the supported transport protocols. Cilium
	// also supports ICMP, ICMPv6, VRRP, and IGMP, but these are
	// IP-layer protocols without ports and cannot be expressed in the
	// terrarium's port-based model.
	validProtocols = map[string]bool{
		"": true, ProtoTCP: true, ProtoUDP: true, ProtoSCTP: true, ProtoAny: true,
	}

	// supportedEntities lists the toEntities values that terrarium
	// supports. Both "world" and "all" expand to dual-stack CIDRs
	// (0.0.0.0/0 and ::/0). In Cilium's non-Kubernetes context,
	// "all" is functionally identical to "world".
	supportedEntities = map[string]bool{
		"world": true, "all": true,
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
		normalizeEgressRule(c, i)

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

			if isIPv4MappedIPv6(cidr) {
				return fmt.Errorf("%w: rule %d cidr %q", ErrCIDRIPv4MappedIPv6, i, cidr)
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
		{"icmps", len(rule.ICMPs) > 0},
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

		p := fqdn.MatchPattern
		if p == "" {
			continue
		}

		switch {
		case p == "*" || p == "**":
			// Bare wildcards: match all FQDNs.
		case strings.HasPrefix(p, "**."):
			// Multi-label wildcard. The remainder after "**." must be
			// wildcard-free.
			if strings.Contains(p[3:], "*") {
				return fmt.Errorf("%w: rule %d selector %d pattern %q",
					ErrFQDNPatternPartialWildcard, ruleIdx, j, fqdn.MatchPattern)
			}

		case strings.HasPrefix(p, "*."):
			// Single-label wildcard. The remainder after "*." must be
			// wildcard-free.
			if strings.Contains(p[2:], "*") {
				return fmt.Errorf("%w: rule %d selector %d pattern %q",
					ErrFQDNPatternPartialWildcard, ruleIdx, j, fqdn.MatchPattern)
			}

		case containsMidPositionDoubleStar(p):
			// Mid-position ** as a complete label (e.g. "test.**.cilium.io").
			// patternToAnchoredRegex handles this via the generic path,
			// producing correct single-label semantics per star.

		case strings.Contains(p, "*"):
			// Wildcard not in a valid leading position.
			return fmt.Errorf("%w: rule %d selector %d pattern %q",
				ErrFQDNPatternPartialWildcard, ruleIdx, j, fqdn.MatchPattern)
		}
	}

	return nil
}

// validateFQDNConstraints checks cross-selector constraints when a rule
// has toFQDNs: no CIDR mixing, and explicit ports are required.
func validateFQDNConstraints(rule EgressRule, ruleIdx int, hasFQDNs bool) error {
	if !hasFQDNs {
		return nil
	}

	if len(rule.ToCIDR) > 0 || len(rule.ToCIDRSet) > 0 {
		return fmt.Errorf("%w: rule %d", ErrFQDNWithCIDR, ruleIdx)
	}

	hasExplicitPorts := false
	for _, pr := range rule.ToPorts {
		if len(pr.Ports) > 0 {
			hasExplicitPorts = true

			break
		}
	}

	if !hasExplicitPorts {
		return fmt.Errorf("%w: rule %d", ErrFQDNRequiresPorts, ruleIdx)
	}

	for _, pr := range rule.ToPorts {
		for _, p := range pr.Ports {
			if p.Port == "0" {
				return fmt.Errorf("%w: rule %d", ErrFQDNWildcardPort, ruleIdx)
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

		if pr.Rules != nil && len(pr.Rules.HTTP) > 0 {
			if len(pr.Ports) == 0 || hasWildcardPort {
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
		if h.Host != "" {
			if len(h.Host) > maxRegexLen {
				return fmt.Errorf(
					"%w: rule %d host too long (%d > %d)",
					ErrHostInvalidRegex,
					ruleIdx,
					len(h.Host),
					maxRegexLen,
				)
			}

			_, err := regexp.Compile(h.Host)
			if err != nil {
				return fmt.Errorf("%w: rule %d host %q", ErrHostInvalidRegex, ruleIdx, h.Host)
			}
		}

		for i, hdr := range h.Headers {
			if hdr == "" {
				return fmt.Errorf("%w: rule %d headers[%d]", ErrHTTPHeaderEmpty, ruleIdx, i)
			}
		}

		for i, hm := range h.HeaderMatches {
			if hm.Name == "" {
				return fmt.Errorf("%w: rule %d headerMatches[%d]", ErrHeaderMatchNameEmpty, ruleIdx, i)
			}

			if hm.Mismatch != "" {
				return fmt.Errorf("%w: rule %d headerMatches[%d] mismatch %q",
					ErrHeaderMatchMismatchAction, ruleIdx, i, hm.Mismatch)
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

// validateL7Rules checks that L7 rules are only used with toFQDNs
// and that wildcard matchPatterns are not combined with L7 rules.
func validateL7Rules(rule EgressRule, ruleIdx int, hasFQDNs bool) error {
	hasL7 := false
	for _, pr := range rule.ToPorts {
		if pr.Rules != nil && len(pr.Rules.HTTP) > 0 {
			if !hasFQDNs {
				return fmt.Errorf("%w: rule %d", ErrL7RequiresFQDN, ruleIdx)
			}

			hasL7 = true
		}
	}

	// Wildcard matchPatterns break MITM cert paths.
	if hasL7 {
		for j, fqdn := range rule.ToFQDNs {
			if strings.Contains(fqdn.MatchPattern, "*") {
				return fmt.Errorf("%w: rule %d selector %d", ErrWildcardWithL7, ruleIdx, j)
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
		err := validateUnsupportedCIDRRuleFeatures(cidr, idx)
		if err != nil {
			return err
		}

		_, parentNet, err := net.ParseCIDR(cidr.CIDR)
		if err != nil {
			return fmt.Errorf("%w: %s %d cidr %q", ErrCIDRInvalid, prefix, idx, cidr.CIDR)
		}

		if isIPv4MappedIPv6(cidr.CIDR) {
			return fmt.Errorf("%w: %s %d cidr %q", ErrCIDRIPv4MappedIPv6, prefix, idx, cidr.CIDR)
		}

		parentIsV6 := cidrIsIPv6(cidr.CIDR)
		parentOnes, _ := parentNet.Mask.Size()

		for _, exc := range cidr.Except {
			_, excNet, excErr := net.ParseCIDR(exc)
			if excErr != nil {
				return fmt.Errorf("%w: %s %d except %q", ErrCIDRInvalid, prefix, idx, exc)
			}

			if isIPv4MappedIPv6(exc) {
				return fmt.Errorf("%w: %s %d except %q", ErrCIDRIPv4MappedIPv6, prefix, idx, exc)
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
// only on port-53 toPorts entries. Each DNS rule must have exactly one
// of matchName or matchPattern, using the same character and wildcard
// constraints as [FQDNSelector].
func validateDNSRules(rule EgressRule, ruleIdx int) error {
	for _, pr := range rule.ToPorts {
		if pr.Rules == nil || len(pr.Rules.DNS) == 0 {
			continue
		}

		// DNS rules must be on a toPorts entry that includes port 53.
		if !portRuleIncludesPort53(pr) {
			return fmt.Errorf("%w: rule %d", ErrDNSRuleRequiresPort53, ruleIdx)
		}

		for j, dns := range pr.Rules.DNS {
			if dns.MatchName == "" && dns.MatchPattern == "" {
				return fmt.Errorf("%w: rule %d dns %d", ErrDNSRuleSelectorEmpty, ruleIdx, j)
			}

			if dns.MatchName != "" && dns.MatchPattern != "" {
				return fmt.Errorf("%w: rule %d dns %d", ErrDNSRuleSelectorAmbiguous, ruleIdx, j)
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
		}
	}

	return nil
}

// validateDNSWildcardPattern validates wildcard patterns in DNS rules
// using the same leading-wildcard rules as [validateFQDNSelectors].
func validateDNSWildcardPattern(p string, ruleIdx, dnsIdx int) error {
	switch {
	case p == "*" || p == "**":
		// Bare wildcards: match all.
	case strings.HasPrefix(p, "**."):
		if strings.Contains(p[3:], "*") {
			return fmt.Errorf("%w: rule %d dns %d pattern %q",
				ErrFQDNPatternPartialWildcard, ruleIdx, dnsIdx, p)
		}

	case strings.HasPrefix(p, "*."):
		if strings.Contains(p[2:], "*") {
			return fmt.Errorf("%w: rule %d dns %d pattern %q",
				ErrFQDNPatternPartialWildcard, ruleIdx, dnsIdx, p)
		}

	case containsMidPositionDoubleStar(p):
		// Mid-position ** as a complete label.

	case strings.Contains(p, "*"):
		return fmt.Errorf("%w: rule %d dns %d pattern %q",
			ErrFQDNPatternPartialWildcard, ruleIdx, dnsIdx, p)
	}

	return nil
}

// validateServerNames checks that serverNames entries are valid
// hostnames and that the containing rule uses toCIDR/toCIDRSet
// with TCP protocol.
func validateServerNames(pr PortRule, rule EgressRule, ruleIdx int) error {
	if len(pr.ServerNames) == 0 {
		return nil
	}

	// serverNames requires toCIDR or toCIDRSet (not toFQDNs).
	if len(rule.ToCIDR) == 0 && len(rule.ToCIDRSet) == 0 {
		return fmt.Errorf("%w: rule %d", ErrServerNamesRequiresCIDR, ruleIdx)
	}

	// All ports must be TCP.
	for _, p := range pr.Ports {
		if p.Protocol != "" && p.Protocol != ProtoTCP {
			return fmt.Errorf("%w: rule %d port %s protocol %s",
				ErrServerNamesRequiresTCP, ruleIdx, p.Port, p.Protocol)
		}
	}

	// Validate hostname characters and wildcard position.
	for _, name := range pr.ServerNames {
		if !allowedMatchPatternChars.MatchString(name) {
			return fmt.Errorf("%w: rule %d name %q",
				ErrServerNamesInvalidHostname, ruleIdx, name)
		}

		if strings.Contains(name, "*") {
			switch {
			case strings.HasPrefix(name, "**.") && !strings.Contains(name[3:], "*"):
				// Multi-label wildcard prefix: valid.
			case strings.HasPrefix(name, "*.") && !strings.Contains(name[2:], "*"):
				// Single-label wildcard prefix: valid.
			default:
				return fmt.Errorf("%w: rule %d name %q",
					ErrServerNamesInvalidWildcard, ruleIdx, name)
			}
		}
	}

	return nil
}

// validateEgressDenyRules checks that all egress deny rules are
// well-formed: valid CIDRs, valid ports, no L7 rules, and at least
// one selector present.
func (c *Config) validateEgressDenyRules() error {
	denyRules := c.EgressDenyRules()
	for i := range denyRules {
		// Expand entities before normalization and the empty-rule
		// check so expanded CIDRs satisfy selectors.
		err := expandAndValidateDenyEntities(&(*c.EgressDeny)[i], i)
		if err != nil {
			return err
		}

		normalizeEgressDenyRule(c, i)

		rule := denyRules[i]

		if len(rule.ToCIDR) == 0 && len(rule.ToCIDRSet) == 0 && len(rule.ToPorts) == 0 {
			return fmt.Errorf("%w: egressDeny rule %d", ErrDenyRuleEmpty, i)
		}

		if len(rule.ToCIDR) > 0 && len(rule.ToCIDRSet) > 0 {
			return fmt.Errorf("%w: egressDeny rule %d", ErrCIDRAndCIDRSetMixed, i)
		}

		for _, cidr := range rule.ToCIDR {
			_, _, parseErr := net.ParseCIDR(cidr)
			if parseErr != nil {
				return fmt.Errorf("%w: egressDeny rule %d cidr %q", ErrCIDRInvalid, i, cidr)
			}

			if isIPv4MappedIPv6(cidr) {
				return fmt.Errorf("%w: egressDeny rule %d cidr %q", ErrCIDRIPv4MappedIPv6, i, cidr)
			}
		}

		for _, pr := range rule.ToPorts {
			if pr.Rules != nil {
				return fmt.Errorf("%w: egressDeny rule %d", ErrDenyRuleL7, i)
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
	}

	return nil
}

// expandAndValidateEntities processes toEntities on an egress rule.
// "world" is expanded into dual-stack CIDRs (0.0.0.0/0 and ::/0)
// appended to ToCIDR. Other entity values are rejected with
// [ErrUnsupportedEntity]. After processing, ToEntities is cleared
// so downstream L3 mutual-exclusivity checks operate on the
// expanded CIDRs.
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
		e := strings.ToLower(entity)
		if !supportedEntities[e] {
			return fmt.Errorf("%w: rule %d has %q", ErrUnsupportedEntity, ruleIdx, entity)
		}

		rule.ToCIDR = append(rule.ToCIDR, "0.0.0.0/0", "::/0")
	}

	rule.ToEntities = nil

	return nil
}

// expandAndValidateDenyEntities processes toEntities on an egress deny
// rule. Supported entities ("world", "all") are expanded into dual-stack
// CIDRs appended to ToCIDR. Unsupported values are rejected with
// [ErrUnsupportedEntity]. After processing, ToEntities is cleared.
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
		e := strings.ToLower(entity)
		if !supportedEntities[e] {
			return fmt.Errorf("%w: egressDeny rule %d has %q", ErrUnsupportedEntity, ruleIdx, entity)
		}

		rule.ToCIDR = append(rule.ToCIDR, "0.0.0.0/0", "::/0")
	}

	rule.ToEntities = nil

	return nil
}

// portRuleIncludesPort53 reports whether a [PortRule] includes port 53
// (or has an empty Ports list, which matches all ports).
func portRuleIncludesPort53(pr PortRule) bool {
	if len(pr.Ports) == 0 {
		return true
	}

	for _, p := range pr.Ports {
		resolved, err := ResolvePort(p.Port)
		if err != nil {
			continue
		}

		n := int(resolved)

		if n == 0 || n == 53 {
			return true
		}

		if p.EndPort > 0 && 53 >= n && 53 <= p.EndPort {
			return true
		}
	}

	return false
}
