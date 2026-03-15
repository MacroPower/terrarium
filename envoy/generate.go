package envoy

import "go.jacobcolvin.com/terrarium/config"

// BuildAccessLog returns Envoy stderr access log config when logging is
// enabled, or nil when disabled.
func BuildAccessLog(logging bool) []AccessLog {
	if !logging {
		return nil
	}

	return []AccessLog{{
		Name: "envoy.access_loggers.stderr",
		TypedConfig: typeOnly{
			AtType: "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StderrAccessLog",
		},
	}}
}

// StripL7Restrictions converts restricted rules to passthrough by
// clearing their HTTPRules. This implements Cilium's OR semantics
// between open port rules and FQDN+L7 rules on the same port: the
// open port allows ALL traffic, overriding any L7 restrictions.
func StripL7Restrictions(rules []config.ResolvedRule) []config.ResolvedRule {
	result := make([]config.ResolvedRule, len(rules))
	for i, r := range rules {
		result[i] = config.ResolvedRule{Domain: r.Domain}
	}

	return result
}
