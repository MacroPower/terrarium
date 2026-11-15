package config

import "slices"

// RedactedValue is the value that [Config.Redacted] writes in place of
// a [HeaderMatch] value. It differs from the empty value, so a reader
// can tell a redacted value from a value that the policy left empty.
const RedactedValue = "<redacted>"

// Redacted returns a copy of c in which [RedactedValue] replaces
// every [HeaderMatch] value that is not empty. Such a value can be a
// credential, because the ADD and REPLACE actions write it into the
// requests of the sandboxed process. Pass the copy to [MarshalConfig]
// to write the policy to a place that the sandboxed process can read,
// such as the stats event store.
//
// The copy keeps every rule at its index in `egress` and in
// `egressDeny`, and it keeps an empty value empty. An entry with an
// empty value matches on the presence of the header, so the copy
// still shows which kind of match each entry is. [ParseConfig] accepts
// the marshaled copy whenever it accepts the marshaled c.
//
// Redacted does not change c. The copy shares with c every part that
// holds no [HeaderMatch].
func (c *Config) Redacted() *Config {
	out := *c

	if c.Egress != nil {
		rules := slices.Clone(*c.Egress)

		for i := range rules {
			rules[i].ToPorts = redactPortRules(rules[i].ToPorts)
		}

		out.Egress = &rules
	}

	if c.EgressDeny != nil {
		rules := slices.Clone(*c.EgressDeny)

		for i := range rules {
			rules[i].ToPorts = redactPortRules(rules[i].ToPorts)
		}

		out.EgressDeny = &rules
	}

	return &out
}

// redactPortRules returns ports with [RedactedValue] in place of
// every [HeaderMatch] value that is not empty. It returns ports
// itself when no port rule holds an HTTP rule, and a copy otherwise.
func redactPortRules(ports []PortRule) []PortRule {
	var out []PortRule

	for i := range ports {
		rules := ports[i].Rules
		if rules == nil || len(rules.HTTP) == 0 {
			continue
		}

		if out == nil {
			out = slices.Clone(ports)
		}

		l7 := *rules
		l7.HTTP = slices.Clone(rules.HTTP)

		for j := range l7.HTTP {
			l7.HTTP[j].HeaderMatches = redactHeaderMatches(l7.HTTP[j].HeaderMatches)
		}

		out[i].Rules = &l7
	}

	if out == nil {
		return ports
	}

	return out
}

// redactHeaderMatches returns a copy of matches with [RedactedValue]
// in place of every value that is not empty. It returns matches
// itself when it holds no entry.
func redactHeaderMatches(matches []HeaderMatch) []HeaderMatch {
	if len(matches) == 0 {
		return matches
	}

	out := slices.Clone(matches)

	for i := range out {
		if out[i].Value != "" {
			out[i].Value = RedactedValue
		}
	}

	return out
}
