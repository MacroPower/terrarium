package firewall

import "github.com/google/nftables/expr"

// LogPrefix exposes the unexported logPrefix helper for tests.
func LogPrefix(prefix string) []expr.Any { return logPrefix(prefix) }

// LogGroupPrefix exposes the unexported logGroupPrefix helper for
// tests.
func LogGroupPrefix(group uint16, prefix string) []expr.Any {
	return logGroupPrefix(group, prefix)
}

// EmitLogExpr renders the log expressions a logEmitter built from
// (enabled, useGroup, group) would produce for prefix. Lets tests
// drive the dispatch table without leaking the unexported struct.
func EmitLogExpr(enabled, useGroup bool, group uint16, prefix string) []expr.Any {
	return logEmitter{enabled: enabled, useGroup: useGroup, group: group}.expr(prefix)
}
