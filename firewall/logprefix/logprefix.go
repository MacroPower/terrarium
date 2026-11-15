package logprefix

import (
	"strconv"
	"strings"
)

// Kind identifies the decision a `log prefix` payload describes.
type Kind uint8

// Kind values.
const (
	// KindAllow tags an accepted packet. Its rule index names an
	// entry of the egress list of the policy.
	KindAllow Kind = iota

	// KindDeny tags a packet that the policy dropped. Its rule index
	// names an entry of the egressDeny list of the policy. A payload
	// without an index tags a packet that no egress rule allows.
	KindDeny

	// KindLeak tags a packet caught by the postrouting leak
	// guard.
	KindLeak
)

const (
	tagAllow = "TERRARIUM_ALLOW:"
	tagDeny  = "TERRARIUM_DENY:"
	tagLeak  = "TERRARIUM_LEAK:"

	// The allow segment precedes an index into the egress list.
	allowRulePrefix = "rule="
	// The deny segment precedes an index into the egressDeny list.
	denyRulePrefix = "deny-rule="
)

// Encode returns the nftables `log prefix` payload for a decision.
//
// A [KindAllow] payload names the rule at ruleIdx of the egress list
// as `rule=<idx>`. A [KindDeny] payload names the rule at ruleIdx of
// the egressDeny list as `deny-rule=<idx>`, so a reader cannot take
// one index for the other. A negative ruleIdx omits the segment.
// [KindLeak] always omits it, because the leak guard fires outside
// any per-rule chain.
//
// The output always ends with a single trailing space so syslog
// readers see space-delimited tokens. The kernel truncates
// `log prefix` at 64 bytes. The longest payload is the deny tag plus
// `deny-rule=<math.MaxInt64>` plus the trailing space, which is 45
// bytes.
func Encode(k Kind, ruleIdx int) string {
	var b strings.Builder

	b.Grow(48)

	var rulePrefix string

	switch k {
	case KindAllow:
		b.WriteString(tagAllow)

		rulePrefix = allowRulePrefix

	case KindDeny:
		b.WriteString(tagDeny)

		rulePrefix = denyRulePrefix

	case KindLeak:
		b.WriteString(tagLeak)
		b.WriteByte(' ')

		return b.String()
	}

	if ruleIdx >= 0 {
		b.WriteString(rulePrefix)
		b.WriteString(strconv.Itoa(ruleIdx))
	}

	b.WriteByte(' ')

	return b.String()
}

// Decode parses a `log prefix` payload back into [Kind] and a
// rule index. The index of a [KindAllow] payload names an entry of
// the egress list, and the index of a [KindDeny] payload names an
// entry of the egressDeny list. Returns rule index = -1 when the
// prefix names no rule ([KindLeak] or a catch-all). Returns
// ok = false on unknown kind tag, malformed rule segment, a rule
// segment of another kind, or any other non-conforming input. Strict
// parsing keeps an nflog reader's parse-error counter meaningful.
func Decode(s string) (Kind, int, bool) {
	if !strings.HasSuffix(s, " ") {
		return 0, 0, false
	}

	body := s[:len(s)-1]

	var (
		kind       Kind
		rest       string
		rulePrefix string
	)

	switch {
	case strings.HasPrefix(body, tagAllow):
		kind = KindAllow
		rest = body[len(tagAllow):]
		rulePrefix = allowRulePrefix

	case strings.HasPrefix(body, tagDeny):
		kind = KindDeny
		rest = body[len(tagDeny):]
		rulePrefix = denyRulePrefix

	case strings.HasPrefix(body, tagLeak):
		kind = KindLeak
		rest = body[len(tagLeak):]

	default:
		return 0, 0, false
	}

	if rest == "" {
		return kind, -1, true
	}

	if kind == KindLeak {
		return 0, 0, false
	}

	if !strings.HasPrefix(rest, rulePrefix) {
		return 0, 0, false
	}

	digits := rest[len(rulePrefix):]
	if digits == "" {
		return 0, 0, false
	}

	for _, r := range digits {
		if r < '0' || r > '9' {
			return 0, 0, false
		}
	}

	idx, err := strconv.Atoi(digits)
	if err != nil {
		return 0, 0, false
	}

	return kind, idx, true
}
