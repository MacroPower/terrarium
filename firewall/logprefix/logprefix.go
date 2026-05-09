package logprefix

import (
	"strconv"
	"strings"
)

// Kind identifies the decision a `log prefix` payload describes.
type Kind uint8

// Kind values.
const (
	// KindAllow tags an accepted packet.
	KindAllow Kind = iota

	// KindDeny tags a packet dropped by an explicit policy
	// terminal. Replaces the legacy `TERRARIUM_DROP:` tag and
	// aligns with the SQLite `decision` enum.
	KindDeny

	// KindLeak tags a packet caught by the postrouting leak
	// guard. Replaces the legacy `TERRARIUM_EGRESS_LEAK:` tag.
	KindLeak
)

const (
	tagAllow = "TERRARIUM_ALLOW:"
	tagDeny  = "TERRARIUM_DENY:"
	tagLeak  = "TERRARIUM_LEAK:"

	rulePrefix = "rule="
)

// Encode returns the nftables `log prefix` payload for a decision.
//
// ruleIdx < 0 omits the `rule=` segment; [KindLeak] always omits
// it because the leak guard fires outside any per-rule chain. The
// output always ends with a single trailing space so syslog readers
// see space-delimited tokens. The kernel truncates `log prefix` at
// 64 bytes; the longest tag plus `rule=<math.MaxInt64>` plus the
// trailing space is 41 bytes, well under that cap.
func Encode(k Kind, ruleIdx int) string {
	var b strings.Builder
	b.Grow(32)

	switch k {
	case KindAllow:
		b.WriteString(tagAllow)
	case KindDeny:
		b.WriteString(tagDeny)
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
// rule index. Returns rule index = -1 when the prefix omits
// `rule=` ([KindLeak] or a catch-all). Returns ok = false on
// unknown kind tag, malformed `rule=` segment, or any other
// non-conforming input. Strict parsing keeps an nflog reader's
// parse-error counter meaningful.
func Decode(s string) (Kind, int, bool) {
	if !strings.HasSuffix(s, " ") {
		return 0, 0, false
	}

	body := s[:len(s)-1]

	var (
		kind Kind
		rest string
	)

	switch {
	case strings.HasPrefix(body, tagAllow):
		kind = KindAllow
		rest = body[len(tagAllow):]

	case strings.HasPrefix(body, tagDeny):
		kind = KindDeny
		rest = body[len(tagDeny):]

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
