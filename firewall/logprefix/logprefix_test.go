package logprefix_test

import (
	"math"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/firewall/logprefix"
)

func TestEncode(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		kind logprefix.Kind
		idx  int
		want string
	}{
		"allow with no rule": {
			kind: logprefix.KindAllow, idx: -1,
			want: "TERRARIUM_ALLOW: ",
		},
		"allow with rule index": {
			kind: logprefix.KindAllow, idx: 3,
			want: "TERRARIUM_ALLOW:rule=3 ",
		},
		"deny with no rule": {
			kind: logprefix.KindDeny, idx: -1,
			want: "TERRARIUM_DENY: ",
		},
		"deny with the index of an egressDeny rule": {
			kind: logprefix.KindDeny, idx: 3,
			want: "TERRARIUM_DENY:deny-rule=3 ",
		},
		"leak ignores rule index when negative": {
			kind: logprefix.KindLeak, idx: -1,
			want: "TERRARIUM_LEAK: ",
		},
		"leak always omits rule even when index is set": {
			kind: logprefix.KindLeak, idx: 7,
			want: "TERRARIUM_LEAK: ",
		},
		"negative rule index other than -1 omits segment": {
			kind: logprefix.KindAllow, idx: -42,
			want: "TERRARIUM_ALLOW: ",
		},
		"zero rule index is encoded": {
			kind: logprefix.KindAllow, idx: 0,
			want: "TERRARIUM_ALLOW:rule=0 ",
		},
		"zero egressDeny index is encoded": {
			kind: logprefix.KindDeny, idx: 0,
			want: "TERRARIUM_DENY:deny-rule=0 ",
		},
		"negative egressDeny index omits segment": {
			kind: logprefix.KindDeny, idx: -42,
			want: "TERRARIUM_DENY: ",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, logprefix.Encode(tc.kind, tc.idx))
		})
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		kind    logprefix.Kind
		idx     int
		wantIdx int
	}{
		"allow no rule":   {logprefix.KindAllow, -1, -1},
		"allow with rule": {logprefix.KindAllow, 3, 3},
		"deny no rule":    {logprefix.KindDeny, -1, -1},
		"deny with rule":  {logprefix.KindDeny, 3, 3},
		"deny zero rule":  {logprefix.KindDeny, 0, 0},
		"leak no rule":    {logprefix.KindLeak, -1, -1},
		"leak ignores":    {logprefix.KindLeak, 7, -1},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			s := logprefix.Encode(tc.kind, tc.idx)

			gotKind, gotIdx, ok := logprefix.Decode(s)
			require.True(t, ok)
			assert.Equal(t, tc.kind, gotKind)
			assert.Equal(t, tc.wantIdx, gotIdx)
		})
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"unknown tag":                  "FOO_BAR: ",
		"non-decimal rule":             "TERRARIUM_ALLOW:rule=abc ",
		"missing trailing space":       "TERRARIUM_ALLOW:rule=3",
		"double trailing space":        "TERRARIUM_ALLOW:rule=3  ",
		"lowercase tag":                "terrarium_allow:rule=3 ",
		"leading whitespace":           " TERRARIUM_ALLOW:rule=3 ",
		"negative rule literal":        "TERRARIUM_ALLOW:rule=-1 ",
		"empty string":                 "",
		"only space":                   " ",
		"missing colon":                "TERRARIUM_DENY ",
		"missing rule= segment":        "TERRARIUM_ALLOW:3 ",
		"empty rule digits":            "TERRARIUM_ALLOW:rule= ",
		"trailing junk after idx":      "TERRARIUM_ALLOW:rule=3x ",
		"leak with rule segment":       "TERRARIUM_LEAK:rule=3 ",
		"leak with deny-rule segment":  "TERRARIUM_LEAK:deny-rule=3 ",
		"leak with random suffix":      "TERRARIUM_LEAK:foo ",
		"hex rule digits":              "TERRARIUM_ALLOW:rule=0x10 ",
		"rule with leading plus":       "TERRARIUM_ALLOW:rule=+3 ",
		"rule with internal space":     "TERRARIUM_ALLOW:rule= 3 ",
		"deny with an egress index":    "TERRARIUM_DENY:rule=3 ",
		"allow with an egressDeny idx": "TERRARIUM_ALLOW:deny-rule=3 ",
		"non-decimal deny rule":        "TERRARIUM_DENY:deny-rule=abc ",
		"negative deny rule literal":   "TERRARIUM_DENY:deny-rule=-1 ",
		"missing deny-rule= segment":   "TERRARIUM_DENY:3 ",
		"empty deny rule digits":       "TERRARIUM_DENY:deny-rule= ",
		"junk after deny rule idx":     "TERRARIUM_DENY:deny-rule=3x ",
		"deny rule without trailer":    "TERRARIUM_DENY:deny-rule=3",
	}

	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, _, ok := logprefix.Decode(in)
			assert.False(t, ok, "expected Decode(%q) to fail", in)
		})
	}
}

func TestEncodeBelow64Bytes(t *testing.T) {
	t.Parallel()

	for _, k := range []logprefix.Kind{logprefix.KindAllow, logprefix.KindDeny, logprefix.KindLeak} {
		s := logprefix.Encode(k, math.MaxInt64)
		assert.Less(t, len(s), 64,
			"prefix %q (kind=%d, max int64 rule) must fit in 64-byte nftables cap", s, k)
	}

	// Sanity: the explicit MaxInt64 encoding is what we expect.
	assert.Equal(t,
		"TERRARIUM_ALLOW:rule="+strconv.Itoa(math.MaxInt64)+" ",
		logprefix.Encode(logprefix.KindAllow, math.MaxInt64),
	)
	assert.Equal(t,
		"TERRARIUM_DENY:deny-rule="+strconv.Itoa(math.MaxInt64)+" ",
		logprefix.Encode(logprefix.KindDeny, math.MaxInt64),
	)
}
