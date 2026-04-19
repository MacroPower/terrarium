package status

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProcStarttime(t *testing.T) {
	t.Parallel()

	// Build a /proc/<pid>/stat line. Fields after (comm): state,
	// ppid, pgrp, session, tty_nr, tpgid, flags, minflt, cminflt,
	// majflt, cmajflt, utime, stime, cutime, cstime, priority,
	// nice, num_threads, itrealvalue, starttime, ...
	// That's 19 fields before starttime (field 22 overall, index 19
	// in the post-')' tail).
	build := func(comm string, starttime string) string {
		tail := []string{
			"S",  // state
			"1",  // ppid
			"1",  // pgrp
			"1",  // session
			"0",  // tty_nr
			"-1", // tpgid
			"0",  // flags
			"0",  // minflt
			"0",  // cminflt
			"0",  // majflt
			"0",  // cmajflt
			"0",  // utime
			"0",  // stime
			"0",  // cutime
			"0",  // cstime
			"20", // priority
			"0",  // nice
			"1",  // num_threads
			"0",  // itrealvalue
			starttime,
		}

		return "1234 (" + comm + ") " + strings.Join(tail, " ") + "\n"
	}

	cases := map[string]struct {
		line string
		want uint64
		err  bool
	}{
		"plain comm": {
			line: build("bash", "12345"),
			want: 12345,
		},
		"comm with space": {
			line: build("my program", "42"),
			want: 42,
		},
		"comm with parens": {
			line: build("prog (debug)", "999"),
			want: 999,
		},
		"comm with embedded space paren": {
			line: build("weird (name) more", "7"),
			want: 7,
		},
		"kernel thread brackets": {
			line: build("[kworker/u8:1]", "100"),
			want: 100,
		},
		"truncated": {
			line: "1 (bash) S 1 1\n",
			err:  true,
		},
		"no close paren": {
			line: "1 bash S 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 100\n",
			err:  true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := parseProcStarttime(tc.line)
			if tc.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestSplitTailLines(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		in   string
		want []string
	}{
		"terminated": {
			in:   "a\nb\n",
			want: []string{"a", "b"},
		},
		"unterminated": {
			in:   "a\nb",
			want: []string{"a", "b"},
		},
		"crlf": {
			in:   "a\r\nb\r\n",
			want: []string{"a", "b"},
		},
		"empty": {
			in:   "",
			want: []string{},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got := splitTailLines([]byte(tc.in))
			if len(tc.want) == 0 {
				assert.Empty(t, got)
				return
			}

			assert.Equal(t, tc.want, got)
		})
	}
}
