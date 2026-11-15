package main

import (
	"bytes"
	"io"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
)

// userFlagsOf returns the sorted names of the [config.User] flags that
// a command accepts, including the flags that it inherits from its
// parents. The command argument holds the full command path, such as
// "terrarium stats list". The result omits the flags that the command
// defines outside [config.User].
func userFlagsOf(t *testing.T, command string) []string {
	t.Helper()

	root := newRootCmd()

	cmd, _, err := root.Find(strings.Fields(command)[1:])
	require.NoError(t, err)
	require.Equal(t, command, cmd.CommandPath())

	all := pflag.NewFlagSet("all", pflag.ContinueOnError)
	config.NewUser().RegisterFlags(all)

	var got []string

	collect := func(f *pflag.Flag) {
		if all.Lookup(f.Name) != nil {
			got = append(got, f.Name)
		}
	}

	cmd.LocalFlags().VisitAll(collect)
	cmd.InheritedFlags().VisitAll(collect)

	slices.Sort(got)

	return got
}

// TestCommandUserFlags names each test case after the command path
// that it inspects.
func TestCommandUserFlags(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		want []string
	}{
		"terrarium generate": {
			want: []string{"ca-dir", "certs-dir", "config", "envoy-config"},
		},
		"terrarium envoy": {
			want: []string{"config"},
		},
		"terrarium envoy install": {
			want: []string{"config"},
		},
		"terrarium proxy": {
			want: []string{
				"ca-dir", "certs-dir", "config", "envoy-config", "envoy-log", "ready-file",
			},
		},
		"terrarium stats": {
			want: []string{"config"},
		},
		"terrarium stats top": {
			want: []string{"config"},
		},
		"terrarium stats list": {
			want: []string{"config"},
		},
	}

	for command, tt := range tests {
		t.Run(command, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, userFlagsOf(t, command))
		})
	}
}

func TestCommandSharedFlags(t *testing.T) {
	t.Parallel()

	var walk func(cmd *cobra.Command)

	walk = func(cmd *cobra.Command) {
		for _, name := range []string{"config", "log-level", "log-format"} {
			found := cmd.LocalFlags().Lookup(name) != nil ||
				cmd.InheritedFlags().Lookup(name) != nil
			assert.True(t, found, "%s lacks --%s", cmd.CommandPath(), name)
		}

		for _, sub := range cmd.Commands() {
			walk(sub)
		}
	}

	walk(newRootCmd())
}

// TestCommandAcceptsFlagBeforeName names each test case after the
// command line that it runs. Cobra parses every flag with the flag set
// of the command that runs. A flag that the root command does not
// register can therefore precede the command name.
func TestCommandAcceptsFlagBeforeName(t *testing.T) {
	t.Parallel()

	tests := map[string]struct{}{
		"--ready-file=/ready proxy --help":         {},
		"--ready-file /ready proxy --help":         {},
		"--envoy-config=/envoy.yaml proxy --help":  {},
		"--envoy-path=/envoy proxy --help":         {},
		"--ca-dir=/ca generate --help":             {},
		"--ca-dir /ca --config=/c generate --help": {},
	}

	for line := range tests {
		t.Run(line, func(t *testing.T) {
			t.Parallel()

			// The --help flag stops the command after cobra parses the
			// flags, so the command body does not run.
			root := newRootCmd()
			root.SetArgs(strings.Fields(line))
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)

			require.NoError(t, root.ExecuteContext(t.Context()))
		})
	}
}

// TestCommandRejectsUnreadFlags names each test case after the command
// line that it runs. Every command line ends with --help, so that a
// command that accepts the flag prints its help and returns before its
// body runs. The body of the proxy command writes the CA under the
// data directory of the user and serves until a signal arrives.
func TestCommandRejectsUnreadFlags(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err string
	}{
		"proxy --uid=1000 --help":                  {err: "unknown flag: --uid"},
		"proxy --gid=1000 --help":                  {err: "unknown flag: --gid"},
		"proxy --envoy-uid=1001 --help":            {err: "unknown flag: --envoy-uid"},
		"proxy --exclude-dns-uids=53 --help":       {err: "unknown flag: --exclude-dns-uids"},
		"--uid=1000 proxy --help":                  {err: "unknown flag: --uid"},
		"stats --uid=1000 --help":                  {err: "unknown flag: --uid"},
		"stats --ca-dir=/ca --help":                {err: "unknown flag: --ca-dir"},
		"stats --certs-dir=/certs --help":          {err: "unknown flag: --certs-dir"},
		"stats --envoy-config=/envoy.yaml --help":  {err: "unknown flag: --envoy-config"},
		"stats --ready-file=/ready --help":         {err: "unknown flag: --ready-file"},
		"stats top --envoy-uid=1001 --help":        {err: "unknown flag: --envoy-uid"},
		"stats list --envoy-log=/envoy.log --help": {err: "unknown flag: --envoy-log"},
		"envoy --ca-dir=/ca --help":                {err: "unknown flag: --ca-dir"},
		"envoy install --ca-dir=/ca --help":        {err: "unknown flag: --ca-dir"},
		"envoy install --uid=1000 --help":          {err: "unknown flag: --uid"},
		"envoy install --envoy-path=/envoy --help": {err: "unknown flag: --envoy-path"},
		"generate --envoy-path=/envoy --help":      {err: "unknown flag: --envoy-path"},
	}

	for line, tt := range tests {
		t.Run(line, func(t *testing.T) {
			t.Parallel()

			// Cobra reports the unknown flag before it acts on --help.
			// Discard the usage text that cobra prints for a flag error.
			root := newRootCmd()
			root.SetArgs(strings.Fields(line))
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)

			err := root.ExecuteContext(t.Context())
			require.ErrorContains(t, err, tt.err)
		})
	}
}

// ansiStyle matches the escape sequences that set the color and the
// style of terminal text.
var ansiStyle = regexp.MustCompile(`\x1b\[[0-9;:]*m`)

// helpText returns the first line of a flag description or a command
// description with a capital first letter. The help prints that text
// for a description that starts with a word in lowercase.
func helpText(description string) string {
	line, _, _ := strings.Cut(description, "\n")

	first, size := utf8.DecodeRuneInString(line)
	if size == 0 {
		return line
	}

	return string(unicode.ToUpper(first)) + line[size:]
}

// TestHelpKeepsDescriptions names each test case after the command
// path whose help it renders. Fang renders the first word of each flag
// description and of each command description in title case. Title
// case lowercases every letter of the word after the first letter. A
// description that starts with an acronym, such as DNS, therefore
// loses the capitals of the acronym. Each test case fails when the
// help of its command changes more of a description than the case of
// the first letter.
func TestHelpKeepsDescriptions(t *testing.T) {
	t.Parallel()

	var (
		paths []string
		walk  func(cmd *cobra.Command)
	)

	walk = func(cmd *cobra.Command) {
		paths = append(paths, cmd.CommandPath())

		for _, sub := range cmd.Commands() {
			walk(sub)
		}
	}

	walk(newRootCmd())

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			var stdout bytes.Buffer

			args := strings.Fields(path)[1:]

			root := newRootCmd()
			root.SetArgs(append(slices.Clone(args), "--help"))
			root.SetOut(&stdout)
			root.SetErr(io.Discard)

			require.Equal(t, 0, run(t.Context(), root))

			cmd, _, err := root.Find(args)
			require.NoError(t, err)
			require.Equal(t, path, cmd.CommandPath())

			help := ansiStyle.ReplaceAllString(stdout.String(), "")

			const hint = "the help changed the description of %s, " +
				"so start the description with a word that has no capital after its first letter"

			cmd.Flags().VisitAll(func(f *pflag.Flag) {
				if f.Hidden {
					return
				}

				assert.Contains(t, help, helpText(f.Usage), hint, "--"+f.Name)
			})

			for _, sub := range cmd.Commands() {
				if sub.Hidden {
					continue
				}

				assert.Contains(t, help, helpText(sub.Short), hint, sub.CommandPath())
			}
		})
	}
}
