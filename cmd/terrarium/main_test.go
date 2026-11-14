package main

import (
	"io"
	"slices"
	"strings"
	"testing"

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
