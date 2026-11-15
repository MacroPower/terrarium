package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/eventstore"
	"go.jacobcolvin.com/terrarium/mcpserver"
)

// mcpSession runs `terrarium mcp` on a pair of pipes and connects an
// MCP client to it. The command reads the config file at cfgPath and
// takes flags as its own flags. The command runs until the test ends.
// The cleanup closes the session of the client, which closes the
// standard input of the command, and requires the exit code 0.
func mcpSession(t *testing.T, cfgPath string, flags ...string) *mcp.ClientSession {
	t.Helper()

	args := append([]string{"--config", cfgPath, "mcp"}, flags...)

	stdin, clientOut := io.Pipe()
	clientIn, stdout := io.Pipe()

	root := newRootCmd()
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(io.Discard)

	ctx := context.WithoutCancel(t.Context())
	code := make(chan int, 1)

	go func() {
		code <- run(ctx, root)

		// A command that ends before the client connects leaves the
		// client with a read that never returns. The end of the
		// output stream ends that read.
		_ = stdout.Close() //nolint:errcheck // The pipe returns no error.
	}()

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)

	session, err := client.Connect(ctx, &mcp.IOTransport{Reader: clientIn, Writer: clientOut}, nil)
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, session.Close())

		select {
		case got := <-code:
			assert.Equal(t, 0, got)
		case <-time.After(10 * time.Second):
			assert.Fail(t, "the command still runs after the client closed its input")
		}
	})

	return session
}

// toolText returns the text content of a tool result.
func toolText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()

	require.Len(t, res.Content, 1)

	content, ok := res.Content[0].(*mcp.TextContent)
	require.True(t, ok, "content is %T", res.Content[0])

	return content.Text
}

// writeStatsConfig writes a config file that holds the stats section
// and returns its path. An empty section writes a config without one.
func writeStatsConfig(t *testing.T, path, section string) {
	t.Helper()

	require.NoError(t, os.WriteFile(path, []byte("egress: []\n"+section), 0o644))
}

func TestMCPServesStatsDB(t *testing.T) {
	t.Parallel()

	now := time.Now()

	dbPath := seedDB(t, []eventstore.Event{
		{
			Time:     now.Add(-time.Minute),
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionDeny,
			Domain:   "evil.example",
			Reason:   eventstore.ReasonBlockedMode,
		},
		{
			Time:     now.Add(-time.Minute),
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionAllow,
			Domain:   "ok.example",
		},
	})

	tests := map[string]struct {
		// stats is the stats section of the config file.
		stats string

		// flags holds the flags of the command.
		flags []string
	}{
		"config names the database": {
			stats: "stats:\n  enabled: true\n  path: " + dbPath + "\n",
		},
		"db flag names the database": {
			flags: []string{"--db", dbPath},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfgPath := filepath.Join(t.TempDir(), "config.yaml")
			writeStatsConfig(t, cfgPath, tt.stats)

			session := mcpSession(t, cfgPath, tt.flags...)

			init := session.InitializeResult()
			require.NotNil(t, init.ServerInfo)
			assert.Equal(t, "terrarium", init.ServerInfo.Name)
			assert.NotEmpty(t, init.ServerInfo.Version)

			tools, err := session.ListTools(t.Context(), nil)
			require.NoError(t, err)

			var names []string

			for _, tool := range tools.Tools {
				names = append(names, tool.Name)
			}

			assert.ElementsMatch(t, []string{
				"list_instances", "summarize_events", "top_events", "list_events", "get_health",
			}, names)

			res, err := session.CallTool(t.Context(), &mcp.CallToolParams{
				Name:      "list_events",
				Arguments: map[string]any{"domain": "evil.example"},
			})
			require.NoError(t, err)
			require.False(t, res.IsError, toolText(t, res))

			var got mcpserver.EventsResult

			require.NoError(t, json.Unmarshal([]byte(toolText(t, res)), &got))
			require.Len(t, got.Events, 1)
			assert.Equal(t, "evil.example", got.Events[0].Domain)
			assert.NotEmpty(t, got.Instance)

			res, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "get_health"})
			require.NoError(t, err)
			require.False(t, res.IsError, toolText(t, res))

			var health mcpserver.HealthResult

			require.NoError(t, json.Unmarshal([]byte(toolText(t, res)), &health))
			assert.Equal(t, dbPath, health.DatabasePath)
			assert.Equal(t, got.Instance, health.Instance)
		})
	}
}

// TestMCPStatsDisabled starts the server with a config that does not
// enable stats, then enables stats while the session stays open.
func TestMCPStatsDisabled(t *testing.T) {
	t.Parallel()

	dbPath := seedDB(t, []eventstore.Event{
		{
			Time:     time.Now(),
			Source:   eventstore.SourceDNS,
			Decision: eventstore.DecisionDeny,
			Domain:   "evil.example",
			Reason:   eventstore.ReasonBlockedMode,
		},
	})

	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	writeStatsConfig(t, cfgPath, "stats:\n  enabled: false\n  path: "+dbPath+"\n")

	session := mcpSession(t, cfgPath)

	res, err := session.CallTool(t.Context(), &mcp.CallToolParams{Name: "summarize_events"})
	require.NoError(t, err)
	require.True(t, res.IsError)

	msg := toolText(t, res)
	assert.Contains(t, msg, cfgPath)
	assert.Contains(t, msg, dbPath)
	assert.Contains(t, msg, "stats.enabled: true")

	writeStatsConfig(t, cfgPath, "stats:\n  enabled: true\n  path: "+dbPath+"\n")

	res, err = session.CallTool(t.Context(), &mcp.CallToolParams{Name: "summarize_events"})
	require.NoError(t, err)
	require.False(t, res.IsError, toolText(t, res))

	var got mcpserver.SummaryResult

	require.NoError(t, json.Unmarshal([]byte(toolText(t, res)), &got))
	assert.Equal(t, int64(1), got.Total)
}

func TestLocateStatsDB(t *testing.T) {
	t.Parallel()

	const (
		fromFlag   = "/flag/stats.db"
		fromConfig = "/config/stats.db"
	)

	tests := map[string]struct {
		// config is the content of the config file. The test writes no
		// config file when it is nil.
		config *string

		// override is the value of the --db flag.
		override string

		// want is the path of the database.
		want string

		// disabled is the path that the error names when the config
		// does not enable stats.
		disabled string

		// err is a part of the message of any other error.
		err string
	}{
		"db flag": {
			config:   new("egress: []\nstats:\n  enabled: true\n  path: " + fromConfig + "\n"),
			override: fromFlag,
			want:     fromFlag,
		},
		"db flag with stats disabled": {
			config:   new("egress: []\n"),
			override: fromFlag,
			want:     fromFlag,
		},
		"db flag with a config that does not parse": {
			config:   new("stats: [\n"),
			override: fromFlag,
			want:     fromFlag,
		},
		"path of the config": {
			config: new("egress: []\nstats:\n  enabled: true\n  path: " + fromConfig + "\n"),
			want:   fromConfig,
		},
		"default path": {
			config: new("egress: []\nstats:\n  enabled: true\n"),
			want:   config.StatsDBDefault(),
		},
		"no config file": {
			want: config.StatsDBDefault(),
		},
		"stats disabled": {
			config:   new("egress: []\nstats:\n  enabled: false\n  path: " + fromConfig + "\n"),
			disabled: fromConfig,
		},
		"no stats section": {
			config:   new("egress: []\n"),
			disabled: config.StatsDBDefault(),
		},
		"config does not parse": {
			config: new("stats: [\n"),
			err:    "parsing config",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			usr := config.NewUser()
			usr.ConfigPath = filepath.Join(t.TempDir(), "config.yaml")

			if tt.config != nil {
				require.NoError(t, os.WriteFile(usr.ConfigPath, []byte(*tt.config), 0o644))
			}

			got, err := locateStatsDB(usr, tt.override)(t.Context())

			switch {
			case tt.disabled != "":
				require.ErrorIs(t, err, mcpserver.ErrNoDatabase)
				require.ErrorContains(t, err, usr.ConfigPath)
				require.ErrorContains(t, err, tt.disabled)
				require.ErrorContains(t, err, "stats.enabled: true")

			case tt.err != "":
				require.ErrorContains(t, err, tt.err)
				require.NotErrorIs(t, err, mcpserver.ErrNoDatabase)
				require.ErrorContains(t, err, usr.ConfigPath)

			default:
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// TestMCPEndsWithContext cancels the context of the command while its
// input stays open. A signal handler that cancels the context then
// ends the command without an error.
func TestMCPEndsWithContext(t *testing.T) {
	t.Parallel()

	stdin, clientOut := io.Pipe()

	t.Cleanup(func() {
		assert.NoError(t, clientOut.Close())
	})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() {
		done <- runMCP(ctx, config.NewUser(), "/missing/stats.db", stdin, io.Discard)
	}()

	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		require.Fail(t, "the command still runs after its context ended")
	}
}
