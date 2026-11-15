package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/spf13/cobra"
	"go.jacobcolvin.com/x/version"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/mcpserver"
)

// mcpCmd builds the `terrarium mcp` subcommand, which serves the
// read-only tools of [mcpserver] to a Model Context Protocol (MCP)
// client on its standard input and output.
func mcpCmd(usr *config.User) *cobra.Command {
	var dbPath string

	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve read-only stats tools to an MCP client over stdio",
		Long: "Serve read-only stats tools to an MCP client over stdio.\n\n" +
			"A Model Context Protocol (MCP) client, such as a coding agent, " +
			"starts this command and calls its tools to read the egress " +
			"events, the policy snapshots, and the health counters that " +
			"terrarium records in the stats database. No tool writes to " +
			"the database.\n\n" +
			"The command reads the database that `terrarium stats` reads. " +
			"Terrarium writes that database only when the config sets " +
			"`stats.enabled: true`, so pass the --config value of the " +
			"terrarium process whose events you want to read.\n\n" +
			"The standard output carries only the protocol. The logs go to " +
			"the standard error.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMCP(cmd.Context(), usr, dbPath, cmd.InOrStdin(), cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "",
		"path to stats db (default: $XDG_DATA_HOME/terrarium/stats.db)")

	return cmd
}

// runMCP serves one MCP session on in and out. It returns nil when
// the client closes in, and when ctx ends.
func runMCP(ctx context.Context, usr *config.User, dbPath string, in io.Reader, out io.Writer) error {
	srv := mcpserver.New(locateStatsDB(usr, dbPath),
		mcpserver.WithVersion(version.GetVersion()),
		mcpserver.WithLogger(slog.Default()),
	)

	err := srv.RunIO(ctx, in, out)
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("running the MCP server: %w", err)
	}

	return nil
}

// locateStatsDB returns the function that finds the stats database
// for each tool call of `terrarium mcp`. The function resolves the
// path as [resolveStatsDB] does, so the tools read the database that
// `terrarium stats` reads. It reads the config file at each call, so
// a change to the config takes effect without a restart of the
// server.
//
// The function returns [mcpserver.ErrNoDatabase] when the config file
// does not enable stats, because no terrarium process with that
// config writes the database. An explicit --db value names a database
// to read whatever the config holds.
func locateStatsDB(usr *config.User, override string) mcpserver.LocateFunc {
	return func(ctx context.Context) (string, error) {
		db, err := resolveStatsDB(ctx, usr, override)
		if err != nil {
			return "", fmt.Errorf("finding the stats database: %w", err)
		}

		if db.disabled {
			return "", fmt.Errorf(
				"%w: the config %s does not enable stats, so terrarium records no events in %s. "+
					"Set `stats.enabled: true` in that config, start terrarium again, "+
					"then call the tool again",
				mcpserver.ErrNoDatabase, usr.ConfigPath, db.path)
		}

		return db.path, nil
	}
}
