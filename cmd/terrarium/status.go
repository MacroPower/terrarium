package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/status"
)

// statusCmd describes the `terrarium status` subcommand. Building it
// here rather than inline in main.go keeps the --pid-file flag
// registration and the --log-lines / --no-logs / --probe-dns
// registrations co-located with the RunE handler.
func statusCmd(usr *config.User) *cobra.Command {
	opts := status.Options{
		LogLines: 20,
	}

	var pidFile string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Report terrarium daemon health",
		Long: "Print a snapshot of the running terrarium daemon: " +
			"process liveness, firewall state, DNS proxy, Envoy listeners, and recent logs. " +
			"Status reads from the same path flags the running daemon was started with; " +
			"override --pid-file, --envoy-config, --envoy-log, or --envoy-access-log here " +
			"if the daemon used non-defaults. " +
			"Exit status 0 when the daemon is running, 3 when it is not.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStatus(cmd.Context(), cmd, usr, pidFile, opts)
		},
	}

	cmd.PersistentFlags().StringVar(&pidFile, "pid-file",
		config.DefaultPIDFile,
		"path to the daemon PID file (must match what the daemon was started with)")
	cmd.Flags().IntVar(&opts.LogLines, "log-lines", opts.LogLines,
		"number of lines to tail from each envoy log")
	cmd.Flags().BoolVar(&opts.NoLogs, "no-logs", false,
		"skip envoy log tailing entirely")
	cmd.Flags().BoolVar(&opts.ProbeDNS, "probe-dns", false,
		"actively probe the local DNS proxy (pollutes the access log)")

	return cmd
}

// runStatus is the RunE body for [statusCmd]. Extracted so the cobra
// wiring stays focused on flag definitions.
func runStatus(ctx context.Context, cmd *cobra.Command, usr *config.User, pidFile string, opts status.Options) error {
	opts.PIDFile = pidFile
	opts.ConfigPath = usr.ConfigPath
	opts.EnvoyConfigPath = usr.EnvoyConfigPath
	opts.EnvoyLogPath = usr.EnvoyLogPath
	opts.EnvoyAccessLogPath = usr.EnvoyAccessLogPath

	report := status.Collect(ctx, opts)

	err := status.Render(cmd.OutOrStdout(), report)
	if err != nil {
		return fmt.Errorf("rendering status: %w", err)
	}

	if report.Process.Daemon.State != status.DaemonRunning {
		return &ExitError{Code: 3}
	}

	return nil
}
