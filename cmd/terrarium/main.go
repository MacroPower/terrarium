// Terrarium manages egress network policy for containers and VMs.
// It generates nftables firewall rules and Envoy proxy configs from
// Cilium-compatible YAML policy, and can run as either a per-container
// init wrapper or a VM-wide daemon.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"

	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"
	"go.jacobcolvin.com/niceyaml/fangs"
	"go.jacobcolvin.com/x/log"
	"go.jacobcolvin.com/x/version"

	"go.jacobcolvin.com/terrarium/config"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "exec" {
		execPrivDrop(os.Args[2:])
	}

	usr := config.NewUser()
	logCfg := log.NewConfig()

	rootCmd := &cobra.Command{
		Use:   "terrarium",
		Short: "Terrarium container operations",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			handler, err := logCfg.NewHandler(os.Stderr)
			if err != nil {
				return err
			}

			slog.SetDefault(slog.New(handler))

			return nil
		},
	}

	usr.RegisterFlags(rootCmd.PersistentFlags())
	logCfg.RegisterFlags(rootCmd.PersistentFlags())

	err := usr.RegisterCompletions(rootCmd)
	if err != nil {
		slog.Error("registering completions",
			slog.Any("err", err),
		)
	}

	err = logCfg.RegisterCompletions(rootCmd)
	if err != nil {
		slog.Error("registering completions",
			slog.Any("err", err),
		)
	}

	var pidFile string

	daemonCmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run as a VM-wide network filter daemon",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return Daemon(cmd.Context(), usr, pidFile)
		},
	}

	daemonCmd.PersistentFlags().StringVar(&pidFile, "pid-file",
		"/run/terrarium/terrarium.pid", "path to PID file")

	daemonCmd.AddCommand(&cobra.Command{
		Use:   "reload",
		Short: "Validate config and signal the daemon to reload",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return DaemonReload(cmd.Context(), usr, pidFile)
		},
	})

	rootCmd.AddCommand(
		&cobra.Command{
			Use:   "generate",
			Short: "Generate nftables/envoy configs from YAML",
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				_, err := Generate(cmd.Context(), usr, false)
				return err
			},
		},
		&cobra.Command{
			Use:   "init [-- cmd...]",
			Short: "Load firewall, start services, drop privileges, exec cmd",
			Args:  cobra.ArbitraryArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				return Init(cmd.Context(), usr, args)
			},
		},
		daemonCmd,
	)

	err = fang.Execute(context.Background(), rootCmd,
		fang.WithErrorHandler(fangs.ErrorHandler),
		fang.WithoutCompletions(),
		fang.WithoutManpage(),
		fang.WithVersion(version.GetVersion()),
	)
	if err != nil {
		var exitErr *ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}

		os.Exit(1)
	}
}
