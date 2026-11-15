// Terrarium manages egress network policy for containers and VMs.
// It generates nftables firewall rules and Envoy proxy configs from
// Cilium-compatible YAML policy, and can run as either a per-container
// init wrapper or a VM-wide daemon.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"
	"go.jacobcolvin.com/x/log"
	"go.jacobcolvin.com/x/version"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/envoybin"
)

func main() {
	platformDispatch(os.Args)

	os.Exit(run(context.Background(), newRootCmd()))
}

// run executes root and returns the exit code of terrarium. It prints
// the error of the command to the error output of root, except for an
// [*ExitError], whose code it returns without output.
func run(ctx context.Context, root *cobra.Command) int {
	err := fang.Execute(ctx, root,
		fang.WithErrorHandler(errorHandler),
		fang.WithoutCompletions(),
		fang.WithoutManpage(),
		fang.WithVersion(version.GetVersion()),
	)

	return exitCode(err)
}

// newRootCmd builds the terrarium command tree. The root command holds
// the flags that every command accepts: --config and the logging flags.
// The envoy commands accept --config and do not read it, because they
// load no policy. Each subcommand registers the other [config.User]
// flags that it accepts, so the help of a command lists only those
// flags.
func newRootCmd() *cobra.Command {
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

	usr.RegisterFlags(rootCmd.PersistentFlags(), usr.Flags.ConfigPath)
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

	// The envoy commands install the build that the proxy runs.
	envoyInst := envoybin.NewInstaller(config.EnvoyDirDefault())

	rootCmd.AddCommand(
		generateCmd(usr),
		envoyCmd(envoyInst),
		proxyCmd(usr, envoyInst),
		statsCmd(usr),
	)

	rootCmd.AddCommand(platformCommands(usr)...)

	return rootCmd
}

// generateCmd builds the `terrarium generate` subcommand, which writes
// the MITM certificates and the Envoy bootstrap for a policy.
func generateCmd(usr *config.User) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate nftables/envoy configs from YAML",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := Generate(cmd.Context(), usr, false)
			return err
		},
	}

	usr.RegisterFlags(cmd.Flags(),
		usr.Flags.CADir,
		usr.Flags.CertsDir,
		usr.Flags.EnvoyConfigPath,
	)

	return cmd
}
