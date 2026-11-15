package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"go.jacobcolvin.com/terrarium/envoybin"
)

// envoyCmd builds the `terrarium envoy` command group, which manages
// the Envoy build that terrarium pins.
func envoyCmd(inst *envoybin.Installer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "envoy",
		Short: "Manage the pinned Envoy build",
		// Without Args, cobra accepts a mistyped subcommand name and
		// prints the help with exit status 0.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Install the pinned Envoy build for this host and print its path",
		Long: "Install the pinned Envoy build for this host and print its path.\n\n" +
			"The command downloads Envoy " + envoybin.Version + " into " +
			"$XDG_DATA_HOME/terrarium/envoy and checks the download against " +
			"SHA-256 hashes compiled into terrarium. Run it ahead of time on a " +
			"machine that starts the proxy offline.\n\n" +
			"When the binary is already installed, the command checks its hash " +
			"and prints its path without a download. The command does not " +
			"replace an installed binary that has a different hash. Inspect " +
			"that file, remove it, and run the command again.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// A signal cancels the install at any step, and the
			// installer then removes its temporary files.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			return installEnvoy(ctx, cmd.OutOrStdout(), inst)
		},
	})

	return cmd
}

// installEnvoy installs the pinned Envoy build and writes the path of
// the binary to w.
func installEnvoy(ctx context.Context, w io.Writer, inst *envoybin.Installer) error {
	path, err := inst.Install(ctx)
	if err != nil {
		return fmt.Errorf("install envoy: %w", err)
	}

	_, err = fmt.Fprintln(w, path)
	if err != nil {
		return fmt.Errorf("print envoy path: %w", err)
	}

	return nil
}
