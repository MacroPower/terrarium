package main

import (
	"github.com/spf13/cobra"

	"go.jacobcolvin.com/terrarium/config"
)

// platformDispatch intercepts the hidden jail and exec entrypoints
// before cobra parsing. Both re-exec paths perform privilege
// transitions that must run on a single locked OS thread, so they
// bypass the normal command tree. Linux-only: jail enters an AppArmor
// profile and exec drops privileges via capset/setresuid.
func platformDispatch(args []string) {
	if len(args) > 1 && args[1] == "jail" {
		jailChangeProfile(args[2:])
	}

	if len(args) > 1 && args[1] == "exec" {
		execPrivDrop(args[2:])
	}
}

// platformCommands returns the Linux-only commands: init and daemon
// drive the nftables/TPROXY data plane, and status introspects the
// running daemon.
func platformCommands(usr *config.User) []*cobra.Command {
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
		config.DefaultPIDFile, "path to PID file")

	// The daemon does not start a user command, so it does not register
	// --gid, which names the group of that command. The daemon reads
	// --uid to set the owner of the event store. These flags are local
	// to the daemon command, so `daemon reload` inherits only --pid-file
	// from it.
	usr.RegisterFlags(daemonCmd.Flags(),
		usr.Flags.UID,
		usr.Flags.EnvoyUID,
		usr.Flags.ExcludeDNSUIDs,
		usr.Flags.CADir,
		usr.Flags.CertsDir,
		usr.Flags.EnvoyConfigPath,
		usr.Flags.EnvoyLogPath,
		usr.Flags.ReadyFile,
	)

	daemonCmd.AddCommand(&cobra.Command{
		Use:   "reload",
		Short: "Validate config and signal the daemon to reload",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return DaemonReload(cmd.Context(), usr, pidFile)
		},
	})

	initCmd := &cobra.Command{
		Use:   "init [-- cmd...]",
		Short: "Load firewall, start services, drop privileges, exec cmd",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return Init(cmd.Context(), usr, args)
		},
	}

	usr.RegisterFlags(initCmd.Flags(),
		usr.Flags.UID,
		usr.Flags.GID,
		usr.Flags.EnvoyUID,
		usr.Flags.ExcludeDNSUIDs,
		usr.Flags.CADir,
		usr.Flags.CertsDir,
		usr.Flags.EnvoyConfigPath,
		usr.Flags.EnvoyLogPath,
		usr.Flags.ReadyFile,
	)

	return []*cobra.Command{initCmd, daemonCmd, statusCmd(usr)}
}
