//go:build !linux

package main

import (
	"github.com/spf13/cobra"

	"go.jacobcolvin.com/terrarium/config"
)

// platformDispatch intercepts the hidden envoy-guard entrypoint before
// cobra parsing. The proxy starts that entrypoint as the guard process
// of its Envoy, see [envoyGuard]. The jail and exec re-exec entrypoints
// exist only for the Linux data plane (AppArmor confinement and
// capability-aware privilege drops).
func platformDispatch(args []string) {
	if len(args) > 1 && args[1] == envoyGuardCommand {
		envoyGuardMain()
	}
}

// platformCommands returns no extra commands outside Linux. The init,
// daemon, and status commands require the nftables/TPROXY data plane.
func platformCommands(_ *config.User) []*cobra.Command {
	return nil
}
