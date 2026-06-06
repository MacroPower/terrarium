//go:build !linux

package main

import (
	"github.com/spf13/cobra"

	"go.jacobcolvin.com/terrarium/config"
)

// platformDispatch is a no-op outside Linux. The jail and exec
// re-exec entrypoints exist only for the Linux data plane (AppArmor
// confinement and capability-aware privilege drops).
func platformDispatch(_ []string) {}

// platformCommands returns no extra commands outside Linux. The init,
// daemon, and status commands require the nftables/TPROXY data plane.
func platformCommands(_ *config.User) []*cobra.Command {
	return nil
}
