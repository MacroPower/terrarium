package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/pflag"

	"go.jacobcolvin.com/terrarium/jail"
)

// jailChangeProfile is the hidden "jail" subcommand entrypoint.
// It is dispatched from [main] before cobra setup so the
// per-thread AppArmor transition is not migrated across OS
// threads by the Go runtime.
//
// This function does not return on success (it calls execve).
func jailChangeProfile(args []string) {
	runtime.LockOSThread()

	fs := pflag.NewFlagSet("terrarium jail", pflag.ContinueOnError)

	var profile string

	fs.StringVar(&profile, "profile", "terrarium.workload",
		"AppArmor profile to transition into before exec")

	err := fs.Parse(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "terrarium jail: %v\n", err)
		os.Exit(1)
	}

	argv := fs.Args()
	if len(argv) == 0 {
		fmt.Fprintf(os.Stderr, "terrarium jail: no command specified\n")
		os.Exit(1)
	}

	err = jail.Exec(jail.Options{Profile: profile}, argv)
	fmt.Fprintf(os.Stderr, "terrarium jail: %v\n", err)
	os.Exit(1)
}
