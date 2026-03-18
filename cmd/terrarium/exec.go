package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/pflag"

	"go.jacobcolvin.com/terrarium/privdrop"
)

// execPrivDrop is the hidden "exec" subcommand entrypoint. It is
// dispatched from main() before cobra setup to minimize runtime
// overhead and goroutine count during privilege-sensitive syscalls.
//
// This function does not return on success (it calls execve).
func execPrivDrop(args []string) {
	runtime.LockOSThread()

	fs := pflag.NewFlagSet("terrarium exec", pflag.ContinueOnError)

	var (
		reuid       uint32
		regid       uint32
		clearGroups bool
		initGroups  bool
		noNewPrivs  bool
		inhCaps     string
		ambientCaps string
		boundingSet string
	)

	fs.Uint32Var(&reuid, "reuid", 0, "real and effective UID")
	fs.Uint32Var(&regid, "regid", 0, "real and effective GID")
	fs.BoolVar(&clearGroups, "clear-groups", false, "clear supplementary groups")
	fs.BoolVar(&initGroups, "init-groups", false, "resolve supplementary groups from /etc/group")
	fs.BoolVar(&noNewPrivs, "no-new-privs", false, "set PR_SET_NO_NEW_PRIVS")
	fs.StringVar(&inhCaps, "inh-caps", "", "inheritable caps (+cap_name or -all)")
	fs.StringVar(&ambientCaps, "ambient-caps", "", "ambient caps (+cap_name)")
	fs.StringVar(&boundingSet, "bounding-set", "", "bounding set (-all)")

	err := fs.Parse(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "terrarium exec: %v\n", err)
		os.Exit(1)
	}

	argv := fs.Args()
	if len(argv) == 0 {
		fmt.Fprintf(os.Stderr, "terrarium exec: no command specified\n")
		os.Exit(1)
	}

	inhMask, _, err := privdrop.ParseCaps(inhCaps)
	if err != nil {
		fmt.Fprintf(os.Stderr, "terrarium exec: --inh-caps: %v\n", err)
		os.Exit(1)
	}

	ambientMask, _, err := privdrop.ParseCaps(ambientCaps)
	if err != nil {
		fmt.Fprintf(os.Stderr, "terrarium exec: --ambient-caps: %v\n", err)
		os.Exit(1)
	}

	_, clearBounding, err := privdrop.ParseCaps(boundingSet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "terrarium exec: --bounding-set: %v\n", err)
		os.Exit(1)
	}

	opts := privdrop.Options{
		UID:           reuid,
		GID:           regid,
		ClearGroups:   clearGroups,
		InitGroups:    initGroups,
		NoNewPrivs:    noNewPrivs,
		InhCaps:       inhMask,
		AmbientCaps:   ambientMask,
		ClearBounding: clearBounding,
	}

	err = privdrop.Exec(opts, argv)
	// Exec only returns on error.
	fmt.Fprintf(os.Stderr, "terrarium exec: %v\n", err)
	os.Exit(1)
}
