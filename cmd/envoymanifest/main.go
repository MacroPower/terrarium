package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"go.jacobcolvin.com/terrarium/envoybin"
)

// manifestSource is the default path of the Go source file that defines
// [envoybin.DefaultManifest], relative to the root of the repository.
const manifestSource = "envoybin/manifest.go"

// The names of the commands.
const (
	cmdUpdate = "update"
	cmdVerify = "verify"
)

const usage = `usage:
  envoymanifest update [file]       write the hashes of the pinned version into file
  envoymanifest verify [platform]   check the provenance of the build for this host`

var (
	// ErrUsage means that the arguments do not name a command.
	ErrUsage = errors.New(usage)

	// ErrHost means that the host is not the platform that the caller
	// expects.
	ErrHost = errors.New("host is a different platform")
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	err := run(ctx, os.Args[1:], os.Stdout)

	stop()

	if err != nil {
		fmt.Fprintln(os.Stderr, "envoymanifest:", err)
		os.Exit(1)
	}
}

// run executes the command that args names and writes its report to out.
func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || len(args) > 2 {
		return ErrUsage
	}

	manifest := envoybin.DefaultManifest()

	switch args[0] {
	case cmdUpdate:
		path := manifestSource
		if len(args) == 2 {
			path = args[1]
		}

		return update(ctx, &http.Client{}, manifest, path, out)

	case cmdVerify:
		host := envoybin.HostPlatform()
		if len(args) == 2 && args[1] != host.String() {
			return fmt.Errorf("%w: want %s, host is %s", ErrHost, args[1], host)
		}

		return newVerifier(manifest, host, githubToken(os.Getenv)).verify(ctx, out)

	default:
		return ErrUsage
	}
}

// githubToken returns the GitHub token of the environment that getenv
// reads. The GH_TOKEN variable takes precedence over GITHUB_TOKEN, as it
// does for the gh CLI. The result is empty when neither variable has a
// value.
func githubToken(getenv func(string) string) string {
	token := getenv("GH_TOKEN")
	if token == "" {
		token = getenv("GITHUB_TOKEN")
	}

	return token
}
