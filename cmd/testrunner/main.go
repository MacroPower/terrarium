// Command testrunner executes e2e test assertions inside a terrarium
// container. It handles the full test lifecycle: Envoy config validation,
// terrarium init with readiness polling, assertion execution (with
// optional UID switching), and result reporting.
//
// Usage:
//
//	testrunner --spec <path>        # normal mode
//	testrunner --child --spec <path> --results <path>  # child mode (UID 1000)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	specPath := flag.String("spec", "", "path to JSON spec file")
	child := flag.Bool("child", false, "run in child mode (direct assertion execution)")
	resultsPath := flag.String("results", "", "path to write results JSON (child mode)")

	flag.Parse()

	if *specPath == "" {
		fmt.Fprintln(os.Stderr, "usage: testrunner --spec <path>")
		os.Exit(2)
	}

	data, err := os.ReadFile(*specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading spec: %v\n", err)
		os.Exit(2)
	}

	var s spec

	err = json.Unmarshal(data, &s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parsing spec: %v\n", err)
		os.Exit(2)
	}

	ctx := context.Background()

	if *child {
		if *resultsPath == "" {
			fmt.Fprintln(os.Stderr, "child mode requires --results <path>")
			os.Exit(2)
		}

		os.Exit(runChild(ctx, s, *resultsPath))
	}

	if s.DaemonMode {
		os.Exit(runDaemon(ctx, s))
	}

	os.Exit(run(ctx, s))
}
