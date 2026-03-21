package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	readyTimeout = 60 * time.Second
	readyFile    = "/tmp/.terrarium-ready"
)

// run executes the full e2e test lifecycle defined by the given [spec].
// It returns exit code 0 for all-pass, 1 for assertion failures, and
// 2 for infrastructure errors.
func run(s spec) int {
	// Step 1: Validate Envoy config if requested.
	if s.ValidateEnvoy {
		fmt.Println("Validating Envoy configuration...")

		err := validateEnvoy(s.ConfigPath)
		if err != nil {
			fmt.Printf("Infrastructure error: envoy validation: %v\n", err)
			return 2
		}
	}

	// Step 2: Install extra CA cert by creating a combined bundle and
	// setting SSL_CERT_FILE. This must happen before terrarium init
	// so that FindCABundle returns the combined bundle for Envoy's
	// upstream TLS config. The child terrarium process inherits the
	// environment variable.
	if s.ExtraCACertPath != "" {
		err := installExtraCACert(s.ExtraCACertPath)
		if err != nil {
			fmt.Printf("Infrastructure error: %v\n", err)
			return 2
		}
	}

	// Step 3: Start loopback listener if configured.
	if s.LoopbackPort > 0 {
		startLoopbackListener(s.LoopbackPort)
	}

	// Step 4: Start terrarium init as a subprocess.
	initCmd := s.InitCommand
	if initCmd == "" {
		initCmd = "sleep infinity"
	}

	args := []string{
		"init",
		"--config", s.ConfigPath,
		"--ready-file", readyFile,
		"--",
	}
	args = append(args, "sh", "-c", initCmd)

	ctx := context.Background()

	terrarium := exec.CommandContext(ctx, "terrarium", args...) //nolint:gosec // args built from spec
	terrarium.Stdout = os.Stdout
	terrarium.Stderr = os.Stderr

	err := terrarium.Start()
	if err != nil {
		fmt.Printf("Infrastructure error: starting terrarium: %v\n", err)
		return 2
	}

	// Monitor terrarium exit concurrently.
	terrariumDone := make(chan error, 1)

	go func() {
		terrariumDone <- terrarium.Wait()
	}()

	// Step 4: Poll for ready file, watching for early terrarium exit.
	err = waitReady(terrariumDone)
	if err != nil {
		fmt.Printf("Infrastructure error: %v\n", err)
		// Try to capture any terrarium stderr output.
		sigErr := terrarium.Process.Signal(syscall.SIGTERM)
		if sigErr != nil {
			slog.Debug("signaling terrarium", slog.Any("err", sigErr))
		}

		return 2
	}

	// Step 5: Run root assertions (as root, direct execution).
	var results []result

	if len(s.RootAssertions) > 0 {
		fmt.Printf("\nRunning %d root assertions...\n", len(s.RootAssertions))

		for i := range s.RootAssertions {
			r := runAssertion(s.RootAssertions[i])
			printResult(r)

			results = append(results, r)
		}
	}

	// Step 6: Run user assertions as UID 1000.
	if len(s.Assertions) > 0 {
		fmt.Printf("\nRunning %d user assertions (UID 1000)...\n", len(s.Assertions))

		childResults, err := runAsChild(s.Assertions)
		if err != nil {
			fmt.Printf("Infrastructure error: running child assertions: %v\n", err)

			sigErr := terrarium.Process.Signal(syscall.SIGTERM)
			if sigErr != nil {
				slog.Debug("signaling terrarium", slog.Any("err", sigErr))
			}

			return 2
		}

		results = append(results, childResults...)
	}

	// Step 7: Print summary and clean up. Wait for terrarium to exit
	// so Envoy flushes access logs before the container stops.
	sigErr := terrarium.Process.Signal(syscall.SIGTERM)
	if sigErr != nil {
		slog.Debug("signaling terrarium", slog.Any("err", sigErr))
	}

	select {
	case <-terrariumDone:
	case <-time.After(10 * time.Second):
		slog.Debug("terrarium did not exit within 10s after SIGTERM")
	}

	passed := 0

	failed := 0
	for _, r := range results {
		if r.Status == statusPass {
			passed++
		} else {
			failed++
		}
	}

	fmt.Printf("\nResults: %d passed, %d failed\n", passed, failed)

	if failed > 0 {
		return 1
	}

	return 0
}

// validateEnvoy generates an Envoy config and validates it.
func validateEnvoy(configPath string) error {
	ctx := context.Background()

	// Create a temporary access log file so Envoy validation can open
	// the path referenced in the generated config.
	accessLog := "/tmp/envoy-validate-access.log"

	f, err := os.Create(accessLog)
	if err != nil {
		return fmt.Errorf("creating access log for validation: %w", err)
	}

	closeErr := f.Close()
	if closeErr != nil {
		slog.Debug("closing access log for validation", slog.Any("err", closeErr))
	}

	genCmd := exec.CommandContext(ctx, "terrarium", "generate",
		"--config", configPath,
		"--envoy-config", "/tmp/envoy-validate.yaml",
		"--envoy-access-log", accessLog,
	)
	genCmd.Stdout = os.Stdout
	genCmd.Stderr = os.Stderr

	err = genCmd.Run()
	if err != nil {
		return fmt.Errorf("terrarium generate: %w", err)
	}

	valCmd := exec.CommandContext(
		ctx,
		"/usr/local/bin/envoy", "--mode", "validate", "-c", "/tmp/envoy-validate.yaml",
	)
	valCmd.Stdout = os.Stdout
	valCmd.Stderr = os.Stderr

	err = valCmd.Run()
	if err != nil {
		return fmt.Errorf("envoy validate: %w", err)
	}

	rmErr := os.Remove("/tmp/envoy-validate.yaml")
	if rmErr != nil {
		slog.Debug("removing envoy config", slog.Any("err", rmErr))
	}

	rmErr = os.Remove(accessLog)
	if rmErr != nil {
		slog.Debug("removing access log for validation", slog.Any("err", rmErr))
	}

	return nil
}

// waitReady polls for the ready file, returning an error if terrarium
// exits before the file appears or if the timeout is reached.
func waitReady(terrariumDone <-chan error) error {
	deadline := time.After(readyTimeout)

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case err := <-terrariumDone:
			if err != nil {
				return fmt.Errorf("terrarium exited before ready: %w", err)
			}

			return fmt.Errorf("terrarium exited before ready (exit 0)")

		case <-deadline:
			return fmt.Errorf("terrarium did not become ready within %s", readyTimeout)
		case <-ticker.C:
			_, statErr := os.Stat(readyFile)
			if statErr == nil {
				fmt.Println("Terrarium is ready.")
				return nil
			}
		}
	}
}

// runAsChild re-executes the testrunner as a child process with UID/GID
// 1000, running only the given assertions. Returns the child's results.
func runAsChild(assertions []assertion) ([]result, error) {
	childSpec := spec{
		Assertions: assertions,
	}

	specJSON, err := json.Marshal(childSpec)
	if err != nil {
		return nil, fmt.Errorf("marshaling child spec: %w", err)
	}

	specFile := "/tmp/child-spec.json"

	err = os.WriteFile(specFile, specJSON, 0o644)
	if err != nil {
		return nil, fmt.Errorf("writing child spec: %w", err)
	}

	defer func() {
		err := os.Remove(specFile)
		if err != nil {
			slog.Debug("removing spec file", slog.Any("err", err))
		}
	}()

	resultsFile := "/tmp/child-results.json"

	cmd := exec.CommandContext(
		context.Background(),
		"/proc/self/exe", "--child", "--spec", specFile, "--results", resultsFile,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: 1000,
			Gid: 1000,
		},
	}

	err = cmd.Run()
	if err != nil {
		// The child exits 1 on assertion failures -- that is not an
		// infrastructure error. Read the results file if it exists.
		_, statErr := os.Stat(resultsFile)
		if statErr != nil {
			return nil, fmt.Errorf("child process: %w", err)
		}
	}

	data, err := os.ReadFile(resultsFile)
	if err != nil {
		return nil, fmt.Errorf("reading child results: %w", err)
	}

	rmErr := os.Remove(resultsFile)
	if rmErr != nil {
		slog.Debug("removing results file", slog.Any("err", rmErr))
	}

	var results []result

	err = json.Unmarshal(data, &results)
	if err != nil {
		return nil, fmt.Errorf("parsing child results: %w", err)
	}

	return results, nil
}

// runChild executes assertions directly (called in the child process
// after UID switch). Results are written to the given file path.
func runChild(s spec, resultsPath string) int {
	var results []result

	for i := range s.Assertions {
		r := runAssertion(s.Assertions[i])
		printResult(r)

		results = append(results, r)
	}

	data, err := json.Marshal(results)
	if err != nil {
		fmt.Printf("marshaling results: %v\n", err)
		return 2
	}

	err = os.WriteFile(resultsPath, data, 0o644)
	if err != nil {
		fmt.Printf("writing results: %v\n", err)
		return 2
	}

	for _, r := range results {
		if r.Status != statusPass {
			return 1
		}
	}

	return 0
}

// startLoopbackListener starts a simple HTTP server on localhost at the
// given port. Used by the loopback deny-all test.
func startLoopbackListener(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")

		_, err := fmt.Fprint(w, "LOOPBACK_OK\n")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})

	srv := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			slog.Debug("loopback listener exited", slog.Any("err", err))
		}
	}()

	// Wait for the listener to be ready.
	deadline := time.Now().Add(10 * time.Second)

	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(
			context.Background(), http.MethodGet,
			fmt.Sprintf("http://127.0.0.1:%d/", port), http.NoBody,
		)
		if err != nil {
			continue
		}

		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			err := resp.Body.Close()
			if err != nil {
				slog.Debug("closing response body", slog.Any("err", err))
			}

			return
		}

		time.Sleep(100 * time.Millisecond)
	}

	fmt.Printf(
		"Warning: loopback listener on port %d did not start within 10 seconds\n",
		port,
	)
}

// installExtraCACert appends the given CA certificate to the system
// bundle and sets SSL_CERT_FILE to the combined path.
func installExtraCACert(path string) error {
	caData, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading extra CA cert: %w", err)
	}

	systemBundle, err := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
	if err != nil {
		return fmt.Errorf("reading system CA bundle: %w", err)
	}

	combined := make([]byte, 0, len(systemBundle)+1+len(caData))
	combined = append(combined, systemBundle...)
	combined = append(combined, '\n')
	combined = append(combined, caData...)

	combinedPath := "/tmp/ca-bundle-with-test-ca.pem"

	err = os.WriteFile(combinedPath, combined, 0o644)
	if err != nil {
		return fmt.Errorf("writing combined CA bundle: %w", err)
	}

	err = os.Setenv("SSL_CERT_FILE", combinedPath)
	if err != nil {
		return fmt.Errorf("setting SSL_CERT_FILE: %w", err)
	}

	return nil
}

// printResult prints a single assertion result to stdout.
func printResult(r result) {
	if r.Status == statusPass {
		fmt.Printf("  PASS: %s\n", r.Desc)
	} else {
		fmt.Printf("  FAIL: %s (%s)\n", r.Desc, r.Detail)
	}
}
