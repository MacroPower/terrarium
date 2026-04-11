package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// driver orchestrates test execution inside a Lima VM via limactl.
type driver struct {
	vmName string
	ip     string
}

// shell runs a command inside the VM via limactl shell.
func (d *driver) shell(ctx context.Context, args ...string) (string, error) {
	cmdArgs := append([]string{"shell", d.vmName, "--"}, args...)

	cmd := exec.CommandContext(ctx, "limactl", cmdArgs...) //nolint:gosec // args are controlled by test code.

	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("limactl shell %s: %w\noutput: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}

	return strings.TrimSpace(string(out)), nil
}

// writeFile writes content to a path inside the VM.
func (d *driver) writeFile(ctx context.Context, vmPath, content string) error {
	//nolint:gosec // args are controlled by test code.
	cmd := exec.CommandContext(
		ctx,
		"limactl",
		"shell",
		d.vmName,
		"--",
		"sudo",
		"tee",
		vmPath,
	)
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = nil
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// copyFile copies a local file into the VM via limactl cp, then
// moves it to the final destination with sudo.
func (d *driver) copyFile(ctx context.Context, localPath, vmPath string) error {
	home, err := d.shell(ctx, "sh", "-c", "echo $HOME")
	if err != nil {
		return fmt.Errorf("resolving VM home directory: %w", err)
	}

	tmpDest := home + "/lima-cp-tmp"

	cmd := exec.CommandContext(ctx, "limactl", "cp", localPath, //nolint:gosec // args are controlled by test code.
		fmt.Sprintf("%s:%s", d.vmName, tmpDest))

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("limactl cp: %w\n%s", err, string(out))
	}

	_, err = d.shell(ctx, "sudo", "mkdir", "-p", filepath.Dir(vmPath))
	if err != nil {
		return fmt.Errorf("creating directory for %s: %w", vmPath, err)
	}

	_, err = d.shell(ctx, "sudo", "mv", tmpDest, vmPath)
	if err != nil {
		return fmt.Errorf("moving to %s: %w", vmPath, err)
	}

	return nil
}

// vmIP returns the VM's primary interface IP address.
func (d *driver) vmIP(ctx context.Context) (string, error) {
	out, err := d.shell(ctx, "hostname", "-I")
	if err != nil {
		return "", err
	}

	fields := strings.Fields(out)
	if len(fields) == 0 {
		return "", fmt.Errorf("no IP address found")
	}

	return fields[0], nil
}

// defaultLogging is prepended to every test config to ensure all
// sub-process logs are available for debugging failures.
const defaultLogging = `logging:
  dns:
    enabled: true
    path: /var/lib/terrarium/dns.log
  envoy:
    level: info
    path: /var/lib/terrarium/envoy.log
    accessLog:
      enabled: true
      path: /var/lib/terrarium/envoy-access.log
  firewall:
    enabled: true
`

// writeConfig writes a terrarium YAML config to the mutable config
// path inside the VM. If the config does not already contain a
// logging section, [defaultLogging] is prepended so that sub-process
// logs are always available for failure diagnostics.
func (d *driver) writeConfig(ctx context.Context, yaml string) error {
	if !strings.Contains(yaml, "logging:") {
		yaml = defaultLogging + yaml
	}

	return d.writeFile(ctx, "/var/lib/terrarium/config.yaml", yaml)
}

// restartDaemon restarts the terrarium systemd service and polls until
// it reports "active", or returns an error after 30 seconds. It first
// restores /etc/resolv.conf to point at dnsmasq in case the previous
// daemon run replaced it.
func (d *driver) restartDaemon(ctx context.Context) error {
	// Restore resolv.conf to point at dnsmasq before restarting, in
	// case the previous daemon run replaced it.
	_, err := d.shell(ctx, "sudo", "sh", "-c",
		`echo "nameserver 127.0.0.53" > /etc/resolv.conf`)
	if err != nil {
		return fmt.Errorf("restoring resolv.conf: %w", err)
	}

	// Clear logs from previous test runs so failure logs only
	// contain output from the current test.
	_, err = d.shell(ctx, "sudo", "journalctl", "--rotate")
	if err != nil {
		slog.DebugContext(ctx, "rotating journal", slog.String("error", err.Error()))
	}

	_, err = d.shell(ctx, "sudo", "journalctl", "--vacuum-time=1s")
	if err != nil {
		slog.DebugContext(ctx, "vacuuming journal", slog.String("error", err.Error()))
	}

	_, err = d.shell(ctx, "sudo", "truncate", "-s", "0",
		"/var/lib/terrarium/envoy.log",
		"/var/lib/terrarium/envoy-access.log",
		"/var/lib/terrarium/dns.log")
	if err != nil {
		slog.DebugContext(ctx, "truncating log files", slog.String("error", err.Error()))
	}

	_, err = d.shell(ctx, "sudo", "dmesg", "--clear")
	if err != nil {
		slog.DebugContext(ctx, "clearing dmesg", slog.String("error", err.Error()))
	}

	// Remove generated configs so the daemon regenerates them from
	// the updated terrarium config. The daemon skips generation when
	// the envoy config already exists.
	_, err = d.shell(ctx, "sudo", "rm", "-rf", "/var/lib/terrarium/terrarium")
	if err != nil {
		slog.DebugContext(ctx, "removing generated configs", slog.String("error", err.Error()))
	}

	_, err = d.shell(ctx, "sudo", "systemctl", "restart", "terrarium")
	if err != nil {
		return fmt.Errorf("systemctl restart: %w", err)
	}

	// Poll for active status.
	deadline := time.Now().Add(30 * time.Second)

	for time.Now().Before(deadline) {
		out, err := d.shell(ctx, "systemctl", "is-active", "terrarium")
		if err == nil && strings.TrimSpace(out) == "active" {
			return nil
		}

		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("terrarium daemon did not become active within 30s")
}

// stopDaemon stops the terrarium daemon.
func (d *driver) stopDaemon(ctx context.Context) error {
	_, err := d.shell(ctx, "sudo", "systemctl", "stop", "terrarium")
	return err
}

// assertion mirrors the testrunner's assertion struct for JSON
// serialization into the spec passed to the testrunner binary.
type assertion struct {
	Type     string `json:"type"`
	URL      string `json:"url,omitempty"`
	Method   string `json:"method,omitempty"`
	Header   string `json:"header,omitempty"`
	Body     string `json:"body,omitempty"`
	Host     string `json:"host,omitempty"`
	Addr     string `json:"addr,omitempty"`
	Expected string `json:"expected,omitempty"`
	File     string `json:"file,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
	Domain   string `json:"domain,omitempty"`
	UID      string `json:"uid,omitempty"`
	Desc     string `json:"desc"`
	Port     int    `json:"port,omitempty"`
}

// daemonSpec is the JSON spec written to the VM for the testrunner
// to execute in daemon mode.
type daemonSpec struct {
	Assertions      []assertion `json:"assertions"`
	RootAssertions  []assertion `json:"rootAssertions"`
	DaemonMode      bool        `json:"daemonMode"`
	SkipDaemonCheck bool        `json:"skipDaemonCheck,omitempty"`
}

// writeSpec marshals the spec to JSON and writes it to /tmp/spec.json
// inside the VM.
func (d *driver) writeSpec(ctx context.Context, s daemonSpec) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshaling spec: %w", err)
	}

	return d.writeFile(ctx, "/tmp/spec.json", string(data))
}

// runTestrunner executes the testrunner inside the VM and returns
// its exit code and combined output.
func (d *driver) runTestrunner(ctx context.Context) (int, string, error) {
	//nolint:gosec // args are controlled by test code.
	cmd := exec.CommandContext(
		ctx,
		"limactl",
		"shell",
		d.vmName,
		"--",
		"sudo",
		"/usr/local/bin/testrunner",
		"--spec",
		"/tmp/spec.json",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), string(out), nil
		}

		return -1, string(out), err
	}

	return 0, string(out), nil
}

// vmTest defines a single VM e2e test case.
type vmTest struct {
	// setup runs after services are started but before the daemon
	// is restarted. Used for tests that need custom pre-conditions.
	setup func(ctx context.Context, d *driver) error

	// teardown runs after the testrunner completes, before cleanup.
	teardown func(ctx context.Context, d *driver) error

	name           string
	config         string
	assertions     []assertion
	rootAssertions []assertion
	services       []serviceSpec
}

// tailLogs fetches recent terrarium daemon and sub-process logs for
// debugging. It collects the systemd journal (daemon + DNS proxy
// stderr), the on-disk Envoy and DNS log files, the active nftables
// ruleset, and kernel log entries from nftables LOG targets.
func (d *driver) tailLogs(ctx context.Context) string {
	var buf strings.Builder

	journal, err := d.shell(ctx, "sudo", "journalctl", "-u", "terrarium", "-n", "50", "--no-pager")
	if err != nil {
		slog.DebugContext(ctx, "fetching journal", slog.String("error", err.Error()))
	}

	if journal != "" {
		buf.WriteString("  --- terrarium journal ---\n")
		buf.WriteString(journal)
		buf.WriteString("\n")
	}

	logFiles := []struct {
		label string
		path  string
	}{
		{"envoy log", "/var/lib/terrarium/envoy.log"},
		{"envoy access log", "/var/lib/terrarium/envoy-access.log"},
		{"dns log", "/var/lib/terrarium/dns.log"},
	}

	for _, logFile := range logFiles {
		content, err := d.shell(ctx, "sudo", "cat", logFile.path)

		switch {
		case err != nil:
			fmt.Fprintf(&buf, "  --- %s (not found) ---\n", logFile.label)
		case content == "":
			fmt.Fprintf(&buf, "  --- %s (empty) ---\n", logFile.label)
		default:
			lines := strings.Split(content, "\n")
			if len(lines) > 50 {
				lines = lines[len(lines)-50:]
			}

			fmt.Fprintf(&buf, "  --- %s ---\n%s\n", logFile.label, strings.Join(lines, "\n"))
		}
	}

	// nftables ruleset for firewall debugging.
	nft, err := d.shell(ctx, "sudo", "nft", "list", "ruleset")
	if err != nil {
		slog.DebugContext(ctx, "fetching nftables ruleset", slog.String("error", err.Error()))
	}

	if nft != "" {
		buf.WriteString("  --- nftables ruleset ---\n")
		buf.WriteString(nft)
		buf.WriteString("\n")
	}

	// Kernel log entries from nftables LOG targets (TERRARIUM_* prefixed).
	klog, err := d.shell(ctx, "sudo", "dmesg", "--time-format=reltime", "-l", "warn")
	if err != nil {
		slog.DebugContext(ctx, "fetching dmesg", slog.String("error", err.Error()))
	}

	if klog != "" {
		var filtered []string
		for line := range strings.SplitSeq(klog, "\n") {
			if strings.Contains(line, "TERRARIUM_") {
				filtered = append(filtered, line)
			}
		}

		if len(filtered) > 0 {
			if len(filtered) > 50 {
				filtered = filtered[len(filtered)-50:]
			}

			buf.WriteString("  --- firewall log ---\n")
			buf.WriteString(strings.Join(filtered, "\n"))
			buf.WriteString("\n")
		}
	}

	return buf.String()
}

// runTest executes a single test case: sets up services, writes
// config, restarts daemon, runs testrunner, then cleans up.
func (d *driver) runTest(ctx context.Context, tc vmTest) error {
	// Set up DNS entries and services.
	var hostnames []string

	for _, svc := range tc.services {
		hostnames = append(hostnames, svc.hostname)
	}

	err := d.setupDNS(ctx, hostnames)
	if err != nil {
		return fmt.Errorf("setting up DNS: %w", err)
	}

	defer d.cleanupDNS(ctx)

	for _, svc := range tc.services {
		err := d.startService(ctx, svc)
		if err != nil {
			d.stopAllServices(ctx)

			return fmt.Errorf("starting service %s: %w", svc.hostname, err)
		}
	}

	defer d.stopAllServices(ctx)

	// Write config and restart daemon.
	err = d.writeConfig(ctx, tc.config)
	if err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	// Run custom setup if provided.
	if tc.setup != nil {
		err = tc.setup(ctx, d)
		if err != nil {
			return fmt.Errorf("custom setup: %w", err)
		}
	}

	err = d.restartDaemon(ctx)
	if err != nil {
		return fmt.Errorf("restarting daemon: %w", err)
	}

	// Write spec and run testrunner.
	spec := daemonSpec{
		DaemonMode:     true,
		Assertions:     tc.assertions,
		RootAssertions: tc.rootAssertions,
	}

	err = d.writeSpec(ctx, spec)
	if err != nil {
		return fmt.Errorf("writing spec: %w", err)
	}

	exitCode, output, err := d.runTestrunner(ctx)
	if err != nil {
		return fmt.Errorf("running testrunner: %w\noutput:\n%s", err, output)
	}

	// Run custom teardown if provided.
	if tc.teardown != nil {
		tdErr := tc.teardown(ctx, d)
		if tdErr != nil {
			return fmt.Errorf("custom teardown: %w", tdErr)
		}
	}

	fmt.Print(output)

	switch exitCode {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("assertion failures")
	default:
		return fmt.Errorf("infrastructure error (exit %d)", exitCode)
	}
}
