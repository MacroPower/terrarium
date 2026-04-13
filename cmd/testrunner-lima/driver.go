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
	"testing"
	"time"
)

// driver orchestrates test execution inside a Lima VM via limactl.
// It provides helpers for file transfer, service lifecycle, daemon
// management, and running the testrunner binary over limactl shell.
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
// it reports "active", or returns an error after 30 seconds.
func (d *driver) restartDaemon(ctx context.Context) error {
	// Clear logs from previous test runs so failure logs only
	// contain output from the current test.
	_, err := d.shell(ctx, "sudo", "journalctl", "--rotate")
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

	// Flush conntrack entries so stale NAT/DNAT state from the
	// previous test does not affect connection routing.
	_, err = d.shell(ctx, "sudo", "conntrack", "-F")
	if err != nil {
		slog.DebugContext(ctx, "flushing conntrack", slog.String("error", err.Error()))
	}

	// Reload nftables service to restore the guard table and
	// boot-time terrarium table. Tests that flush or delete tables
	// (e.g. vm-guard-table) leave the nftables state dirty; reload
	// ensures a known-good baseline before the daemon replaces the
	// terrarium table with policy rules.
	_, err = d.shell(ctx, "sudo", "systemctl", "reload", "nftables")
	if err != nil {
		slog.DebugContext(ctx, "reloading nftables", slog.String("error", err.Error()))
	}

	_, err = d.shell(ctx, "sudo", "systemctl", "restart", "terrarium")
	if err != nil {
		return fmt.Errorf("systemctl restart: %w", err)
	}

	// Poll for active status, respecting both a 30-second wall-clock
	// deadline and the caller's context (e.g. per-test timeout).
	pollCtx, pollCancel := context.WithTimeout(ctx, 30*time.Second)
	defer pollCancel()

	for pollCtx.Err() == nil {
		out, err := d.shell(pollCtx, "systemctl", "is-active", "terrarium")
		if err == nil && strings.TrimSpace(out) == "active" {
			// Restart nscd (nsncd) after the daemon is active so
			// stale DNS failures from a previous daemon run do not
			// persist. nsncd proxies NSS lookups over a Unix socket;
			// restarting it clears any in-flight failures.
			_, nscdErr := d.shell(ctx, "sudo", "systemctl", "restart", "nscd")
			if nscdErr != nil {
				slog.DebugContext(ctx, "restarting nscd", slog.String("error", nscdErr.Error()))
			}

			return nil
		}

		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("terrarium daemon did not become active within 30s")
}

// reloadDaemon signals the terrarium daemon to reload its configuration
// via `systemctl reload` and restarts nscd to clear stale DNS state.
func (d *driver) reloadDaemon(ctx context.Context) error {
	_, err := d.shell(ctx, "sudo", "systemctl", "reload", "terrarium")
	if err != nil {
		return fmt.Errorf("systemctl reload: %w", err)
	}

	// Verify the daemon is still active after reload, respecting both
	// a 10-second wall-clock deadline and the caller's context.
	pollCtx, pollCancel := context.WithTimeout(ctx, 10*time.Second)
	defer pollCancel()

	for pollCtx.Err() == nil {
		out, err := d.shell(pollCtx, "systemctl", "is-active", "terrarium")
		if err == nil && strings.TrimSpace(out) == "active" {
			// Restart nscd so stale DNS failures from the previous
			// config do not persist.
			_, nscdErr := d.shell(ctx, "sudo", "systemctl", "restart", "nscd")
			if nscdErr != nil {
				slog.DebugContext(ctx, "restarting nscd", slog.String("error", nscdErr.Error()))
			}

			return nil
		}

		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("terrarium daemon did not become active within 10s after reload")
}

// stopDaemon stops the terrarium daemon.
func (d *driver) stopDaemon(ctx context.Context) error {
	_, err := d.shell(ctx, "sudo", "systemctl", "stop", "terrarium")
	return err
}

// assertion mirrors the testrunner's assertion struct for JSON
// serialization. Fields are populated based on the assertion type;
// unused fields are omitted from the JSON spec via omitempty tags.
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

// daemonSpec is the JSON test specification written to the VM for the
// testrunner to execute. Assertions run as a non-root user;
// RootAssertions run as root to test infrastructure-level behavior
// (nftables state, DNS proxy, process UIDs).
type daemonSpec struct {
	Assertions      []assertion `json:"assertions"`
	RootAssertions  []assertion `json:"rootAssertions"`
	DaemonMode      bool        `json:"daemonMode"`
	SkipDaemonCheck bool        `json:"skipDaemonCheck,omitempty"`
	Debug           bool        `json:"debug,omitempty"`
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

// vmTest defines a single VM e2e test case. The test lifecycle is:
// start services, write config, run setup hook, restart daemon, run
// assertions, run verify hook, run teardown hook, stop services.
type vmTest struct {
	// setup runs after services are started but before the daemon
	// is restarted. Used for tests that need custom pre-conditions.
	setup func(ctx context.Context, d *driver) error

	// verify runs after testrunner assertions complete. It receives
	// the per-test timeout context and testing.T so it can call
	// driver methods and assert results directly -- used for tests
	// that need to run commands inside ephemeral containers or other
	// actions the testrunner spec cannot express.
	verify func(ctx context.Context, t *testing.T, d *driver)

	// teardown runs after the testrunner completes, before cleanup.
	teardown func(ctx context.Context, d *driver) error

	// name identifies the test in output and --test filtering.
	name string

	// config is the terrarium YAML config written to the VM.
	config string

	// assertions run as a non-root user inside the VM.
	assertions []assertion

	// rootAssertions run as root inside the VM.
	rootAssertions []assertion

	// services are nginx/socat targets started on the VM host.
	services []serviceSpec

	// containerServices are nginx targets started as bridge-networked
	// containers with fixed IPs.
	containerServices []serviceSpec

	// containerAssertions run from ephemeral bridge-networked
	// containers to test intercepted container traffic.
	containerAssertions []assertion
}

// tailLogs fetches recent terrarium daemon and sub-process logs for
// debugging. It collects the systemd journal (daemon + DNS proxy
// stderr), the on-disk Envoy and DNS log files, the active nftables
// ruleset, and kernel log entries from nftables LOG targets.
func (d *driver) tailLogs(ctx context.Context) string {
	// Per-command timeout so one hung log source does not consume the
	// entire cleanup budget. 15 seconds accounts for limactl shell
	// SSH overhead on a loaded VM.
	const perCmd = 15 * time.Second

	var buf strings.Builder

	cmdCtx, cancel := context.WithTimeout(ctx, perCmd)
	journal, err := d.shell(cmdCtx, "sudo", "journalctl", "-u", "terrarium", "-n", "50", "--no-pager")

	cancel()

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
		cmdCtx, cancel := context.WithTimeout(ctx, perCmd)
		content, err := d.shell(cmdCtx, "sudo", "cat", logFile.path)

		cancel()

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
	cmdCtx, cancel = context.WithTimeout(ctx, perCmd)
	nft, err := d.shell(cmdCtx, "sudo", "nft", "list", "ruleset")

	cancel()

	if err != nil {
		slog.DebugContext(ctx, "fetching nftables ruleset", slog.String("error", err.Error()))
	}

	if nft != "" {
		buf.WriteString("  --- nftables ruleset ---\n")
		buf.WriteString(nft)
		buf.WriteString("\n")
	}

	// Kernel log entries from nftables LOG targets (TERRARIUM_* prefixed).
	cmdCtx, cancel = context.WithTimeout(ctx, perCmd)
	klog, err := d.shell(cmdCtx, "sudo", "dmesg", "--time-format=reltime", "-l", "warn")

	cancel()

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

	// Connection tracking state for NAT/DNAT debugging.
	cmdCtx, cancel = context.WithTimeout(ctx, perCmd)
	conntrack, err := d.shell(cmdCtx, "sudo", "conntrack", "-L")

	cancel()

	if err != nil {
		slog.DebugContext(ctx, "fetching conntrack", slog.String("error", err.Error()))
	}

	if conntrack != "" {
		lines := strings.Split(conntrack, "\n")
		if len(lines) > 50 {
			lines = lines[len(lines)-50:]
		}

		buf.WriteString("  --- conntrack ---\n")
		buf.WriteString(strings.Join(lines, "\n"))
		buf.WriteString("\n")
	}

	// DNS configuration.
	cmdCtx, cancel = context.WithTimeout(ctx, perCmd)
	resolvConf, err := d.shell(cmdCtx, "cat", "/etc/resolv.conf")

	cancel()

	if err != nil {
		slog.DebugContext(ctx, "fetching resolv.conf", slog.String("error", err.Error()))
	}

	if resolvConf != "" {
		buf.WriteString("  --- resolv.conf ---\n")
		buf.WriteString(resolvConf)
		buf.WriteString("\n")
	}

	// Listening sockets.
	cmdCtx, cancel = context.WithTimeout(ctx, perCmd)
	ss, err := d.shell(cmdCtx, "ss", "-tlnp")

	cancel()

	if err != nil {
		slog.DebugContext(ctx, "fetching ss", slog.String("error", err.Error()))
	}

	if ss != "" {
		buf.WriteString("  --- ss -tlnp ---\n")
		buf.WriteString(ss)
		buf.WriteString("\n")
	}

	// Container logs for debugging container test failures.
	cmdCtx, cancel = context.WithTimeout(ctx, perCmd)
	ctList, err := d.shell(cmdCtx, "sudo", "nerdctl", "ps", "-aq")

	cancel()

	if err == nil && ctList != "" {
		for id := range strings.FieldsSeq(ctList) {
			cmdCtx, cancel := context.WithTimeout(ctx, perCmd)
			ctLogs, err := d.shell(cmdCtx, "sudo", "nerdctl", "logs", "--tail", "20", id)

			cancel()

			if err != nil {
				continue
			}

			if ctLogs != "" {
				fmt.Fprintf(&buf, "  --- container %s logs ---\n%s\n", id, ctLogs)
			}
		}
	}

	return buf.String()
}

// startContainerService generates TLS certs, writes an nginx config,
// and starts a named container with a fixed IP on the bridge network.
func (d *driver) startContainerService(ctx context.Context, svc serviceSpec) error {
	tag := sanitizeHostname(svc.hostname)
	certPath := fmt.Sprintf("/tmp/nginx-%s-cert.pem", tag)
	keyPath := fmt.Sprintf("/tmp/nginx-%s-key.pem", tag)
	csrPath := fmt.Sprintf("/tmp/nginx-%s-csr.pem", tag)
	extPath := fmt.Sprintf("/tmp/nginx-%s-ext.cnf", tag)
	confPath := fmt.Sprintf("/tmp/nginx-%s.conf", tag)

	// Generate a TLS cert signed by the test CA.
	_, err := d.shell(ctx, "sudo", "sh", "-c", fmt.Sprintf(
		`openssl req -newkey rsa:2048 -keyout %s `+
			`-out %s -nodes -subj "/CN=%s" 2>/dev/null && `+
			`echo "subjectAltName=DNS:%s" > %s && `+
			`openssl x509 -req -in %s `+
			`-CA /tmp/test-ca.pem -CAkey /tmp/test-ca-key.pem `+
			`-CAcreateserial -out %s -days 1 `+
			`-extfile %s 2>/dev/null`,
		keyPath, csrPath, svc.hostname, svc.hostname, extPath,
		csrPath, certPath, extPath))
	if err != nil {
		return fmt.Errorf("generating TLS cert: %w", err)
	}

	// Write nginx config wrapped in required top-level directives.
	// The container volume-mounts certs to /tmp/nginx-cert.pem and
	// /tmp/nginx-key.pem, matching the paths in the config templates.
	fullConf := "error_log /dev/null;\nevents {}\nhttp {\naccess_log /dev/null;\n" + svc.nginxConf + "\n}\n"
	err = d.writeFile(ctx, confPath, fullConf)
	if err != nil {
		return fmt.Errorf("writing nginx config: %w", err)
	}

	// Remove any stale container with this name from a previous test
	// run whose cleanup may not have completed yet.
	_, err = d.shell(ctx, "sudo", "nerdctl", "rm", "-f", svc.hostname)
	if err != nil {
		slog.DebugContext(ctx, "removing stale container", slog.String("error", err.Error()))
	}

	// Start the container with host networking so it listens on
	// the VM's IP. Host networking avoids br_netfilter issues where
	// NAT REDIRECT fails for bridge subnet destinations.
	_, err = d.shell(ctx, "sudo", "nerdctl", "run", "-d",
		"--name", svc.hostname,
		"--network", "host",
		"-v", certPath+":/tmp/nginx-cert.pem:ro",
		"-v", keyPath+":/tmp/nginx-key.pem:ro",
		"-v", confPath+":/etc/nginx/nginx.conf:ro",
		"terrarium-test:latest",
		"nginx", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;")
	if err != nil {
		return fmt.Errorf("starting container %s: %w", svc.hostname, err)
	}

	return nil
}

// runInBridgeContainer runs a command inside an ephemeral
// bridge-networked container with the given DNS server and returns
// the combined output. The container is removed after the command
// completes.
func (d *driver) runInBridgeContainer(ctx context.Context, dns string, args ...string) (string, error) {
	cmdArgs := []string{
		"sudo", "nerdctl", "run", "--rm",
		"--network", "bridge",
		"--dns", dns,
		"terrarium-test:latest",
	}
	cmdArgs = append(cmdArgs, args...)

	return d.shell(ctx, cmdArgs...)
}

// stopContainerServices kills and removes all test containers.
func (d *driver) stopContainerServices(ctx context.Context) {
	_, err := d.shell(ctx, "sudo", "sh", "-c",
		`nerdctl rm -f $(nerdctl ps -aq) 2>/dev/null || true`)
	if err != nil {
		slog.DebugContext(ctx, "stopping containers", slog.String("error", err.Error()))
	}
}

// setupContainerDNS writes dnsmasq host entries mapping all service
// hostnames to the VM's IP. Container services run with host
// networking so they listen on the VM's IP alongside VM services.
func (d *driver) setupContainerDNS(ctx context.Context, vmServices, containerServices []serviceSpec) error {
	var lines []string

	for _, svc := range vmServices {
		lines = append(lines, fmt.Sprintf("%s %s", d.ip, svc.hostname))
	}

	for _, svc := range containerServices {
		lines = append(lines, fmt.Sprintf("%s %s", d.ip, svc.hostname))
	}

	if len(lines) == 0 {
		return nil
	}

	content := strings.Join(lines, "\n") + "\n"

	err := d.writeFile(ctx, "/etc/dnsmasq-hosts", content)
	if err != nil {
		return fmt.Errorf("writing dnsmasq-hosts: %w", err)
	}

	_, err = d.shell(ctx, "sudo", "systemctl", "reload", "dnsmasq")
	if err != nil {
		_, err = d.shell(ctx, "sudo", "systemctl", "restart", "dnsmasq")
		if err != nil {
			return fmt.Errorf("reloading dnsmasq: %w", err)
		}
	}

	return nil
}
