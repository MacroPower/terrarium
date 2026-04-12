package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// serviceSpec defines a target service to run inside the VM.
type serviceSpec struct {
	hostname  string
	nginxConf string
	socat     string // "tcp" or "udp" for socat echo services
	port      int    // port for socat services
}

// nginxService creates a serviceSpec for an nginx target.
func nginxService(hostname, conf string) serviceSpec {
	return serviceSpec{hostname: hostname, nginxConf: conf}
}

// nginxServiceOnPort creates a serviceSpec for nginx on a single custom port.
func nginxServiceOnPort(hostname string, port int) serviceSpec {
	return serviceSpec{hostname: hostname, nginxConf: nginxConfOnPort(port)}
}

// udpEchoService creates a serviceSpec for a socat UDP echo service.
func udpEchoService(hostname string, port int) serviceSpec {
	return serviceSpec{hostname: hostname, socat: "udp", port: port}
}

// tcpEchoService creates a serviceSpec for a socat TCP echo service.
func tcpEchoService(hostname string, port int) serviceSpec {
	return serviceSpec{hostname: hostname, socat: "tcp", port: port}
}

// cleanupDNS removes test hostname entries and clears
// /etc/dnsmasq-hosts.
func (d *driver) cleanupDNS(ctx context.Context) {
	// Clear dnsmasq-hosts.
	err := d.writeFile(ctx, "/etc/dnsmasq-hosts", "")
	if err != nil {
		slog.DebugContext(ctx, "clearing dnsmasq-hosts", slog.String("error", err.Error()))
	}

	_, err = d.shell(ctx, "sudo", "systemctl", "reload", "dnsmasq")
	if err != nil {
		slog.DebugContext(ctx, "reloading dnsmasq", slog.String("error", err.Error()))
	}
}

// startService starts a target service inside the VM.
func (d *driver) startService(ctx context.Context, svc serviceSpec) error {
	if svc.socat != "" {
		return d.startSocat(ctx, svc)
	}

	return d.startNginx(ctx, svc)
}

// sanitizeHostname replaces dots with dashes for use in file paths.
func sanitizeHostname(h string) string {
	return strings.ReplaceAll(h, ".", "-")
}

// startNginx generates a TLS cert signed by the test CA and starts
// nginx with the given config. Each service gets its own per-hostname
// config, cert, and pid files so multiple nginx instances can run
// concurrently.
func (d *driver) startNginx(ctx context.Context, svc serviceSpec) error {
	tag := sanitizeHostname(svc.hostname)
	certPath := fmt.Sprintf("/tmp/nginx-%s-cert.pem", tag)
	keyPath := fmt.Sprintf("/tmp/nginx-%s-key.pem", tag)
	csrPath := fmt.Sprintf("/tmp/nginx-%s-csr.pem", tag)
	extPath := fmt.Sprintf("/tmp/nginx-%s-ext.cnf", tag)
	confPath := fmt.Sprintf("/tmp/nginx-%s.conf", tag)
	pidPath := fmt.Sprintf("/tmp/nginx-%s.pid", tag)
	logPath := fmt.Sprintf("/tmp/nginx-%s-error.log", tag)

	// Generate a TLS cert signed by the test CA.
	_, err := d.shell(ctx, "sudo", "sh", "-c", fmt.Sprintf(
		`openssl req -newkey rsa:2048 -keyout %s `+
			`-out %s -nodes -subj "/CN=%s" 2>/dev/null && `+
			`echo "subjectAltName=DNS:%s" > %s && `+
			`openssl x509 -req -in %s `+
			`-CA /etc/ssl/certs/ca-certificates.crt -CAkey /tmp/test-ca-key.pem `+
			`-CAcreateserial -out %s -days 1 `+
			`-extfile %s 2>/dev/null`,
		keyPath, csrPath, svc.hostname, svc.hostname, extPath,
		csrPath, certPath, extPath))
	if err != nil {
		// Fall back to using the test CA cert directly if the system
		// bundle cannot be used as CA cert (NixOS bundles all certs).
		_, err = d.shell(ctx, "sudo", "sh", "-c", fmt.Sprintf(
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
	}

	// Rewrite cert/key paths in the nginx config to point at the
	// per-hostname cert files.
	conf := strings.ReplaceAll(svc.nginxConf, "/tmp/nginx-cert.pem", certPath)
	conf = strings.ReplaceAll(conf, "/tmp/nginx-key.pem", keyPath)

	// Write nginx config. The service configs are bare server blocks, so
	// wrap them in the required top-level directives for a standalone
	// nginx config file.
	fullConf := "events {}\nhttp {\naccess_log /dev/null;\n" + conf + "\n}\n"
	err = d.writeFile(ctx, confPath, fullConf)
	if err != nil {
		return fmt.Errorf("writing nginx config: %w", err)
	}

	// Start nginx (each instance has its own config and pid file).
	out, err := d.shell(ctx, "sudo", "nginx", "-c", confPath,
		"-g", fmt.Sprintf("daemon on; pid %s; error_log %s;", pidPath, logPath))
	if err != nil {
		// If the port is already bound by a previous service's nginx,
		// skip silently. Multiple services using defaultNginxConf share
		// ports 80/443 and only need one nginx instance.
		if strings.Contains(out, "Address already in use") {
			return nil
		}

		return fmt.Errorf("starting nginx: %w", err)
	}

	return nil
}

// startSocat starts a socat echo service inside the VM.
func (d *driver) startSocat(ctx context.Context, svc serviceSpec) error {
	var cmd string
	if svc.socat == "udp" {
		cmd = fmt.Sprintf(
			`nohup socat UDP-RECVFROM:%d,fork,reuseaddr EXEC:'echo UDP_ECHO_OK' `+
				`>/dev/null 2>&1 & echo $!`,
			svc.port)
	} else {
		cmd = fmt.Sprintf(
			`nohup socat TCP-LISTEN:%d,fork,reuseaddr 'SYSTEM:echo TCP_FORWARD_OK; sleep 10' `+
				`>/dev/null 2>&1 & echo $!`,
			svc.port)
	}

	_, err := d.shell(ctx, "sudo", "sh", "-c", cmd)
	if err != nil {
		return fmt.Errorf("starting socat %s:%d: %w", svc.socat, svc.port, err)
	}

	return nil
}

// stopAllServices kills nginx and socat processes started by tests
// and waits for them to exit so ports are released before the next
// test starts its own services.
func (d *driver) stopAllServices(ctx context.Context) {
	// Use SIGKILL for immediate termination. SIGTERM leaves a race
	// window where the next test's startNginx sees "Address already
	// in use" and silently skips, running against the stale nginx.
	_, err := d.shell(ctx, "sudo", "pkill", "-KILL", "nginx")
	if err != nil {
		slog.DebugContext(ctx, "stopping nginx", slog.String("error", err.Error()))
	}

	_, err = d.shell(ctx, "sudo", "pkill", "-KILL", "-f", "socat")
	if err != nil {
		slog.DebugContext(ctx, "stopping socat", slog.String("error", err.Error()))
	}

	// Wait for processes to fully exit so listening sockets are
	// released before the next test binds the same ports.
	_, err = d.shell(ctx, "sudo", "sh", "-c",
		`for i in 1 2 3 4 5; do pgrep nginx >/dev/null 2>&1 || break; sleep 0.1; done`)
	if err != nil {
		slog.DebugContext(ctx, "waiting for nginx to exit", slog.String("error", err.Error()))
	}

	_, err = d.shell(ctx, "sudo", "sh", "-c",
		`rm -f /tmp/nginx-*.conf /tmp/nginx-*.pid /tmp/nginx-*-cert.pem `+
			`/tmp/nginx-*-key.pem /tmp/nginx-*-csr.pem /tmp/nginx-*-ext.cnf `+
			`/tmp/nginx-*-error.log`)
	if err != nil {
		slog.DebugContext(ctx, "cleaning up service files", slog.String("error", err.Error()))
	}
}

// writeTestCACert writes the test CA cert to the VM for nginx cert
// signing. The CA cert is also baked into the NixOS trust store via
// security.pki.certificateFiles.
func (d *driver) writeTestCACert(ctx context.Context) error {
	return d.writeFile(ctx, "/tmp/test-ca.pem", testCACert)
}
