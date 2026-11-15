//go:build linux

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/config"
)

// requireTransparentSockets skips the test when the process cannot set
// IP_TRANSPARENT on a socket. The catch-all UDP listener of the
// container-mode bootstrap sets the option, and Envoy exits when the
// kernel refuses it.
func requireTransparentSockets(t *testing.T) {
	t.Helper()

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	require.NoError(t, err)

	defer func() {
		assert.NoError(t, syscall.Close(fd))
	}()

	err = syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
	if err != nil {
		t.Skipf("IP_TRANSPARENT unavailable: %v", err)
	}
}

// requireFreeListenerPorts skips the test when another process holds
// one of ports on loopback. The container-mode bootstrap binds fixed
// ports, so a terrarium on the host of the test holds them.
func requireFreeListenerPorts(t *testing.T, ports ...int) {
	t.Helper()

	for _, port := range ports {
		err := checkListenAddress(t.Context(), fmt.Sprintf("%s:%d", loopbackIPv4, port))
		if err != nil {
			t.Skipf("envoy listener port in use: %v", err)
		}
	}
}

// TestInitE2EEnvoyReady checks the readiness wait of container mode
// against a real Envoy that loads a container-mode bootstrap together
// with the ready overlay.
//
// Envoy answers on the ready socket only after its listeners accept
// connections. When another process holds one of its listener ports,
// Envoy exits, and the wait reports that Envoy is not running. A
// connection to that port still succeeds.
//
//nolint:paralleltest // e2e tests run envoy subprocesses on fixed ports.
func TestInitE2EEnvoyReady(t *testing.T) {
	requireEnvoy(t)
	requireTransparentSockets(t)

	tcpPorts := []int{15443, 15080, config.CatchAllProxyPort}
	requireFreeListenerPorts(t, tcpPorts...)

	ctx := t.Context()

	cfg, err := config.ParseConfig(ctx, []byte("egress:\n"+
		"  - toFQDNs:\n"+
		"      - matchName: api.example.com\n"+
		"    toPorts:\n"+
		"      - ports:\n"+
		"          - port: \"443\"\n"+
		"          - port: \"80\"\n"))
	require.NoError(t, err)

	bootstrap, err := GenerateEnvoyFromConfig(ctx, cfg, "", "", false)
	require.NoError(t, err)

	dir := t.TempDir()
	bootstrapPath := filepath.Join(dir, "envoy.yaml")
	logPath := filepath.Join(dir, "envoy.log")

	require.NoError(t, os.WriteFile(bootstrapPath, []byte(bootstrap), 0o644))

	t.Cleanup(func() {
		if !t.Failed() {
			return
		}

		envoyLog, readErr := os.ReadFile(logPath)
		if readErr == nil {
			t.Logf("envoy log:\n%s", envoyLog)
		}
	})

	// start runs Envoy as init does, without the privilege drop.
	start := func(startupTimeout time.Duration) (*exec.Cmd, error) {
		socket, err := newReadySocket(ctx, shortTempDir(t), os.Getgid())
		require.NoError(t, err)

		overlay, err := readyOverlayYAML(socket)
		require.NoError(t, err)

		cmd := exec.CommandContext(ctx, "envoy",
			"-c", bootstrapPath,
			"--config-yaml", overlay,
			"--log-path", logPath,
			"--concurrency", "2",
			// Hot restart uses a shared-memory region keyed by
			// base-id, which the Envoys of other tests also use.
			"--disable-hot-restart")

		settings := config.EnvoySettings{
			StartupTimeout: config.Duration{Duration: startupTimeout},
			DrainTimeout:   config.Duration{Duration: 15 * time.Second},
		}

		return cmd, startEnvoyAndWait(ctx, cmd, socket, settings)
	}

	dial := func(port int) error {
		dialer := net.Dialer{Timeout: 2 * time.Second}

		conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", loopbackIPv4, port))
		if err != nil {
			return err
		}

		return conn.Close()
	}

	cmd, err := start(30 * time.Second)
	require.NoError(t, err)

	// One attempt for each port, without a retry. The listeners of the
	// bootstrap file already accept connections when the wait returns.
	for _, port := range tcpPorts {
		require.NoError(t, dial(port), "listener port %d", port)
	}

	stopEnvoy(ctx, cmd, 15*time.Second)
	require.NotNil(t, cmd.ProcessState, "envoy must have exited")

	// Another process takes a listener port before Envoy starts. Go
	// does not set SO_REUSEPORT, so Envoy cannot bind the port.
	lc := net.ListenConfig{}

	ln, err := lc.Listen(ctx, "tcp", fmt.Sprintf("%s:%d", loopbackIPv4, 15080))
	require.NoError(t, err)

	t.Cleanup(func() {
		assert.NoError(t, ln.Close())
	})

	cmd, err = start(3 * time.Second)
	require.ErrorIs(t, err, ErrEnvoyNotRunning)
	require.ErrorIs(t, err, ErrListenerNotReady)
	require.NotNil(t, cmd.ProcessState, "envoy must have been waited on")

	// A connection to the port succeeds, so the port does not show
	// whose listener accepts the connection.
	require.NoError(t, dial(15080))
}
