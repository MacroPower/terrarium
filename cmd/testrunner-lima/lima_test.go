package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

var testDriver *driver

func TestMain(m *testing.M) {
	vmName := os.Getenv("LIMA_VM")
	if vmName == "" {
		vmName = "terrarium"
	}

	ctx := context.Background()
	testDriver = &driver{vmName: vmName}

	// Build and deploy testrunner.
	fmt.Println("Building testrunner for linux...")

	binPath, err := buildTestrunner(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "building testrunner: %v\n", err)
		os.Exit(2)
	}

	fmt.Println("Copying testrunner to VM...")

	err = testDriver.copyFile(ctx, binPath, "/usr/local/bin/testrunner")

	rmErr := os.Remove(binPath)
	if rmErr != nil {
		slog.DebugContext(ctx, "removing temp binary", slog.String("error", rmErr.Error()))
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "copying testrunner to VM: %v\n", err)
		os.Exit(2)
	}

	_, err = testDriver.shell(ctx, "sudo", "chmod", "+x", "/usr/local/bin/testrunner")
	if err != nil {
		fmt.Fprintf(os.Stderr, "chmod testrunner: %v\n", err)
		os.Exit(2)
	}

	// Install test CA cert and key for nginx cert signing.
	err = testDriver.writeTestCACert(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "writing test CA cert: %v\n", err)
		os.Exit(2)
	}

	err = testDriver.writeFile(ctx, "/tmp/test-ca-key.pem", testCAKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "writing test CA key: %v\n", err)
		os.Exit(2)
	}

	// Discover VM IP.
	testDriver.ip, err = testDriver.vmIP(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "discovering VM IP: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("VM IP: %s\n", testDriver.ip)

	os.Exit(m.Run())
}

func TestVM(t *testing.T) { //nolint:paralleltest // sequential: shared VM, shared daemon
	// Tests run sequentially against a single shared VM: each test
	// writes its own config, restarts the daemon, and runs assertions.
	// Parallel execution would cause config and daemon conflicts.
	//
	// Post-suite cleanup resets the VM to a known-good state so that
	// subsequent lima:rebuild runs succeed without manual intervention.
	t.Cleanup(func() { resetVM(t.Context()) })

	for i := range vmTests { //nolint:paralleltest // sequential: shared VM
		tc := vmTests[i]
		t.Run(tc.name, func(t *testing.T) {
			runVMTest(t, tc)
		})
	}
}

// resetVM restores the VM to a clean state after the full test suite.
// This ensures lima:rebuild works without manual intervention: the
// stale mutable config is removed (so the NixOS default is seeded on
// next daemon start), nftables tables are reloaded, and the daemon is
// restarted with the default config.
func resetVM(ctx context.Context) {
	d := testDriver

	d.stopAllServices(ctx)
	d.stopContainerServices(ctx)
	d.cleanupDNS(ctx)

	// Remove the test-written mutable config so the seed script
	// copies the NixOS-managed default on next daemon start.
	_, err := d.shell(ctx, "sudo", "rm", "-f", "/var/lib/terrarium/config.yaml")
	if err != nil {
		slog.WarnContext(ctx, "removing mutable config", slog.String("error", err.Error()))
	}

	// Reload nftables to restore guard and boot-time tables.
	_, err = d.shell(ctx, "sudo", "systemctl", "reload", "nftables")
	if err != nil {
		slog.WarnContext(ctx, "reloading nftables", slog.String("error", err.Error()))
	}

	// Restart the daemon with the default config so it is in a
	// known-good state for lima:rebuild.
	_, err = d.shell(ctx, "sudo", "rm", "-rf", "/var/lib/terrarium/terrarium")
	if err != nil {
		slog.WarnContext(ctx, "removing generated configs", slog.String("error", err.Error()))
	}

	_, err = d.shell(ctx, "sudo", "systemctl", "restart", "terrarium")
	if err != nil {
		slog.WarnContext(ctx, "restarting terrarium", slog.String("error", err.Error()))
	}
}

func runVMTest(t *testing.T, tc vmTest) {
	t.Helper()

	ctx := t.Context()
	d := testDriver

	hasContainers := len(tc.containerServices) > 0 || len(tc.containerAssertions) > 0

	// Kill any stale services from a previous test before starting
	// new ones. Cleanup runs between tests but a bind failure race
	// can leave a previous test's nginx occupying ports that the
	// current test needs with a different config.
	d.stopAllServices(ctx)

	// Start container services first (they need time to start).
	if len(tc.containerServices) > 0 {
		for _, svc := range tc.containerServices {
			err := d.startContainerService(ctx, svc)
			if err != nil {
				d.stopContainerServices(ctx)
				require.NoError(t, err, "starting container service %s", svc.hostname)
			}
		}
	}

	if hasContainers {
		t.Cleanup(func() { d.stopContainerServices(ctx) })
	}

	// Set up merged DNS entries for both VM and container services.
	err := d.setupContainerDNS(ctx, tc.services, tc.containerServices)
	require.NoError(t, err, "setting up DNS")

	t.Cleanup(func() { d.cleanupDNS(ctx) })

	for _, svc := range tc.services {
		err := d.startService(ctx, svc)
		if err != nil {
			d.stopAllServices(ctx)
			require.NoError(t, err, "starting service %s", svc.hostname)
		}
	}

	t.Cleanup(func() { d.stopAllServices(ctx) })

	// Collect logs on failure (registered last, runs first in LIFO).
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(d.tailLogs(ctx))
		}
	})

	// Write config and restart daemon.
	err = d.writeConfig(ctx, tc.config)
	require.NoError(t, err, "writing config")

	// Run custom setup if provided.
	if tc.setup != nil {
		err = tc.setup(ctx, d)
		require.NoError(t, err, "custom setup")
	}

	err = d.restartDaemon(ctx)
	require.NoError(t, err, "restarting daemon")

	// Merge container assertions into the VM assertion spec so they
	// run through the testrunner as UID 1000. Container assertions
	// cannot use bridge-networked containers or direct VM commands
	// because Linux NAT REDIRECT does not re-route traffic destined
	// for bridge subnet IPs (br_netfilter limitation).
	merged := tc
	merged.assertions = append(merged.assertions, tc.containerAssertions...)

	// Run all assertions via testrunner subprocess.
	runVMAssertions(t, d, merged)

	// Run custom verify if provided.
	if tc.verify != nil {
		tc.verify(t, d)
	}

	// Run custom teardown if provided.
	if tc.teardown != nil {
		err := tc.teardown(ctx, d)
		require.NoError(t, err, "custom teardown")
	}
}

func runVMAssertions(t *testing.T, d *driver, tc vmTest) {
	t.Helper()

	if len(tc.assertions) == 0 && len(tc.rootAssertions) == 0 {
		return
	}

	ctx := t.Context()

	spec := daemonSpec{
		DaemonMode:     true,
		Assertions:     tc.assertions,
		RootAssertions: tc.rootAssertions,
		Debug:          os.Getenv("TERRARIUM_DEBUG") == "1",
	}

	err := d.writeSpec(ctx, spec)
	require.NoError(t, err, "writing spec")

	exitCode, output, err := d.runTestrunner(ctx)
	require.NoError(t, err, "running testrunner")

	t.Log(output)

	switch exitCode {
	case 0:
		// All assertions passed.
	case 1:
		t.Error("testrunner assertion failures")
	default:
		t.Fatalf("testrunner infrastructure error (exit %d)", exitCode)
	}
}
