package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/dnsproxy"
	"go.jacobcolvin.com/terrarium/firewall"
)

// Daemon runs terrarium as a VM-wide network filter daemon. It
// performs the same infrastructure setup as [Init] (nftables, DNS
// proxy, Envoy) but applies policy rules to all UIDs in the network
// namespace rather than a single Terrarium UID. Instead of
// privilege-dropping and exec'ing a user command, it blocks until
// SIGTERM or SIGINT arrives and then tears down cleanly.
//
// On shutdown, nftables rules and policy routes are intentionally
// left in place so the VM remains fail-closed. The rules are
// atomically replaced on the next startup.
func Daemon(ctx context.Context, usr *config.User) error {
	envoyUID, err := parseUID(usr.EnvoyUID)
	if err != nil {
		return err
	}

	uids := firewall.UIDs{
		Envoy:       envoyUID,
		Root:        0,
		VMMode:      true,
		ExcludeUIDs: toUint32s(usr.ExcludeDNSUIDs),
	}

	inf, err := setupInfrastructure(ctx, usr, uids)
	if err != nil {
		return err
	}

	// Start watchdog goroutine before signaling readiness.
	watchdogCtx, watchdogCancel := context.WithCancel(ctx)
	defer watchdogCancel()

	go sdWatchdog(watchdogCtx)

	sdNotify(ctx, "READY=1")

	slog.InfoContext(ctx, "terrarium daemon ready, filtering all VM traffic")

	// Block until termination signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	sig := <-sigCh

	slog.InfoContext(ctx, "received signal, shutting down",
		slog.Any("signal", sig),
	)

	sdNotify(ctx, "STOPPING=1")
	watchdogCancel()

	// Shut down Envoy and DNS proxy but intentionally leave nftables
	// rules and policy routes in place for fail-closed behavior.
	daemonShutdown(ctx, inf.envoyCmd, inf.dnsProxy, inf.drainTimeout)

	return nil
}

// daemonShutdown stops Envoy and the DNS proxy without removing
// nftables rules or policy routes. The firewall rules persist in
// the kernel so the VM remains fail-closed after the daemon exits.
func daemonShutdown(
	ctx context.Context, envoyCmd *exec.Cmd,
	dnsProxy *dnsproxy.Proxy, drainTimeout time.Duration,
) {
	// Stop Envoy first so DNS remains available during drain.
	stopEnvoy(ctx, envoyCmd, drainTimeout)
	stopDNSProxy(ctx, dnsProxy)
}

// sdNotify sends a notification to systemd via the NOTIFY_SOCKET.
// Errors are logged but not returned -- sd_notify is best-effort.
func sdNotify(ctx context.Context, state string) {
	socketAddr := os.Getenv("NOTIFY_SOCKET")
	if socketAddr == "" {
		return
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "unixgram", socketAddr)
	if err != nil {
		slog.DebugContext(ctx, "sd_notify dial", slog.Any("err", err))
		return
	}

	defer func() {
		cerr := conn.Close()
		if cerr != nil {
			slog.Debug("sd_notify close", slog.Any("err", cerr))
		}
	}()

	_, err = conn.Write([]byte(state))
	if err != nil {
		slog.DebugContext(ctx, "sd_notify write", slog.Any("err", err))
	}
}

// sdWatchdog sends periodic watchdog pings to systemd until the
// context is canceled.
func sdWatchdog(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sdNotify(ctx, "WATCHDOG=1")
		}
	}
}
