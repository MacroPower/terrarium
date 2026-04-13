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
// namespace rather than a single container UID. Instead of
// privilege-dropping and exec'ing a user command, it blocks until
// a termination signal arrives and then tears down cleanly.
//
// SIGHUP triggers a live configuration reload via
// [reloadInfrastructure] without restarting the process. SIGTERM and
// SIGINT initiate graceful shutdown.
//
// On shutdown, nftables rules and policy routes are intentionally
// left in place so the VM remains fail-closed. The rules are
// atomically replaced on the next startup.
func Daemon(ctx context.Context, usr *config.User, pidFile string) error {
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

	// Write PID file so `terrarium daemon reload` can discover us.
	err = writePIDFile(pidFile)
	if err != nil {
		return err
	}

	defer os.Remove(pidFile) //nolint:errcheck // best-effort cleanup.

	// Start watchdog goroutine before signaling readiness.
	watchdogCtx, watchdogCancel := context.WithCancel(ctx)
	defer watchdogCancel()

	go sdWatchdog(watchdogCtx)

	sdNotify(ctx, "READY=1")

	slog.InfoContext(ctx, "terrarium daemon ready, filtering all VM traffic")

	// Block until termination signal, handling SIGHUP for reload.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	for sig := range sigCh {
		if sig != syscall.SIGHUP {
			slog.InfoContext(ctx, "received signal, shutting down",
				slog.Any("signal", sig),
			)

			break
		}

		slog.InfoContext(ctx, "received SIGHUP, reloading configuration")

		sdNotify(ctx, "RELOADING=1")
		reloadInfrastructure(ctx, usr, uids, inf)
		sdNotify(ctx, "READY=1")
	}

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
