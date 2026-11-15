//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.jacobcolvin.com/terrarium/config"
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
// SIGINT initiate graceful shutdown. A termination signal that
// arrives during a reload shuts the daemon down when that reload
// ends, before the reload for a SIGHUP that also arrived. See
// [serveSignals] for the handling of a reload that does not complete.
//
// Daemon returns an error when a reload stops after it started to
// replace the installed CA certificate, the running rules, the DNS
// proxy, or Envoy. The daemon then shuts down as it does for a
// termination signal, so a supervisor such as systemd can restart it.
//
// Daemon records each reload in the reload status file, so
// [DaemonReload] can wait for the reload and report its outcome. See
// [reloadRecorder] for the content of the file and [serveReloads] for
// when Daemon removes it.
//
// The restarted daemon generates its configs from the config file
// again, so a corrected config file takes effect.
// [setupInfrastructure] generates the configs only when the Envoy
// bootstrap does not exist. Daemon therefore removes the generated
// bootstrap in each of these cases:
//
//   - A reload makes Daemon return an error. See
//     [reloadInfrastructure].
//   - The setup generates the bootstrap and then returns an error.
//     See [discardBootstrapOnError].
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

	inf, err := discardBootstrapOnError(ctx, usr.EnvoyConfigPath, func() (*infra, error) {
		return setupInfrastructure(ctx, usr, uids)
	})
	if err != nil {
		return err
	}

	// Write the reload status before the PID file, so that
	// `terrarium daemon reload` finds the status of each daemon that
	// it finds through the PID file.
	recorder, err := newReloadRecorder(reloadStatusPath(pidFile))
	if err != nil {
		daemonShutdown(ctx, inf)

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
	// [signal.Notify] drops a signal when its channel is full. SIGHUP
	// has its own channel, so that the SIGHUP signals that arrive
	// during a reload never fill the channel of the termination
	// signals.
	termCh := make(chan os.Signal, 1)
	signal.Notify(termCh, syscall.SIGTERM, syscall.SIGINT)

	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)

	return serveReloads(ctx, termCh, hupCh, sdNotify, recorder,
		func(ctx context.Context) error {
			return reloadInfrastructure(ctx, usr, uids, inf)
		},
		func(ctx context.Context) {
			watchdogCancel()

			// Shut down Envoy and DNS proxy but intentionally leave
			// nftables rules and policy routes in place for
			// fail-closed behavior. The stats DB still closes,
			// because the rules and routes in the kernel keep the VM
			// fail-closed, not stats ingestion.
			daemonShutdown(ctx, inf)
		},
	)
}

// serveReloads runs the signal loop of the daemon with [serveSignals]
// and returns the error of that loop. It passes reload to the loop
// through recorder, so the reload status file records each reload.
//
// When the loop returns, serveReloads sends STOPPING=1 through notify
// and calls shutdown. It then removes the status file only when the
// loop returned nil. The loop returns nil for a termination signal
// and when termCh or hupCh closes. After a reload that ends the
// daemon, the file stays, so [DaemonReload] can report the error of
// that reload.
func serveReloads(
	ctx context.Context,
	termCh, hupCh <-chan os.Signal,
	notify func(ctx context.Context, state string),
	recorder *reloadRecorder,
	reload func(ctx context.Context) error,
	shutdown func(ctx context.Context),
) error {
	err := serveSignals(ctx, termCh, hupCh, notify, func(ctx context.Context) error {
		return recorder.record(ctx, reload)
	})

	notify(ctx, "STOPPING=1")
	shutdown(ctx)

	if err == nil {
		recorder.remove(ctx)
	}

	return err
}

// discardBootstrapOnError calls setup and returns its result. When
// the Envoy bootstrap at path did not exist before the call and setup
// returns an error, discardBootstrapOnError removes the bootstrap
// that setup generated. The next start of the daemon then generates
// the configs from the config file again.
//
// A bootstrap that existed before the call stays in place, because
// setup did not generate it.
func discardBootstrapOnError(ctx context.Context, path string, setup func() (*infra, error)) (*infra, error) {
	_, statErr := os.Stat(path)

	inf, err := setup()
	if err != nil && errors.Is(statErr, fs.ErrNotExist) {
		removeErr := removeEnvoyBootstrap(path)
		if removeErr != nil {
			slog.ErrorContext(ctx, "discarding the configs of the setup", slog.Any("err", removeErr))
		}
	}

	return inf, err
}

// serveSignals handles the signals of the daemon until the daemon
// must shut down. It reads each signal with [nextSignal], from termCh
// for the termination signals and from hupCh for SIGHUP. It returns
// nil for a termination signal, which is every signal except SIGHUP,
// and when termCh or hupCh closes.
//
// During a reload, serveSignals reads neither channel, and
// [signal.Notify] drops a signal when its channel is full. The caller
// must therefore give termCh a buffer and send it only termination
// signals. With that buffer, termCh keeps a termination signal that
// arrives during a reload.
//
// For each SIGHUP, serveSignals sends RELOADING=1 through notify and
// calls reload. The result of reload decides what follows:
//
//   - With no error, the daemon runs the new config. serveSignals
//     sends READY=1 and waits for the next signal.
//   - With an error that wraps [ErrReloadRejected], the daemon runs
//     the previous config unchanged. serveSignals logs the error,
//     sends READY=1, and waits for the next signal.
//   - With every other error, the reload stopped between the previous
//     config and the new config. serveSignals does not send READY=1,
//     and it returns the error so the caller shuts the daemon down.
func serveSignals(
	ctx context.Context,
	termCh, hupCh <-chan os.Signal,
	notify func(ctx context.Context, state string),
	reload func(ctx context.Context) error,
) error {
	for {
		sig := nextSignal(termCh, hupCh)
		if sig == nil {
			return nil
		}

		if sig != syscall.SIGHUP {
			slog.InfoContext(ctx, "received signal, shutting down",
				slog.Any("signal", sig),
			)

			return nil
		}

		slog.InfoContext(ctx, "received SIGHUP, reloading configuration")

		notify(ctx, "RELOADING=1")

		err := reload(ctx)

		switch {
		case err == nil:

		case errors.Is(err, ErrReloadRejected):
			slog.ErrorContext(ctx, "keeping the running configuration", slog.Any("err", err))

		default:
			return fmt.Errorf("reloading configuration: %w", err)
		}

		notify(ctx, "READY=1")
	}
}

// nextSignal waits for a signal on termCh or hupCh and returns it. It
// returns nil when the channel that it reads is closed.
//
// When both channels hold a signal, nextSignal returns the signal of
// termCh. The daemon therefore shuts down for a termination signal
// before it starts a reload for a SIGHUP that also waits.
func nextSignal(termCh, hupCh <-chan os.Signal) os.Signal {
	// A select with two ready channels picks one at random, so read
	// termCh alone first.
	select {
	case sig := <-termCh:
		return sig
	default:
	}

	select {
	case sig := <-termCh:
		return sig
	case sig := <-hupCh:
		return sig
	}
}

// daemonShutdown stops Envoy, the gRPC access-log server, and the
// DNS proxy without removing nftables rules or policy routes. The
// firewall rules persist in the kernel so the VM remains
// fail-closed after the daemon exits. The stats event store closes
// regardless so any final batched writes flush. A nil [*infra] is
// a no-op.
func daemonShutdown(ctx context.Context, inf *infra) {
	if inf == nil {
		return
	}

	stopEnvoy(ctx, inf.envoyProc, inf.drainTimeout)
	shutdownAccessLog(ctx, inf.accessLog)
	stopDNSProxy(ctx, inf.dnsProxy)

	// Stop the heartbeat goroutine before closing the event store so
	// the final shutdown snapshot can still send through the writer
	// channel.
	if inf.heartbeatStop != nil {
		inf.heartbeatStop()
	}

	err := inf.eventStore.Close() //nolint:contextcheck // shutdown flush must not inherit a cancelable ctx.
	if err != nil {
		slog.DebugContext(ctx, "closing event store on daemon shutdown", slog.Any("err", err))
	}
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
			slog.DebugContext(ctx, "sd_notify close", slog.Any("err", cerr))
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
