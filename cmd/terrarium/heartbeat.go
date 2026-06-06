//go:build linux

package main

import (
	"context"
	"log/slog"
	"time"

	"go.jacobcolvin.com/terrarium/eventstore"
)

// startHeartbeat launches a goroutine that snapshots ingestion-health
// counters from inf into the `instance_metrics` table every
// [eventstore.HeartbeatInterval]. The returned [context.CancelFunc]
// stops the goroutine and runs one final snapshot so the last row
// reflects shutdown counters.
//
// Returns a no-op CancelFunc when stats is disabled (inf.eventStore
// is nil); there is nothing to write to. Tolerates a nil
// nflogReader: in unrestricted mode or with firewall logging
// disabled the corresponding counters land as zeros.
func startHeartbeat(ctx context.Context, inf *infra) context.CancelFunc {
	if inf == nil || inf.eventStore == nil {
		return func() {}
	}

	return startHeartbeatEvery(ctx, inf, eventstore.HeartbeatInterval)
}

// startHeartbeatEvery accepts an arbitrary tick interval; tests
// inject a sub-second value to avoid waiting on the production 60s
// cadence.
func startHeartbeatEvery(ctx context.Context, inf *infra, interval time.Duration) context.CancelFunc {
	hbCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	// Detached so the final snapshot still has a usable context
	// after the heartbeat ctx is canceled. WithoutCancel preserves
	// values while clearing deadline/cancel.
	shutdownCtx := context.WithoutCancel(ctx)

	go func() {
		defer close(done)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-hbCtx.Done():
				snapshotHeartbeat(shutdownCtx, inf)

				return

			case <-ticker.C:
				snapshotHeartbeat(hbCtx, inf)
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}
}

// snapshotHeartbeat reads counters from inf and forwards them to the
// eventstore writer goroutine via [eventstore.Store.RecordHeartbeat].
func snapshotHeartbeat(ctx context.Context, inf *infra) {
	h := eventstore.Heartbeat{
		RecordedAt:          time.Now(),
		EventStoreDropCount: inf.eventStore.DropCount(),
		EventStoreLastWrite: inf.eventStore.LastWriteTime(),
	}

	if inf.nflogReader != nil {
		h.NFLogKernelDrops = inf.nflogReader.KernelDrops()
		h.NFLogParseErrors = inf.nflogReader.ParseErrors()
		h.NFLogLastEvent = inf.nflogReader.LastEventTime()
	}

	if inf.dnsCache != nil {
		h.DNSCacheSize = int64(inf.dnsCache.Size())
		h.DNSCacheEvictions = inf.dnsCache.Evictions()
	}

	err := inf.eventStore.RecordHeartbeat(ctx, h)
	if err != nil {
		slog.WarnContext(ctx, "heartbeat: recording snapshot", slog.Any("err", err))
	}
}
