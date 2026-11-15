package main

import (
	"context"
	"log/slog"
	"time"

	"go.jacobcolvin.com/terrarium/eventstore"
)

// heartbeatCounters adds the counters of the subsystems of a run to h.
// Each heartbeat already holds the counters of the event store.
type heartbeatCounters func(h *eventstore.Heartbeat)

// startHeartbeat records one heartbeat in store and then launches a
// goroutine that records one more every
// [eventstore.HeartbeatInterval]. A reader of the store takes a run
// with an old heartbeat and without an end for a run whose process
// stopped without closing the store. The first heartbeat gives such a
// reader a time to measure from, even for a run that stops in its
// first interval.
//
// The returned [context.CancelFunc] stops the goroutine and records
// one final heartbeat, so that the stored counters are those of the
// shutdown.
//
// Each heartbeat holds the counters of store. A run with more
// subsystems passes counters, which adds their counters. A nil
// counters leaves those counters zero.
//
// It returns a no-op CancelFunc for a nil store, which is the store
// of a run with stats disabled.
func startHeartbeat(ctx context.Context, store *eventstore.Store, counters heartbeatCounters) context.CancelFunc {
	if store == nil {
		return func() {}
	}

	return startHeartbeatEvery(ctx, store, counters, eventstore.HeartbeatInterval)
}

// startHeartbeatEvery is [startHeartbeat] for a store that is not nil
// and with interval as the time between two heartbeats. Tests pass a
// short interval, so that they do not wait for
// [eventstore.HeartbeatInterval].
func startHeartbeatEvery(
	ctx context.Context, store *eventstore.Store, counters heartbeatCounters, interval time.Duration,
) context.CancelFunc {
	hbCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	// Detached so the final snapshot still has a usable context
	// after the heartbeat ctx is canceled. WithoutCancel preserves
	// values while clearing deadline/cancel.
	shutdownCtx := context.WithoutCancel(ctx)

	snapshotHeartbeat(ctx, store, counters)

	go func() {
		defer close(done)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-hbCtx.Done():
				snapshotHeartbeat(shutdownCtx, store, counters)

				return

			case <-ticker.C:
				snapshotHeartbeat(hbCtx, store, counters)
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}
}

// snapshotHeartbeat reads the counters of store, adds those of
// counters, and forwards them to the eventstore writer goroutine via
// [eventstore.Store.RecordHeartbeat].
func snapshotHeartbeat(ctx context.Context, store *eventstore.Store, counters heartbeatCounters) {
	h := eventstore.Heartbeat{
		RecordedAt:          time.Now(),
		EventStoreDropCount: store.DropCount(),
		EventStoreLastWrite: store.LastWriteTime(),
	}

	if counters != nil {
		counters(&h)
	}

	err := store.RecordHeartbeat(ctx, h)
	if err != nil {
		slog.WarnContext(ctx, "heartbeat: recording snapshot", slog.Any("err", err))
	}
}
