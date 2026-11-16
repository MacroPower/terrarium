package status

import (
	"context"
	"errors"
	"fmt"
	"os"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/eventstore"
)

// collectStats reads a high-level summary of the SQLite event store
// when stats is enabled. Failures land on [StatsSection.Err] so the
// renderer can still produce useful output.
//
// The heartbeat of the summary is the heartbeat of the latest
// instance whose mode has a firewall (see
// [eventstore.Mode.HasFirewall]). A `terrarium proxy` run can write
// to the same store, and its heartbeat does not describe the daemon.
// The instance is the instance of
// [eventstore.Reader.DefaultInstanceID], except in a store that
// holds only proxy runs. The summary then holds no heartbeat, because
// a proxy has no firewall, no firewall log, and no DNS cache to
// report on.
func collectStats(ctx context.Context, cfg *config.Config) StatsSection {
	if cfg == nil || !cfg.StatsEnabled() {
		return StatsSection{}
	}

	dbPath := cfg.StatsPath(config.StatsDBDefault())

	s := StatsSection{
		DBPath:  dbPath,
		Enabled: true,
	}

	info, err := os.Stat(dbPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// DB has not been created yet; that is fine.
		return s
	case err != nil:
		s.Err = fmt.Errorf("stat: %w", err)
		return s

	default:
		s.DBSizeBytes = info.Size()
	}

	r, err := eventstore.OpenReader(ctx, dbPath)
	if err != nil {
		s.Err = fmt.Errorf("opening db: %w", err)
		return s
	}

	defer r.Close() //nolint:errcheck // read-only.

	// The list holds the instance with the latest start first.
	instances, err := r.Instances(ctx)
	if err != nil {
		s.Err = fmt.Errorf("resolving instance: %w", err)
		return s
	}

	// The empty ID selects no heartbeat.
	var instanceID string

	for _, in := range instances {
		if in.Mode.HasFirewall() {
			instanceID = in.ID

			break
		}
	}

	h, err := r.Health(ctx, instanceID)
	if err != nil {
		s.Err = fmt.Errorf("reading health: %w", err)
		return s
	}

	s.Events24h = h.Events24h
	s.LastEvent = h.LastEvent

	if h.HasHeartbeat {
		s.HeartbeatRecordedAt = h.Heartbeat.RecordedAt
		s.NFLogKernelDrops = h.Heartbeat.NFLogKernelDrops
		s.NFLogParseErrors = h.Heartbeat.NFLogParseErrors
		s.NFLogLastEvent = h.Heartbeat.NFLogLastEvent
		s.DNSCacheSize = h.Heartbeat.DNSCacheSize
		s.DNSCacheEvictions = h.Heartbeat.DNSCacheEvictions
		s.EventStoreDropCount = h.Heartbeat.EventStoreDropCount
		s.EventStoreLastWrite = h.Heartbeat.EventStoreLastWrite
	}

	s.FirewallNullDomain1h = h.FirewallNullDomain1h
	s.FirewallEvents1h = h.FirewallEvents1h

	if h.FirewallEvents1h > 0 {
		s.FirewallNullDomainRate1h = float64(h.FirewallNullDomain1h) / float64(h.FirewallEvents1h)
	}

	return s
}
