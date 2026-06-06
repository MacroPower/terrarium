package status

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"go.jacobcolvin.com/terrarium/config"
	"go.jacobcolvin.com/terrarium/eventstore"
)

// collectStats reads a high-level summary of the SQLite event store
// when stats is enabled. Failures land on [StatsSection.Err] so the
// renderer can still produce useful output.
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

	db, err := eventstore.OpenReadOnly(ctx, dbPath)
	if err != nil {
		s.Err = fmt.Errorf("opening db: %w", err)
		return s
	}

	defer db.Close() //nolint:errcheck // read-only.

	cutoff := time.Now().Add(-24 * time.Hour).UnixMicro()

	err = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM events WHERE ts >= ?`, cutoff,
	).Scan(&s.Events24h)
	if err != nil {
		s.Err = fmt.Errorf("counting events: %w", err)
		return s
	}

	var maxTS sql.NullInt64

	err = db.QueryRowContext(ctx, `SELECT MAX(ts) FROM events`).Scan(&maxTS)
	if err != nil {
		s.Err = fmt.Errorf("reading last event: %w", err)
		return s
	}

	if maxTS.Valid {
		s.LastEvent = time.UnixMicro(maxTS.Int64)
	}

	instanceID, _, err := eventstore.LatestInstanceID(ctx, db)
	if err != nil {
		s.Err = fmt.Errorf("resolving instance: %w", err)
		return s
	}

	if instanceID != "" {
		hb, ok, err := eventstore.LatestHeartbeat(ctx, db, instanceID)
		if err != nil {
			s.Err = fmt.Errorf("reading heartbeat: %w", err)
			return s
		}

		if ok {
			s.HeartbeatRecordedAt = hb.RecordedAt
			s.NFLogKernelDrops = hb.NFLogKernelDrops
			s.NFLogParseErrors = hb.NFLogParseErrors
			s.NFLogLastEvent = hb.NFLogLastEvent
			s.DNSCacheSize = hb.DNSCacheSize
			s.DNSCacheEvictions = hb.DNSCacheEvictions
			s.EventStoreDropCount = hb.EventStoreDropCount
			s.EventStoreLastWrite = hb.EventStoreLastWrite
		}
	}

	nullCount, totalCount, err := firewallNullDomainCounts(ctx, db, time.Now().Add(-time.Hour))
	if err != nil {
		s.Err = fmt.Errorf("computing null domain rate: %w", err)
		return s
	}

	s.FirewallNullDomain1h = nullCount
	s.FirewallEvents1h = totalCount

	if totalCount > 0 {
		s.FirewallNullDomainRate1h = float64(nullCount) / float64(totalCount)
	}

	return s
}

// firewallNullDomainCounts returns (nullCount, totalCount) for
// firewall-source events with `ts >= cutoff` (cutoff inclusive).
// Uses the existing `events_source_ts` index. Returns (0, 0, nil)
// when there are no firewall events in the window so the caller can
// surface a clean 0/0 rate.
func firewallNullDomainCounts(
	ctx context.Context, db *sql.DB, cutoff time.Time,
) (int64, int64, error) {
	var (
		nullCount  sql.NullInt64
		totalCount int64
	)

	err := db.QueryRowContext(ctx, `
		SELECT
		  SUM(CASE WHEN domain IS NULL THEN 1 ELSE 0 END),
		  COUNT(*)
		FROM events
		WHERE source = ? AND ts >= ?
	`, string(eventstore.SourceFirewall), cutoff.UnixMicro()).Scan(&nullCount, &totalCount)
	if err != nil {
		return 0, 0, fmt.Errorf("scanning firewall null-domain counts: %w", err)
	}

	return nullCount.Int64, totalCount, nil
}
