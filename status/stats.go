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

	db, err := eventstore.OpenReadOnly(dbPath)
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

	return s
}
