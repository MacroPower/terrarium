package eventstore

import (
	"context"
	"time"
)

// RemoveWALIfEmpty exposes removeWALIfEmpty for eventstore_test. It
// skips the check of the `-wal` file that removeEmptyWAL runs first,
// so a test can call it on a `-wal` file that holds frames.
func RemoveWALIfEmpty(ctx context.Context, path string) error {
	return removeWALIfEmpty(ctx, path)
}

// OpenWithoutWriter opens a store as [Open] does, but it does not
// start the writer goroutine. Each heartbeat that the test records
// therefore stays pending, and the test runs a step of the writer
// itself, such as [Store.DrainHeartbeats]. [Store.Close] waits for the
// writer, so the test must call [Store.StartWriter] before Close.
func OpenWithoutWriter(ctx context.Context, path string, opts ...Option) (*Store, error) {
	return open(ctx, path, opts...)
}

// StartWriter starts the writer goroutine of a store that
// [OpenWithoutWriter] opened.
func (s *Store) StartWriter() {
	go s.run()
}

// DrainHeartbeats exposes drainHeartbeats for eventstore_test. The
// writer goroutine must not run during the call, because the two
// share the heartbeat channel and the database connection.
func (s *Store) DrainHeartbeats(last *Heartbeat) {
	s.drainHeartbeats(last)
}

// SetCounters sets the last write and the drop count of the store to
// the values that the writer and [Store.Emit] reach after a commit and
// after dropped events. A zero lastWrite stands for a store without a
// commit.
func (s *Store) SetCounters(lastWrite time.Time, drops int64) {
	s.lastWriteUnix.Store(unixMicroOrZero(lastWrite))
	s.dropCount.Store(drops)
}
