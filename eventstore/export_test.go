package eventstore

import "context"

// RemoveWALIfEmpty exposes removeWALIfEmpty for eventstore_test. It
// skips the check of the `-wal` file that removeEmptyWAL runs first,
// so a test can call it on a `-wal` file that holds frames.
func RemoveWALIfEmpty(ctx context.Context, path string) error {
	return removeWALIfEmpty(ctx, path)
}
