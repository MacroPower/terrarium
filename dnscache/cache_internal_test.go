package dnscache

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stepClock is a manually-advanced clock for tests that need
// deterministic expiry. Methods are safe for concurrent use.
type stepClock struct {
	nanos atomic.Int64
}

func newStepClock(t time.Time) *stepClock {
	c := &stepClock{}
	c.nanos.Store(t.UnixNano())

	return c
}

func (c *stepClock) now() time.Time {
	return time.Unix(0, c.nanos.Load())
}

func (c *stepClock) advance(d time.Duration) {
	c.nanos.Add(int64(d))
}

func TestPruneOnceDropsExpiredEntries(t *testing.T) {
	t.Parallel()

	clk := newStepClock(time.Unix(1_700_000_000, 0))
	c := New(WithClock(clk.now))
	t.Cleanup(c.Close)

	ip := netip.MustParseAddr("10.0.0.1")
	c.Add(ip, "example.com.", 30*time.Second)

	// Still inside ttl + grace.
	clk.advance(5 * time.Minute)
	c.pruneOnce()

	c.mu.Lock()
	require.Contains(t, c.entries, ip)
	c.mu.Unlock()

	// Past ttl + grace.
	clk.advance(10 * time.Minute)
	c.pruneOnce()

	c.mu.Lock()

	_, present := c.entries[ip]
	c.mu.Unlock()

	assert.False(t, present, "expired entry should be pruned")
}

func TestPruneOnceClosedCacheNoop(t *testing.T) {
	t.Parallel()

	c := New()
	c.Close()

	// Must not panic on closed cache.
	c.pruneOnce()
}

func TestSweepLoopStopsOnClose(t *testing.T) {
	t.Parallel()

	c := New()

	done := make(chan struct{})
	go func() {
		c.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return; sweeper goroutine leak")
	}
}
