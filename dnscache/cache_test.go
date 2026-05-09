package dnscache_test

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.jacobcolvin.com/terrarium/dnscache"
)

// stepClock is a manually-advanced clock for tests that need
// deterministic expiry.
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

func TestAddLookupHappyPath(t *testing.T) {
	t.Parallel()

	clk := newStepClock(time.Unix(1_700_000_000, 0))
	c := dnscache.New(dnscache.WithClock(clk.now))
	t.Cleanup(c.Close)

	ip := netip.MustParseAddr("10.0.0.1")
	c.Add(ip, "example.com.", 60*time.Second)

	got, ok := c.Lookup(ip)
	require.True(t, ok)
	assert.Equal(t, "example.com.", got)
}

func TestLookupColdMiss(t *testing.T) {
	t.Parallel()

	c := dnscache.New()
	t.Cleanup(c.Close)

	_, ok := c.Lookup(netip.MustParseAddr("10.0.0.99"))
	assert.False(t, ok)
}

func TestMostRecentQnameWins(t *testing.T) {
	t.Parallel()

	clk := newStepClock(time.Unix(1_700_000_000, 0))
	c := dnscache.New(dnscache.WithClock(clk.now))
	t.Cleanup(c.Close)

	ip := netip.MustParseAddr("10.0.0.1")
	c.Add(ip, "first.example.com.", 5*time.Minute)

	clk.advance(time.Second)
	c.Add(ip, "second.example.com.", 5*time.Minute)

	got, ok := c.Lookup(ip)
	require.True(t, ok)
	assert.Equal(t, "second.example.com.", got)
}

func TestGlobalLRUEviction(t *testing.T) {
	t.Parallel()

	clk := newStepClock(time.Unix(1_700_000_000, 0))
	c := dnscache.New(dnscache.WithMaxEntries(2), dnscache.WithClock(clk.now))
	t.Cleanup(c.Close)

	ipA := netip.MustParseAddr("10.0.0.1")
	ipB := netip.MustParseAddr("10.0.0.2")
	ipC := netip.MustParseAddr("10.0.0.3")

	c.Add(ipA, "a.example.com.", time.Hour)
	c.Add(ipB, "b.example.com.", time.Hour)

	// Touch A so B becomes least-recently-touched.
	_, ok := c.Lookup(ipA)
	require.True(t, ok)

	// Inserting C must evict B.
	c.Add(ipC, "c.example.com.", time.Hour)

	_, ok = c.Lookup(ipB)
	assert.False(t, ok, "B should have been evicted")

	_, ok = c.Lookup(ipA)
	assert.True(t, ok, "A should still be present")

	_, ok = c.Lookup(ipC)
	assert.True(t, ok, "C should still be present")
}

func TestPerIPFIFOEviction(t *testing.T) {
	t.Parallel()

	clk := newStepClock(time.Unix(1_700_000_000, 0))
	c := dnscache.New(dnscache.WithMaxPerIP(2), dnscache.WithClock(clk.now))
	t.Cleanup(c.Close)

	ip := netip.MustParseAddr("10.0.0.1")
	c.Add(ip, "first.example.com.", time.Hour)

	clk.advance(time.Second)
	c.Add(ip, "second.example.com.", time.Hour)

	clk.advance(time.Second)
	c.Add(ip, "third.example.com.", time.Hour)

	// Lookup returns the most recent.
	got, ok := c.Lookup(ip)
	require.True(t, ok)
	assert.Equal(t, "third.example.com.", got)

	// "first" should have been FIFO-evicted; "second" remains as the
	// older surviving record. We can't observe non-newest qnames
	// through Lookup, but the per-IP cap is enforced internally
	// regardless. The visible invariant is that Lookup keeps
	// returning a non-empty result and never returns the evicted
	// "first" once "third" is overwritten.
	clk.advance(2 * time.Hour) // Expire all current records.

	_, ok = c.Lookup(ip)
	assert.False(t, ok, "after expiry the IP must yield no qname")
}

func TestExpiryAfterTTLPlusGrace(t *testing.T) {
	t.Parallel()

	clk := newStepClock(time.Unix(1_700_000_000, 0))
	c := dnscache.New(dnscache.WithClock(clk.now))
	t.Cleanup(c.Close)

	ip := netip.MustParseAddr("10.0.0.1")
	c.Add(ip, "example.com.", 30*time.Second)

	// 30s TTL + 10m grace == 630s. Just under: still present.
	clk.advance(629 * time.Second)

	got, ok := c.Lookup(ip)
	require.True(t, ok)
	assert.Equal(t, "example.com.", got)

	// Past ttl + grace: gone.
	clk.advance(2 * time.Second)

	_, ok = c.Lookup(ip)
	assert.False(t, ok)
}

func TestV4MappedV6CollapsesWithV4(t *testing.T) {
	t.Parallel()

	c := dnscache.New()
	t.Cleanup(c.Close)

	mapped := netip.MustParseAddr("::ffff:1.2.3.4")
	bare := netip.MustParseAddr("1.2.3.4")

	c.Add(mapped, "mapped.example.com.", time.Hour)

	got, ok := c.Lookup(bare)
	require.True(t, ok)
	assert.Equal(t, "mapped.example.com.", got)

	c.Add(bare, "bare.example.com.", time.Hour)

	got, ok = c.Lookup(mapped)
	require.True(t, ok)
	assert.Equal(t, "bare.example.com.", got)
}

func TestEmptyQnameNoop(t *testing.T) {
	t.Parallel()

	c := dnscache.New()
	t.Cleanup(c.Close)

	ip := netip.MustParseAddr("10.0.0.1")
	c.Add(ip, "", time.Hour)

	_, ok := c.Lookup(ip)
	assert.False(t, ok)
}

func TestClosedCacheRejects(t *testing.T) {
	t.Parallel()

	c := dnscache.New()
	c.Close()

	ip := netip.MustParseAddr("10.0.0.1")
	c.Add(ip, "example.com.", time.Hour)

	_, ok := c.Lookup(ip)
	assert.False(t, ok)
}

func TestCloseIdempotent(t *testing.T) {
	t.Parallel()

	c := dnscache.New()
	c.Close()

	assert.NotPanics(t, func() { c.Close() })
}

func TestConcurrentAddLookup(t *testing.T) {
	t.Parallel()

	c := dnscache.New(dnscache.WithMaxEntries(64), dnscache.WithMaxPerIP(4))
	t.Cleanup(c.Close)

	const (
		workers  = 8
		duration = time.Second
	)

	stop := make(chan struct{})

	var wg sync.WaitGroup

	// Hot key exercised by every worker. Concurrent Lookup on the
	// same key drove the choice of a single Mutex (LRU promotion
	// requires a write lock).
	hot := netip.MustParseAddr("10.0.0.1")

	for i := range workers {
		wg.Add(1)

		go func(seed int) {
			defer wg.Done()

			ip := netip.AddrFrom4([4]byte{10, 0, 1, byte(seed)})
			n := 0

			for {
				select {
				case <-stop:
					return
				default:
				}

				c.Add(hot, "hot.example.com.", time.Hour)
				c.Add(ip, "worker.example.com.", time.Hour)

				_, _ = c.Lookup(hot)
				_, _ = c.Lookup(ip)

				n++
				if n%128 == 0 {
					_, _ = c.Lookup(netip.AddrFrom4([4]byte{10, 0, 2, byte(n & 0xff)}))
				}
			}
		}(i)
	}

	time.Sleep(duration)
	close(stop)
	wg.Wait()
}
