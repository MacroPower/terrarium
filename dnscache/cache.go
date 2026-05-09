package dnscache

import (
	"container/list"
	"net/netip"
	"sync"
	"time"
)

// Default cache bounds. 100k entries at ~96 B/entry caps memory near
// 9 MB under any DNS flood. 16 qnames per IP fits typical CDN fan-out
// (4-8 hostnames per IP) without growing unbounded under a
// many-domains-per-IP attack.
const (
	// DefaultMaxEntries is the global LRU cap.
	DefaultMaxEntries = 100_000

	// DefaultMaxPerIP is the per-IP FIFO cap.
	DefaultMaxPerIP = 16
)

// grace is added to each record's TTL so callers attributing
// kernel-logged packets to a domain can still find a qname when the
// log record lags the resolver decision by several seconds under
// load. Not configurable in v1.
const grace = 10 * time.Minute

// sweepInterval is how often the background sweeper runs. Not
// configurable in v1. Tests drive expiry via the unexported
// pruneOnce hook instead of waiting on the tick.
const sweepInterval = 60 * time.Second

// Cache is a bounded reverse map from destination IP to the most
// recent qname that resolved to it.
//
// Create instances with [New]. The zero value is not usable; the
// background sweeper only starts when a [*Cache] is built through
// [New].
type Cache struct {
	now     func() time.Time
	entries map[netip.Addr]*entry
	lru     *list.List
	stopCh  chan struct{}

	stopWG     sync.WaitGroup
	mu         sync.Mutex
	maxEntries int
	maxPerIP   int
	closed     bool
}

// entry holds the per-IP qname history and a back-pointer to its
// global LRU list element.
type entry struct {
	elem    *list.Element
	records []record
}

// record pairs a stored qname with the wall-clock instant after which
// it is considered expired (TTL + grace).
type record struct {
	expiresAt time.Time
	qname     string
}

// Option configures optional behavior of a [Cache].
//
// The following options are available:
//
//   - [WithMaxEntries]
//   - [WithMaxPerIP]
//   - [WithClock]
type Option func(*Cache)

// WithMaxEntries overrides [DefaultMaxEntries]. Tests use this to
// drive global LRU eviction at small caps without inserting 100k
// entries. Production callers use the default. An [Option].
func WithMaxEntries(n int) Option {
	return func(c *Cache) {
		c.maxEntries = n
	}
}

// WithMaxPerIP overrides [DefaultMaxPerIP]. Tests use this to drive
// per-IP FIFO eviction at small caps. Production callers use the
// default. An [Option].
func WithMaxPerIP(n int) Option {
	return func(c *Cache) {
		c.maxPerIP = n
	}
}

// WithClock replaces the default wall clock with fn. Test-only seam.
// Production callers use real time. An [Option].
func WithClock(fn func() time.Time) Option {
	return func(c *Cache) {
		c.now = fn
	}
}

// New creates a new [*Cache] with the given options applied. The
// background expiry sweeper starts before [New] returns. Callers
// must invoke [Cache.Close] to stop it.
func New(opts ...Option) *Cache {
	c := &Cache{
		now:        time.Now,
		entries:    make(map[netip.Addr]*entry),
		lru:        list.New(),
		maxEntries: DefaultMaxEntries,
		maxPerIP:   DefaultMaxPerIP,
		stopCh:     make(chan struct{}),
	}

	for _, opt := range opts {
		opt(c)
	}

	c.stopWG.Add(1)

	go c.sweepLoop()

	return c
}

// Add records that ip resolved to qname, valid for ttl + grace.
// Empty qname is a no-op. ip is normalized via [netip.Addr.Unmap]
// so 4-byte v4 and v4-mapped-v6 keys collapse to the same canonical
// form. Adding bumps the LRU. If the per-IP slice is full, the
// oldest qname for that IP is FIFO-evicted. If the global cap is
// exceeded, the least-recently-touched IP is evicted whole. After
// [Cache.Close] returns, Add is a no-op.
func (c *Cache) Add(ip netip.Addr, qname string, ttl time.Duration) {
	if qname == "" {
		return
	}

	key := ip.Unmap()
	expiresAt := c.now().Add(ttl + grace)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}

	rec := record{qname: qname, expiresAt: expiresAt}

	e, ok := c.entries[key]
	if !ok {
		elem := c.lru.PushFront(key)
		e = &entry{elem: elem, records: []record{rec}}
		c.entries[key] = e

		c.evictGlobalLocked()

		return
	}

	c.lru.MoveToFront(e.elem)

	// If the qname is already present, move it to the end so it
	// counts as the most recent.
	for i := range e.records {
		if e.records[i].qname != qname {
			continue
		}

		e.records = append(e.records[:i], e.records[i+1:]...)
		e.records = append(e.records, rec)

		return
	}

	if len(e.records) >= c.maxPerIP {
		e.records = e.records[1:]
	}

	e.records = append(e.records, rec)
}

// Lookup returns the most-recently-resolved non-expired qname for
// ip. ip is [netip.Addr.Unmap]-normalized to match the storage key.
// Bumps the entry's LRU position. Returns ok=false on cold or
// fully-expired entries and on a closed [*Cache].
func (c *Cache) Lookup(ip netip.Addr) (string, bool) {
	key := ip.Unmap()

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return "", false
	}

	e, found := c.entries[key]
	if !found {
		return "", false
	}

	now := c.now()

	for i := len(e.records) - 1; i >= 0; i-- {
		if e.records[i].expiresAt.After(now) {
			c.lru.MoveToFront(e.elem)

			return e.records[i].qname, true
		}
	}

	return "", false
}

// Close stops the background expiry sweeper. Idempotent. After
// Close returns, [Cache.Add] is a no-op and [Cache.Lookup] returns
// ok=false.
func (c *Cache) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()

		return
	}

	c.closed = true
	close(c.stopCh)
	c.mu.Unlock()

	c.stopWG.Wait()
}

// evictGlobalLocked drops least-recently-touched IPs until the
// entry count is within the configured cap. Caller holds c.mu.
// The list only ever holds [netip.Addr] values pushed by Add.
func (c *Cache) evictGlobalLocked() {
	for len(c.entries) > c.maxEntries {
		back := c.lru.Back()
		if back == nil {
			return
		}

		c.lru.Remove(back)
		delete(c.entries, back.Value.(netip.Addr))
	}
}

// sweepLoop runs the periodic expiry pass on a background goroutine.
func (c *Cache) sweepLoop() {
	defer c.stopWG.Done()

	t := time.NewTicker(sweepInterval)
	defer t.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-t.C:
			c.pruneOnce()
		}
	}
}

// pruneOnce removes entries whose newest record is past expiresAt.
// Holds c.mu for the full map walk. With maxEntries=100k that costs
// a few ms once per [sweepInterval], blocking concurrent Add/Lookup
// for that window.
func (c *Cache) pruneOnce() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return
	}

	now := c.now()

	for key, e := range c.entries {
		if len(e.records) == 0 {
			c.lru.Remove(e.elem)
			delete(c.entries, key)

			continue
		}

		newest := e.records[len(e.records)-1]
		if !newest.expiresAt.After(now) {
			c.lru.Remove(e.elem)
			delete(c.entries, key)
		}
	}
}
