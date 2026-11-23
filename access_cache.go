package account

import (
	"context"
	"crypto/sha256"
	"errors"
	"math/rand/v2"
	"sync"
	"time"
)

// CacheConfig controls the per-Client cache. Zero values select the defaults.
// TTL is a hard upper bound, measured from the start of an Account lookup,
// and cannot exceed one minute. Token/snapshot expiration can shorten it.
type CacheConfig struct {
	Disabled           bool
	TTL                time.Duration
	RefreshInterval    time.Duration
	IdleTimeout        time.Duration
	MaxEntries         int
	RefreshConcurrency int
}

func normalizeCacheConfig(c CacheConfig) (CacheConfig, error) {
	if c.TTL < 0 || c.RefreshInterval < 0 || c.IdleTimeout < 0 || c.MaxEntries < 0 || c.RefreshConcurrency < 0 {
		return c, errors.New("account: cache settings must not be negative")
	}
	if c.TTL == 0 {
		c.TTL = time.Minute
	}
	if c.RefreshInterval == 0 {
		c.RefreshInterval = c.TTL / 2
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 5 * time.Minute
	}
	if c.MaxEntries == 0 {
		c.MaxEntries = 10000
	}
	if c.RefreshConcurrency == 0 {
		c.RefreshConcurrency = 4
	}
	if c.TTL > time.Minute || c.RefreshInterval <= 0 || c.RefreshInterval >= c.TTL {
		return c, errors.New("account: cache requires 0 < refresh interval < TTL <= 1 minute")
	}
	return c, nil
}

type cacheKey struct{ kind, id string }
type cacheLoader func(context.Context) (any, time.Time, error)
type cacheFlight struct {
	done  chan struct{}
	value any
	until time.Time
	err   error
}
type cacheEntry struct {
	value                            any
	denial                           error
	expires, lastAccess, nextRefresh time.Time
	hardExpires                      time.Time
	load                             cacheLoader
	flight                           *cacheFlight
}
type accessCache struct {
	mu              sync.Mutex
	config          CacheConfig
	entries         map[cacheKey]*cacheEntry
	ctx             context.Context
	cancel          context.CancelFunc
	started, closed bool
	slots           chan struct{}
	wg              sync.WaitGroup
	timeout         time.Duration
	inflight        int
}

func newAccessCache(config CacheConfig, timeout time.Duration) *accessCache {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &accessCache{config: config, entries: make(map[cacheKey]*cacheEntry), ctx: ctx, cancel: cancel, slots: make(chan struct{}, config.RefreshConcurrency), timeout: timeout}
}

// Close stops refresh and cancels outstanding cached lookups. Call it when the
// owning service shuts down. It is safe to call concurrently and repeatedly.
func (c *Client) Close() error {
	c.cache.mu.Lock()
	c.cache.closed = true
	c.cache.cancel()
	c.cache.entries = make(map[cacheKey]*cacheEntry)
	c.cache.mu.Unlock()
	c.cache.wg.Wait()
	return nil
}

func tokenCacheKey(kind, token string) cacheKey {
	sum := sha256.Sum256([]byte(token))
	return cacheKey{kind, string(sum[:])}
}

func (c *accessCache) clear() {
	c.mu.Lock()
	c.entries = make(map[cacheKey]*cacheEntry)
	c.mu.Unlock()
}

func (c *accessCache) forget(key cacheKey) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

func (c *accessCache) get(ctx context.Context, key cacheKey, load cacheLoader) (any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, ErrClientClosed
	}
	if c.config.Disabled {
		c.mu.Unlock()
		value, _, err := load(ctx)
		return value, err
	}
	now := time.Now()
	e := c.entries[key]
	if e != nil && now.Sub(e.lastAccess) >= c.config.IdleTimeout {
		delete(c.entries, key)
		e = nil
	}
	if e == nil {
		if len(c.entries) >= c.config.MaxEntries {
			// Prefer evicting an idle entry. In-flight entries retain their slot
			// so a burst of distinct users cannot create unbounded goroutines.
			var oldest *cacheEntry
			var victim cacheKey
			for k, candidate := range c.entries {
				if candidate.flight == nil && (oldest == nil || candidate.lastAccess.Before(oldest.lastAccess)) {
					oldest, victim = candidate, k
				}
			}
			if oldest == nil {
				c.mu.Unlock()
				return nil, ErrCacheCapacity
			}
			delete(c.entries, victim)
		}
		e = &cacheEntry{load: load}
		c.entries[key] = e
	}
	e.lastAccess = now // Only business calls count as activity, never refresh.
	if !c.started {
		c.started = true
		c.wg.Add(1)
		go c.run()
	}
	if (e.value != nil || e.denial != nil) && now.Before(e.expires) {
		value := e.value
		err := e.denial
		c.mu.Unlock()
		return value, err
	}
	if e.flight == nil {
		if !c.startLocked(key, e, false) {
			c.mu.Unlock()
			return nil, ErrCacheCapacity
		}
	}
	f := e.flight
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-f.done:
		if f.err == nil && !time.Now().Before(f.until) {
			return nil, ErrInvalidResponse
		}
		return f.value, f.err
	}
}

// startLocked starts at most one lookup per entry. Background refresh only
// starts when a network slot is available; foreground misses can wait for one.
func (c *accessCache) startLocked(key cacheKey, e *cacheEntry, background bool) bool {
	if c.inflight >= c.config.MaxEntries {
		return false
	}
	if background {
		select {
		case c.slots <- struct{}{}:
		default:
			return false
		}
	}
	f := &cacheFlight{done: make(chan struct{})}
	e.flight = f
	c.inflight++
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
		defer cancel()
		var value any
		var expiration time.Time
		var err error
		acquired := background
		if !acquired {
			select {
			case c.slots <- struct{}{}:
				acquired = true
			case <-ctx.Done():
				err = ctx.Err()
			}
		}
		started := time.Now()
		if acquired {
			value, expiration, err = e.load(ctx)
			<-c.slots
		}
		until := started.Add(c.config.TTL)
		if !expiration.IsZero() && expiration.Before(until) {
			until = expiration
		}
		if err == nil && (value == nil || !time.Now().Before(until)) {
			err = ErrInvalidResponse
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		c.inflight--
		if c.closed {
			err = ErrClientClosed
		} else if c.entries[key] != e {
			err = ErrCacheInvalidated
		} else {
			e.flight = nil
			// Earlier-only jitter spreads requests without extending validity.
			e.nextRefresh = time.Now().Add(c.config.RefreshInterval - time.Duration(rand.Float64()*float64(c.config.RefreshInterval/5)))
			if err == nil {
				e.value, e.expires = value, until
				e.denial = nil
				if key.kind != "permissions" {
					e.hardExpires = expiration
				}
			} else if errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrForbidden) {
				// An explicit rejection immediately removes any previous allow.
				e.value, e.expires, e.denial = nil, started.Add(c.config.TTL), err
			}
		}
		if err != nil {
			value = nil
		}
		f.value, f.until, f.err = value, until, err
		close(f.done)
	}()
	return true
}

func (c *accessCache) run() {
	defer c.wg.Done()
	interval := min(c.config.RefreshInterval/4, c.config.IdleTimeout/4, time.Second)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case now := <-ticker.C:
			c.refreshDue(now)
		}
	}
}

func (c *accessCache) refreshDue(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	for key, e := range c.entries {
		if now.Sub(e.lastAccess) >= c.config.IdleTimeout || (!e.hardExpires.IsZero() && !now.Before(e.hardExpires)) {
			delete(c.entries, key)
			continue
		}
		// Expired tokens cannot be made live by polling. Permission snapshots
		// may expire and be fetched again while their user remains active.
		if e.flight == nil && !now.Before(e.nextRefresh) {
			c.startLocked(key, e, true)
		}
	}
}
