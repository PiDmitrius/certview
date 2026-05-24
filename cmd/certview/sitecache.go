package main

import (
	"sync"
	"sync/atomic"
	"time"
)

type siteCache struct {
	mu      sync.Mutex
	entries map[string]*siteCacheEntry
	ttl     time.Duration
}

type siteCacheEntry struct {
	mu      sync.Mutex // singleflight gate: hold across fresh()/store() to serialize parallel callers on the same key
	resp    *siteResponse
	expires atomic.Int64 // unix nano; 0 = no value yet
}

func newSiteCache(ttl time.Duration) *siteCache {
	c := &siteCache{
		entries: make(map[string]*siteCacheEntry),
		ttl:     ttl,
	}
	if ttl > 0 {
		go c.cleanupLoop()
	}
	return c
}

func (c *siteCache) entryFor(key string) *siteCacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		e = &siteCacheEntry{}
		c.entries[key] = e
	}
	return e
}

// fresh returns the cached response if it is still valid. Caller must hold e.mu.
func (e *siteCacheEntry) fresh() *siteResponse {
	if e.resp == nil {
		return nil
	}
	if time.Now().UnixNano() > e.expires.Load() {
		return nil
	}
	return e.resp
}

// store sets the cached response with the given TTL. Caller must hold e.mu.
func (e *siteCacheEntry) store(resp *siteResponse, ttl time.Duration) {
	e.resp = resp
	e.expires.Store(time.Now().Add(ttl).UnixNano())
}

func (c *siteCache) cleanupLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		c.cleanup()
	}
}

func (c *siteCache) cleanup() {
	now := time.Now().UnixNano()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		exp := e.expires.Load()
		if exp == 0 || now <= exp {
			continue
		}
		// If a fetcher holds the per-key mutex right now, leave the entry
		// alone — deleting it would break the singleflight invariant (the
		// in-flight goroutine would then store its response into an entry
		// that's no longer in the map, and a concurrent caller would create
		// a fresh entry and issue a duplicate fetch).
		if !e.mu.TryLock() {
			continue
		}
		delete(c.entries, k)
		e.mu.Unlock()
	}
}
