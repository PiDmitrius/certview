package main

import (
	"sync"
	"sync/atomic"
	"time"
)

type respCache[T any] struct {
	mu      sync.Mutex
	entries map[string]*respCacheEntry[T]
	ttl     time.Duration
}

type respCacheEntry[T any] struct {
	mu      sync.Mutex // singleflight gate: hold across fresh()/store() to serialize parallel callers on the same key
	resp    *T
	expires atomic.Int64 // unix nano; 0 = no value yet
}

func newRespCache[T any](ttl time.Duration) *respCache[T] {
	c := &respCache[T]{
		entries: make(map[string]*respCacheEntry[T]),
		ttl:     ttl,
	}
	go c.cleanupLoop()
	return c
}

func (c *respCache[T]) entryFor(key string) *respCacheEntry[T] {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		e = &respCacheEntry[T]{}
		c.entries[key] = e
	}
	return e
}

// fresh returns the cached response if it is still valid. Caller must hold e.mu.
func (e *respCacheEntry[T]) fresh() *T {
	if e.resp == nil {
		return nil
	}
	if time.Now().UnixNano() > e.expires.Load() {
		return nil
	}
	return e.resp
}

// store sets the cached response with the given TTL. Caller must hold e.mu.
func (e *respCacheEntry[T]) store(resp *T, ttl time.Duration) {
	e.resp = resp
	e.expires.Store(time.Now().Add(ttl).UnixNano())
}

func (c *respCache[T]) cleanupLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		c.cleanup()
	}
}

func (c *respCache[T]) cleanup() {
	now := time.Now().UnixNano()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if now <= e.expires.Load() {
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
