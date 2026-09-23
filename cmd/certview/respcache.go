package main

import (
	"context"
	"sync"
	"time"
)

// respCache remembers computed responses for ttl. Parallel callers on the
// same key wait for one computation; waiting honours the caller's context,
// and the gate is released before the caller writes its response.
type respCache[T any] struct {
	mu      sync.Mutex
	entries map[string]*respCacheEntry[T]
	ttl     time.Duration
}

type respCacheEntry[T any] struct {
	gate    chan struct{}
	resp    *T
	expires time.Time
}

func newRespCache[T any](ttl time.Duration) *respCache[T] {
	c := &respCache[T]{entries: make(map[string]*respCacheEntry[T]), ttl: ttl}
	go c.cleanupLoop()
	return c
}

// get returns the cached response for key, or computes and caches it; hit
// reports a cached response.
func (c *respCache[T]) get(ctx context.Context, key string, compute func() (*T, error)) (resp *T, hit bool, err error) {
	c.mu.Lock()
	e, ok := c.entries[key]
	if !ok {
		e = &respCacheEntry[T]{gate: make(chan struct{}, 1)}
		c.entries[key] = e
	}
	c.mu.Unlock()

	select {
	case e.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
	defer func() { <-e.gate }()

	if e.resp != nil && time.Now().Before(e.expires) {
		return e.resp, true, nil
	}
	if resp, err = compute(); err != nil {
		return nil, false, err
	}
	e.resp, e.expires = resp, time.Now().Add(c.ttl)
	return resp, false, nil
}

func (c *respCache[T]) cleanupLoop() {
	t := time.NewTicker(max(c.ttl, 5*time.Second))
	defer t.Stop()
	for range t.C {
		now := time.Now()
		c.mu.Lock()
		for k, e := range c.entries {
			select {
			case e.gate <- struct{}{}:
				if !now.Before(e.expires) {
					delete(c.entries, k)
				}
				<-e.gate
			default:
			}
		}
		c.mu.Unlock()
	}
}
