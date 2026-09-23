package main

// Every analysis runs under guardAnalysis: it holds one of NumCPU slots, is
// cancelled when the client leaves or analyzeTimeout passes, and is watched by
// a watchdog that exits the process (for the container to restart it) when an
// analysis outlives hardTimeout — the only way out of a hang inside C code.
// A parsed CRL costs memory in proportion to its entries, so CRLs above
// bigCRLSize are parsed and processed one at a time. Up to bigCRLQueue
// analyses waiting for that turn give their slot back meanwhile, so raw CRLs
// held in memory stay bounded by slots plus that queue. Request bodies and
// /api/der responses over bigTransferSize are admitted bigTransfers at a time.
//
// External data is untrusted: every fetch is bounded by size and time for its
// kind, an analysis makes at most maxFetches of them, only the first few URLs
// of each kind in a certificate are followed, and a URL that failed — or any
// URL on an endpoint that could not be connected to — is not retried for the
// cache TTL. A shared download is cancelled when its last waiter leaves.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	analyzeTimeout  = 3 * time.Minute
	slotWait        = 30 * time.Second
	hardTimeout     = 10 * time.Minute
	bigCRLSize      = 16 << 20
	bigCRLQueue     = 2
	bigTransfers    = 2
	bigTransferSize = 1 << 20
	derWriteTime    = 5 * time.Minute

	maxCRLSize       = 128 << 20
	maxFetches       = 20
	maxAIAURLs       = 3
	maxCDPURLs       = 3
	maxOCSPURLs      = 2
	maxAIACerts      = 32
	maxAltCandidates = 8
	maxChainDepth    = 10
)

type fetchKind struct {
	name     string
	maxBytes int64
	timeout  time.Duration // 0: only the client's idle and overall timeouts
}

var (
	fetchAIA  = fetchKind{"AIA", 1 << 20, 15 * time.Second}
	fetchCRL  = fetchKind{"CRL", maxCRLSize, 0}
	fetchOCSP = fetchKind{"OCSP", 64 << 10, 15 * time.Second}
)

var (
	errBusy  = errors.New("server busy, try again later")
	slots    = make(chan struct{}, runtime.NumCPU())
	bigCRL   = make(chan struct{}, 1)
	bigIO    = make(chan struct{}, bigTransfers)
	crlQueue = make(chan struct{}, bigCRLQueue)
	running  sync.Map // request id → start time
	inflight = &fetchFlight{calls: map[string]*fetchCall{}, failed: map[string]failure{}}

	errBudget      = fmt.Errorf("fetch budget of %d per analysis exhausted", maxFetches)
	errUnreachable = errors.New("unreachable")
)

type budgetKey struct{}

type slotKey struct{}

// slotHold records whether an analysis currently owns its slot.
type slotHold struct{ held atomic.Bool }

func guardAnalysis(ctx context.Context, rl reqLog) (context.Context, func(), error) {
	wait, stopWait := context.WithTimeout(ctx, slotWait)
	defer stopWait()
	select {
	case slots <- struct{}{}:
	case <-wait.Done():
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		rl.f("busy: no analysis slot within %s", slotWait)
		return nil, nil, errBusy
	}
	running.Store(rl.id, time.Now())
	budget := new(atomic.Int32)
	budget.Store(maxFetches)
	ctx = context.WithValue(ctx, budgetKey{}, budget)
	hold := &slotHold{}
	hold.held.Store(true)
	ctx = context.WithValue(ctx, slotKey{}, hold)
	ctx, cancel := context.WithTimeout(ctx, analyzeTimeout)
	return ctx, func() {
		cancel()
		running.Delete(rl.id)
		if hold.held.Load() {
			<-slots
		}
	}, nil
}

func acquireCRLMemory(ctx context.Context, size int) (func(), error) {
	if size < bigCRLSize {
		return func() {}, nil
	}
	release := func() { <-bigCRL }
	select {
	case bigCRL <- struct{}{}:
		return release, nil
	default:
	}
	hold, _ := ctx.Value(slotKey{}).(*slotHold)
	select {
	case crlQueue <- struct{}{}:
		defer func() { <-crlQueue }()
	default:
		hold = nil
	}
	if hold != nil {
		hold.held.Store(false)
		<-slots
	}
	select {
	case bigCRL <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if hold == nil {
		return release, nil
	}
	// Never wait for a slot while holding the gate: slot holders may be
	// waiting for the gate. Without a free slot, give the gate back, take a
	// slot, then wait for the gate like any slot holder.
	select {
	case slots <- struct{}{}:
		hold.held.Store(true)
		return release, nil
	default:
	}
	release()
	select {
	case slots <- struct{}{}:
		hold.held.Store(true)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case bigCRL <- struct{}{}:
		return release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// acquireBigIO admits a transfer of size bytes (-1 if unknown); small ones
// pass freely. The returned release may be called more than once.
func acquireBigIO(ctx context.Context, size int64) (func(), error) {
	if size >= 0 && size <= bigTransferSize {
		return func() {}, nil
	}
	wait, stop := context.WithTimeout(ctx, slotWait)
	defer stop()
	select {
	case bigIO <- struct{}{}:
		return sync.OnceFunc(func() { <-bigIO }), nil
	case <-wait.Done():
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errBusy
	}
}

func runWatchdog() {
	for range time.Tick(15 * time.Second) {
		running.Range(func(id, start any) bool {
			if age := time.Since(start.(time.Time)); age > hardTimeout {
				log.Printf("watchdog: [r%04d] running for %s, exiting for restart", id, age.Round(time.Second))
				os.Exit(2)
			}
			return true
		})
	}
}

// writeAnalysisError maps guard errors to HTTP; a gone client gets nothing.
func writeAnalysisError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errBusy):
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	case errors.Is(err, context.DeadlineExceeded):
		http.Error(w, "analysis timed out", http.StatusGatewayTimeout)
	case errors.Is(err, context.Canceled):
	default:
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}

func spendFetch(ctx context.Context) error {
	if n, ok := ctx.Value(budgetKey{}).(*atomic.Int32); ok && n.Add(-1) < 0 {
		return errBudget
	}
	return nil
}

// usableURLs returns the first max http(s) URLs.
func usableURLs(urls []string, max int) []string {
	var out []string
	for _, u := range urls {
		if len(out) == max {
			break
		}
		if l := strings.ToLower(u); strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
			out = append(out, u)
		}
	}
	return out
}

func readLimited(r io.Reader, contentLength, max int64) ([]byte, error) {
	if contentLength > max {
		return nil, fmt.Errorf("too large: %d bytes, limit %d", contentLength, max)
	}
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("too large: over %d bytes", max)
	}
	return data, nil
}

// fetchFlight shares one download per key between concurrent requests and
// remembers failures for failTTL. The download itself is bounded by its kind
// and the guarded client's timeouts, not by any single waiter, so one leaving
// client does not fail the others.
type fetchFlight struct {
	mu      sync.Mutex
	calls   map[string]*fetchCall
	failed  map[string]failure
	failTTL time.Duration
}

type failure struct {
	err   error
	until time.Time
}

type fetchCall struct {
	done        chan struct{}
	cancel      context.CancelFunc
	waiters     int
	data        []byte
	contentType string
	err         error
}

// do fetches under key; a failure wrapping errUnreachable also marks the
// endpoint (scheme://host:port).
func (f *fetchFlight) do(ctx context.Context, kind fetchKind, key, endpoint string, fetch func(context.Context) ([]byte, string, error)) ([]byte, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	hostKey := "endpoint " + endpoint
	f.mu.Lock()
	for _, k := range []string{key, hostKey} {
		if fl, ok := f.failed[k]; ok {
			if time.Now().Before(fl.until) {
				f.mu.Unlock()
				return nil, "", fmt.Errorf("failed within the last %s: %w", f.failTTL, fl.err)
			}
			delete(f.failed, k)
		}
	}
	if err := spendFetch(ctx); err != nil {
		f.mu.Unlock()
		return nil, "", err
	}
	c, ok := f.calls[key]
	if !ok {
		fctx, cancel := context.WithCancel(context.Background())
		if kind.timeout > 0 {
			fctx, cancel = context.WithTimeout(fctx, kind.timeout)
		}
		c = &fetchCall{done: make(chan struct{}), cancel: cancel}
		f.calls[key] = c
		go func() {
			c.data, c.contentType, c.err = fetch(fctx)
			abandoned := errors.Is(fctx.Err(), context.Canceled)
			cancel()
			f.mu.Lock()
			if f.calls[key] == c {
				delete(f.calls, key)
			}
			if c.err != nil && !abandoned && f.failTTL > 0 {
				now := time.Now()
				if len(f.failed) >= 4096 {
					for k, fl := range f.failed {
						if now.After(fl.until) {
							delete(f.failed, k)
						}
					}
				}
				f.failed[key] = failure{c.err, now.Add(f.failTTL)}
				if errors.Is(c.err, errUnreachable) {
					f.failed[hostKey] = failure{c.err, now.Add(f.failTTL)}
				}
			}
			f.mu.Unlock()
			close(c.done)
		}()
	}
	c.waiters++
	f.mu.Unlock()
	select {
	case <-c.done:
		return c.data, c.contentType, c.err
	case <-ctx.Done():
		f.mu.Lock()
		if c.waiters--; c.waiters == 0 {
			c.cancel()
			if f.calls[key] == c {
				delete(f.calls, key)
			}
		}
		f.mu.Unlock()
		return nil, "", ctx.Err()
	}
}
