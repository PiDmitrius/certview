package main

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFetchFlightSharesDownload(t *testing.T) {
	f := &fetchFlight{calls: map[string]*fetchCall{}, failed: map[string]failure{}}
	var calls atomic.Int32
	release := make(chan struct{})
	fetch := func(context.Context) ([]byte, string, error) {
		calls.Add(1)
		<-release
		return []byte("crl"), "", nil
	}

	gone, leave := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	results := make([]error, 3)
	for i := range results {
		ctx := context.Background()
		if i == 0 {
			ctx = gone
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, results[i] = f.do(ctx, fetchCRL, "CRL http://example.test/ca.crl", "http://example.test:80", fetch)
		}()
	}
	time.Sleep(50 * time.Millisecond)
	leave()
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if n := calls.Load(); n != 1 {
		t.Fatalf("downloads: got %d, want 1", n)
	}
	if !errors.Is(results[0], context.Canceled) || results[1] != nil || results[2] != nil {
		t.Fatalf("results: %v", results)
	}
}

func TestGuardAnalysisQueuedClientLeaves(t *testing.T) {
	for i := 0; i < cap(slots); i++ {
		slots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(slots); i++ {
			<-slots
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := guardAnalysis(ctx, reqLog{id: 1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("gone client: got %v", err)
	}
}

func TestFetchFlightRemembersFailureForTTL(t *testing.T) {
	f := &fetchFlight{calls: map[string]*fetchCall{}, failed: map[string]failure{}, failTTL: 100 * time.Millisecond}
	var calls atomic.Int32
	fail := func(context.Context) ([]byte, string, error) {
		calls.Add(1)
		return nil, "", errUnreachable
	}
	try := func(urls ...string) {
		for _, url := range urls {
			if _, _, err := f.do(context.Background(), fetchAIA, url, "example.test", fail); err == nil {
				t.Fatal("expected error")
			}
		}
	}
	try("http://example.test/a.crt", "http://example.test/a.crt", "http://example.test/b.crt")
	if n := calls.Load(); n != 1 {
		t.Fatalf("attempts within TTL: got %d, want 1 (same URL and unreachable host are remembered)", n)
	}
	time.Sleep(150 * time.Millisecond)
	try("http://example.test/b.crt")
	if n := calls.Load(); n != 2 {
		t.Fatalf("attempts after TTL: got %d, want 2", n)
	}
}

func TestFetchBudget(t *testing.T) {
	ctx, release, err := guardAnalysis(context.Background(), reqLog{id: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for i := 0; i < maxFetches; i++ {
		if err := spendFetch(ctx); err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
	}
	if err := spendFetch(ctx); !errors.Is(err, errBudget) {
		t.Fatalf("over budget: got %v", err)
	}
}

func TestReadLimited(t *testing.T) {
	if _, err := readLimited(bytes.NewReader(make([]byte, 10)), 11, 10); err == nil {
		t.Fatal("declared length over limit accepted")
	}
	if _, err := readLimited(bytes.NewReader(make([]byte, 11)), -1, 10); err == nil {
		t.Fatal("undeclared body over limit accepted")
	}
	if data, err := readLimited(bytes.NewReader(make([]byte, 10)), -1, 10); err != nil || len(data) != 10 {
		t.Fatalf("body at limit: %d bytes, %v", len(data), err)
	}
}

func TestUsableURLs(t *testing.T) {
	got := usableURLs([]string{"ldap://x", "http://a", "HTTPS://b", "http://c", "http://d"}, 3)
	if want := []string{"http://a", "HTTPS://b", "http://c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestFetchFlightCancelsAbandonedDownload(t *testing.T) {
	f := &fetchFlight{calls: map[string]*fetchCall{}, failed: map[string]failure{}, failTTL: time.Minute}
	stopped := make(chan error, 1)
	fetch := func(fctx context.Context) ([]byte, string, error) {
		<-fctx.Done()
		stopped <- fctx.Err()
		return nil, "", fctx.Err()
	}
	ctx, leave := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		leave()
	}()
	if _, _, err := f.do(ctx, fetchCRL, "CRL http://example.test/a.crl", "http://example.test:80", fetch); !errors.Is(err, context.Canceled) {
		t.Fatalf("waiter: got %v", err)
	}
	select {
	case err := <-stopped:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("download stopped with %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("abandoned download kept running")
	}
	time.Sleep(20 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.failed) != 0 {
		t.Fatalf("abandoned download remembered as failure: %v", f.failed)
	}
}

func TestCRLGateGivesSlotBack(t *testing.T) {
	ctx, release, err := guardAnalysis(context.Background(), reqLog{id: 5})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	bigCRL <- struct{}{}
	held := len(slots)
	done := make(chan func())
	go func() {
		r, err := acquireCRLMemory(ctx, bigCRLSize)
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	time.Sleep(50 * time.Millisecond)
	if len(slots) != held-1 {
		t.Fatalf("slots while waiting for the CRL gate: %d, want %d", len(slots), held-1)
	}
	<-bigCRL
	(<-done)()
	if len(slots) != held {
		t.Fatalf("slots after the CRL gate: %d, want %d", len(slots), held)
	}
}

func TestURLEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"http://CA.example/x.crl":     "http://ca.example:80",
		"https://ca.example/x.crt":    "https://ca.example:443",
		"http://ca.example:1/x":       "http://ca.example:1",
		"http://[2001:db8::1]:8080/x": "http://[2001:db8::1]:8080",
	} {
		if got := urlEndpoint(in); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}

func TestRespCache(t *testing.T) {
	c := newRespCache[int](time.Minute)
	n := 0
	compute := func() (*int, error) { n++; v := n; return &v, nil }
	if _, hit, _ := c.get(context.Background(), "k", compute); hit {
		t.Fatal("first get was a hit")
	}
	if v, hit, _ := c.get(context.Background(), "k", compute); !hit || *v != 1 {
		t.Fatalf("second get: hit=%v v=%d", hit, *v)
	}

	release := make(chan struct{})
	go c.get(context.Background(), "slow", func() (*int, error) { <-release; return new(int), nil })
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := c.get(ctx, "slow", compute); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiter behind a slow computation: got %v", err)
	}
	close(release)
}

func TestCRLGateKeepsSlotWhenQueueFull(t *testing.T) {
	ctx, release, err := guardAnalysis(context.Background(), reqLog{id: 6})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	bigCRL <- struct{}{}
	for i := 0; i < cap(crlQueue); i++ {
		crlQueue <- struct{}{}
	}
	held := len(slots)
	done := make(chan func())
	go func() {
		r, err := acquireCRLMemory(ctx, bigCRLSize)
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	time.Sleep(50 * time.Millisecond)
	if len(slots) != held {
		t.Fatalf("slot given back with a full queue: %d, want %d", len(slots), held)
	}
	for i := 0; i < cap(crlQueue); i++ {
		<-crlQueue
	}
	<-bigCRL
	(<-done)()
}

func TestCRLGateCancelledWhileQueued(t *testing.T) {
	ctx, release, err := guardAnalysis(context.Background(), reqLog{id: 7})
	if err != nil {
		t.Fatal(err)
	}
	bigCRL <- struct{}{}
	held := len(slots)
	cctx, cancel := context.WithCancel(ctx)
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	if _, err := acquireCRLMemory(cctx, bigCRLSize); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	<-bigCRL
	release()
	if len(slots) != held-1 {
		t.Fatalf("slots after cancelled wait and release: %d, want %d", len(slots), held-1)
	}
}

func TestCRLGateNotHeldWhileWaitingForSlot(t *testing.T) {
	ctx, release, err := guardAnalysis(context.Background(), reqLog{id: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	bigCRL <- struct{}{}
	done := make(chan func())
	go func() {
		r, err := acquireCRLMemory(ctx, bigCRLSize)
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	time.Sleep(50 * time.Millisecond)
	free := cap(slots) - len(slots)
	for i := 0; i < free; i++ {
		slots <- struct{}{}
	}
	<-bigCRL
	select {
	case bigCRL <- struct{}{}:
	case <-time.After(time.Second):
		t.Fatal("gate kept while waiting for a slot")
	}
	for i := 0; i < free; i++ {
		<-slots
	}
	time.Sleep(50 * time.Millisecond)
	<-bigCRL
	(<-done)()
}
