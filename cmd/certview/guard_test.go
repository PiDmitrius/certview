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
			_, _, results[i] = f.do(ctx, fetchCRL, "http://example.test/ca.crl", "example.test", fetch)
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
