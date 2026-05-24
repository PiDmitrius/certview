package main

import (
	"context"
	"time"
)

const (
	MaxChainLen = 16
	MaxCertSize = 16 << 10
)

type Fetcher interface {
	Name() string
	Available() bool
	Fetch(ctx context.Context, host, ip string, port int, sni string) (*Result, error)
}

type Result struct {
	Chain       [][]byte
	TLSVersion  string
	CipherSuite string
	Duration    time.Duration
}
