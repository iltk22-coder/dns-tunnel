// Package client implements the SOCKS5 proxy and DNS tunnel client.
package client

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// Resolver represents a single DNS resolver with health tracking.
type Resolver struct {
	Addr string

	mu       sync.RWMutex
	failures uint32
	lastFail time.Time
	avgLatMs int64 // stored atomically, milliseconds
}

// IsHealthy returns true if the resolver should accept new connections.
func (r *Resolver) IsHealthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.failures == 0 {
		return true
	}
	// After 30 s cool-down, try again.
	return time.Since(r.lastFail) > 30*time.Second
}

// RecordSuccess updates latency stats and resets the failure counter.
func (r *Resolver) RecordSuccess(lat time.Duration) {
	atomic.StoreInt64(&r.avgLatMs, lat.Milliseconds())
	r.mu.Lock()
	r.failures = 0
	r.mu.Unlock()
}

// RecordFailure increments the failure counter and records when it happened.
func (r *Resolver) RecordFailure() {
	r.mu.Lock()
	r.failures++
	r.lastFail = time.Now()
	r.mu.Unlock()
}

// AvgLatencyMs returns the last recorded average latency in milliseconds.
func (r *Resolver) AvgLatencyMs() int64 {
	return atomic.LoadInt64(&r.avgLatMs)
}

// ResolverPool manages a list of resolvers and distributes connections
// across them in round-robin order, skipping unhealthy ones.
type ResolverPool struct {
	resolvers []*Resolver
	counter   uint64 // atomic round-robin index
}

// NewResolverPool creates a pool from a list of "host:port" addresses.
func NewResolverPool(addrs []string) *ResolverPool {
	rs := make([]*Resolver, len(addrs))
	for i, a := range addrs {
		rs[i] = &Resolver{Addr: a}
	}
	return &ResolverPool{resolvers: rs}
}

// Pick returns a healthy resolver for a new connection.
// It cycles through all resolvers and returns the first healthy one.
// If none are healthy, it returns a random one (fallback).
func (p *ResolverPool) Pick() *Resolver {
	n := uint64(len(p.resolvers))
	if n == 0 {
		return nil
	}
	for i := uint64(0); i < n; i++ {
		idx := atomic.AddUint64(&p.counter, 1) % n
		r := p.resolvers[idx]
		if r.IsHealthy() {
			return r
		}
	}
	// All resolvers are currently marked unhealthy — use a random one anyway.
	return p.resolvers[rand.Intn(int(n))]
}

// All returns all resolvers (for logging / status display).
func (p *ResolverPool) All() []*Resolver {
	return p.resolvers
}
