// Package ratelimit provides an IP-based token bucket rate limiter
// with amortized eviction of stale entries.
package ratelimit

import (
	"sync"
	"time"
)

const (
	sweepInterval  = 5 * time.Minute
	staleThreshold = 10 * time.Minute
)

// Limiter is an IP-based token bucket rate limiter.
type Limiter struct {
	mu        sync.Mutex
	clients   map[string]*bucket
	rps       float64
	burst     int
	calls     int
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewLimiter creates a rate limiter with the given requests-per-second and burst size.
func NewLimiter(rps float64, burst int) *Limiter {
	return &Limiter{
		clients: make(map[string]*bucket),
		rps:     rps,
		burst:   burst,
	}
}

// Allow reports whether a request from the given key should be allowed.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	l.calls++
	if l.calls%1000 == 0 && now.Sub(l.lastSweep) > sweepInterval {
		l.lastSweep = now
		for k, b := range l.clients {
			if now.Sub(b.last) > staleThreshold {
				delete(l.clients, k)
			}
		}
	}

	b, ok := l.clients[key]
	if !ok {
		l.clients[key] = &bucket{tokens: float64(l.burst - 1), last: now}
		return true
	}

	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rps
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
