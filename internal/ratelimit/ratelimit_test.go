package ratelimit

import (
	"testing"
	"time"
)

func TestAllow(t *testing.T) {
	l := NewLimiter(10, 10)

	for i := range 10 {
		if !l.Allow("ip1") {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if l.Allow("ip1") {
		t.Fatal("expected denial after burst exhausted")
	}
	if !l.Allow("ip2") {
		t.Fatal("different IP should be allowed")
	}
}

func TestEvictsStaleEntries(t *testing.T) {
	l := NewLimiter(10, 10)

	staleTime := time.Now().Add(-15 * time.Minute)
	l.clients["stale-ip"] = &bucket{tokens: 10, last: staleTime}

	l.calls = 999
	l.lastSweep = time.Now().Add(-10 * time.Minute)

	l.Allow("fresh-ip")

	if _, exists := l.clients["stale-ip"]; exists {
		t.Fatal("expected stale entry to be evicted")
	}
	if _, exists := l.clients["fresh-ip"]; !exists {
		t.Fatal("expected fresh entry to exist")
	}
}
