package server

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// keyedLimiter is one token bucket per key (an address, an IP), with idle
// buckets dropped so the map does not grow with every address ever seen.
type keyedLimiter struct {
	every time.Duration
	burst int

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

func newKeyedLimiter(every time.Duration, burst int) *keyedLimiter {
	return &keyedLimiter{every: every, burst: burst, buckets: map[string]*bucket{}}
}

// allow reports whether one more event is within the key's rate.
func (k *keyedLimiter) allow(key string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := time.Now()
	b, ok := k.buckets[key]
	if !ok {
		if len(k.buckets) >= 10000 {
			k.prune(now)
		}
		b = &bucket{lim: rate.NewLimiter(rate.Every(k.every), k.burst)}
		k.buckets[key] = b
	}
	b.seen = now
	return b.lim.AllowN(now, 1)
}

// prune drops buckets idle long enough to be full again.
func (k *keyedLimiter) prune(now time.Time) {
	idle := k.every * time.Duration(k.burst)
	for key, b := range k.buckets {
		if now.Sub(b.seen) > idle {
			delete(k.buckets, key)
		}
	}
}
