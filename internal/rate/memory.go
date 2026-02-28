package rate

import (
	"sync"
	"time"
)

type bucket struct {
	count int
	start time.Time
}

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]bucket
	lastGC  time.Time
}

func NewLimiter() *Limiter {
	return &Limiter{buckets: map[string]bucket{}, lastGC: time.Now().UTC()}
}

func (l *Limiter) Allow(key string, limit int, window time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now().UTC()
	if now.Sub(l.lastGC) > time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.start) > 3*window {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}
	b, ok := l.buckets[key]
	if !ok || now.Sub(b.start) >= window {
		l.buckets[key] = bucket{count: 1, start: now}
		return true
	}
	if b.count >= limit {
		return false
	}
	b.count++
	l.buckets[key] = b
	return true
}
