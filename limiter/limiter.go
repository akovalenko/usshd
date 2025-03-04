package limiter

import (
	"sync"
	"time"
)

type mapEntry struct {
	debt float64
	ts   time.Time
}

type LimiterConfig struct {
	Period time.Duration
	Burst  int
}

type Limiter[K comparable] struct {
	config *LimiterConfig
	mu     sync.Mutex
	m      map[K]*mapEntry
}

func NewLimiter[K comparable](config *LimiterConfig) *Limiter[K] {
	return &Limiter[K]{
		config: config,
		m:      make(map[K]*mapEntry),
	}
}

func (l *Limiter[K]) Allow(key K) bool {
	burst := 1 + float64(l.config.Burst)
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[key]
	if !ok {
		e = &mapEntry{
			ts: now,
		}
		l.m[key] = e
	}
	elapsed := now.Sub(e.ts)
	forgiven := float64(elapsed.Nanoseconds()) / float64(l.config.Period.Nanoseconds())
	if forgiven != 0 {
		if e.debt < forgiven {
			e.debt = 0
		} else {
			e.debt -= forgiven
		}
	}
	e.ts = now

	newDebt := e.debt + 1
	if newDebt > burst {
		return false
	}
	e.debt = newDebt
	return true
}

func (l *Limiter[K]) Gc() {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, e := range l.m {
		elapsed := now.Sub(e.ts)
		forgiven := float64(elapsed.Nanoseconds()) / float64(l.config.Period.Nanoseconds())
		if forgiven >= e.debt {
			delete(l.m, k)
		}
	}
}
