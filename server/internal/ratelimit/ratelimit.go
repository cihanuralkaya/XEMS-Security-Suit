// Package ratelimit, anahtar-başına (ör. istemci IP) token-bucket hız sınırlaması
// sağlar. Ağ-açık uçların (harici log alımı, kayıt) sel/DoS'a karşı korunması için.
// Saf ve testlidir (saat enjekte edilebilir); harici bağımlılık yok.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter, anahtar-başına token-bucket hız sınırlayıcıdır.
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // saniyede yenilenen token
	burst   float64 // tavan (ani-yük payı)
	now     func() time.Time
	buckets map[string]*bucket
	maxKeys int
}

// New oluşturur: ratePerSec token/sn yenilenir, burst tavan. now nil → time.Now.
// rate<=0 → sınır yok (Allow her zaman true; devre dışı).
func New(ratePerSec, burst float64, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	if burst < 1 {
		burst = 1
	}
	return &Limiter{
		rate: ratePerSec, burst: burst, now: now,
		buckets: map[string]*bucket{}, maxKeys: 100000,
	}
}

// Allow, verilen anahtar için bir istek jetonu tüketmeye çalışır. Yeterli jeton
// varsa true (izin), yoksa false (sınır aşıldı). rate<=0 ise her zaman true.
func (l *Limiter) Allow(key string) bool {
	if l.rate <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()

	// Bellek koruması: harita çok büyürse dolu (idle) kovaları at.
	if len(l.buckets) > l.maxKeys {
		l.pruneLocked(now)
	}

	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	// Geçen süreye göre jeton yenile (tavanla sınırlı).
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens -= 1
		return true
	}
	return false
}

// pruneLocked, tam (tokens>=burst) ve bir süredir görülmeyen kovaları siler.
func (l *Limiter) pruneLocked(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens >= l.burst && now.Sub(b.last) > time.Minute {
			delete(l.buckets, k)
		}
	}
}
