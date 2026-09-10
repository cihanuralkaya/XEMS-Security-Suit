package adminapi

import (
	"sync"
	"time"
)

// loginLimiter, kaba-kuvvet (brute-force) parola denemelerine karşı istemci
// başına başarısız giriş denemelerini sayar ve eşiği aşınca geçici kilit uygular.
// Bellek-içidir (süreç başına); çok örnekli dağıtımda ortak bir depo (ör. Redis)
// gerekir — bu, tek örnek için makul bir taban savunmadır.
type loginLimiter struct {
	mu     sync.Mutex
	recs   map[string]*attemptRec
	max    int           // kilit öncesi izin verilen başarısız deneme
	window time.Duration // sayaç penceresi + kilit süresi
	now    func() time.Time
	lastGC time.Time
}

type attemptRec struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{
		recs:   make(map[string]*attemptRec),
		max:    max,
		window: window,
		now:    time.Now,
	}
}

// allowed, verilen anahtar (istemci) için giriş denemesine izin verilip
// verilmediğini döner. Kilitliyse false + kalan süre döner.
func (l *loginLimiter) allowed(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.gc(now)
	r := l.recs[key]
	if r == nil {
		return true, 0
	}
	if now.Before(r.lockedUntil) {
		return false, r.lockedUntil.Sub(now)
	}
	return true, 0
}

// recordFailure, başarısız bir denemeyi kaydeder; eşik aşılırsa kilitler.
// recordFailure, başarısız bir denemeyi kaydeder; eşik aşılırsa kilitler. Bu
// denemeyle YENİ bir kilit başladıysa true döner (kaba-kuvvet uyarısı için).
func (l *loginLimiter) recordFailure(key string) (justLocked bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	r := l.recs[key]
	if r == nil || now.Sub(r.windowStart) > l.window {
		r = &attemptRec{windowStart: now}
		l.recs[key] = r
	}
	r.count++
	if r.count >= l.max {
		r.lockedUntil = now.Add(l.window)
	}
	// Eşiği TAM olarak bu denemede aştıysa YENİ kilit (bir kez uyar).
	return r.count == l.max
}

// recordSuccess, başarılı girişte istemcinin sayacını temizler.
func (l *loginLimiter) recordSuccess(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.recs, key)
}

// gc, süresi geçmiş kayıtları ara sıra temizler (bellek sızıntısını önler).
// Çağıran kilidi tutmalıdır.
func (l *loginLimiter) gc(now time.Time) {
	if now.Sub(l.lastGC) < l.window {
		return
	}
	l.lastGC = now
	for k, r := range l.recs {
		if now.After(r.lockedUntil) && now.Sub(r.windowStart) > l.window {
			delete(l.recs, k)
		}
	}
}
