package ratelimit

import "sync"

// adaptive.go — UYARLANIR (adaptive) backpressure (§8). Aşağı-akış (hedef sistem,
// TI sağlayıcı, DB) baskı sinyali verdiğinde (429/503/timeout) eşzamanlılık sınırı
// çarpımsal olarak DÜŞÜRÜLÜR; sürekli başarıda toplamsal olarak YÜKSELTİLİR (AIMD —
// TCP tıkanıklık kontrolüne benzer). Böylece XEMS hedefleri aşırı yüklemez, WAF/IDS
// tetiklemesini azaltır ve kendi kaynağını korur. Saf ve testli; saat gerektirmez.

// Result, bir aşağı-akış çağrısının gözlemlenen sonucudur.
type Result int

const (
	Success  Result = iota // başarılı
	Overload               // 429/503 (hedef aşırı yüklü)
	Timeout                // zaman aşımı / bağlantı hatası
)

// Adaptive, AIMD ile ayarlanan sınırlı-eşzamanlılık kontrolörüdür.
type Adaptive struct {
	mu            sync.Mutex
	min, max      int // sınır aralığı
	limit         int // güncel eşzamanlılık sınırı
	inflight      int // o an devam eden çağrı sayısı
	successStreak int // ard arda başarı (toplamsal artış için)
	increaseEvery int // kaç başarıda +1 (varsayılan 10)
}

// NewAdaptive, [min,max] aralığında bir kontrolör kurar (başlangıç sınırı = max).
// min<1 → 1; max<min → min.
func NewAdaptive(min, max int) *Adaptive {
	if min < 1 {
		min = 1
	}
	if max < min {
		max = min
	}
	return &Adaptive{min: min, max: max, limit: max, increaseEvery: 10}
}

// TryAcquire, güncel sınır aşılmıyorsa bir yer ayırır (inflight++) ve true döner;
// aksi halde false (backpressure — çağıran beklemeli/kuyruğa almalı/düşürmeli).
func (a *Adaptive) TryAcquire() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inflight >= a.limit {
		return false
	}
	a.inflight++
	return true
}

// Release, TryAcquire ile alınan yeri geri verir (inflight--). Genelde defer'le.
func (a *Adaptive) Release() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.inflight > 0 {
		a.inflight--
	}
}

// Observe, bir çağrı sonucunu geri besler ve sınırı AIMD ile ayarlar:
//   - Overload/Timeout → sınır = max(min, sınır/2) (çarpımsal azalış), seri sıfırlanır.
//   - Success → seri++; increaseEvery'e ulaşınca sınır = min(max, sınır+1) (toplamsal artış).
func (a *Adaptive) Observe(r Result) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch r {
	case Overload, Timeout:
		a.successStreak = 0
		a.limit /= 2
		if a.limit < a.min {
			a.limit = a.min
		}
	case Success:
		a.successStreak++
		if a.successStreak >= a.increaseEvery {
			a.successStreak = 0
			if a.limit < a.max {
				a.limit++
			}
		}
	}
}

// Limit, güncel eşzamanlılık sınırını döner (gözlem/metrik).
func (a *Adaptive) Limit() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.limit
}

// Inflight, o an devam eden çağrı sayısını döner (gözlem/metrik).
func (a *Adaptive) Inflight() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.inflight
}
