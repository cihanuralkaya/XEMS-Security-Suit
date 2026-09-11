// Package dedup, olay boru-hattı için içerik-adresli YİNELEME TESPİTİ sağlar (§6).
// Aynı olay (ayni EventID) kısa bir pencere içinde yeniden gelirse (ağ retransmit'i,
// çift-gönderim, yeniden-oynatma) bir kez kabul edilir; kopyalar düşürülür. Böylece
// tespit/korelasyon/sayımlar çift-saymaz. §5'in içerik-adresli EventID'si üzerine kurulu.
//
// Eşzamanlı-güvenli, sınırlı bellek: pencere-tabanlı budama + azami boyut (FIFO tahliye).
package dedup

import (
	"sync"
	"time"
)

// Seen, son "window" içinde görülen EventID'leri izler.
type Seen struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	seen   map[string]time.Time // eventID -> ilk görülme
	order  []string             // ekleme sırası (azami boyut aşımında en eskiyi tahliye)
	now    func() time.Time
}

// New, "window" süreli ve en çok "max" girdilik bir yineleme dedektörü kurar.
// window<=0 veya max<=0 ise dedektör devre dışıdır (Duplicate her zaman false döner).
func New(window time.Duration, max int) *Seen {
	return &Seen{
		window: window,
		max:    max,
		seen:   make(map[string]time.Time),
		now:    time.Now,
	}
}

// Duplicate, id daha önce pencere içinde görülmüşse true döner. Aksi halde id'yi
// kaydeder ve false döner (ilk görülme). Boş id asla yineleme sayılmaz.
func (s *Seen) Duplicate(id string) bool {
	if s == nil || s.window <= 0 || s.max <= 0 || id == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.pruneLocked(now)
	if t, ok := s.seen[id]; ok && now.Sub(t) <= s.window {
		return true // pencere içinde tekrar → yineleme
	}
	// İlk görülme (ya da penceresi geçmiş, yeniden kabul).
	if _, existed := s.seen[id]; !existed {
		s.order = append(s.order, id)
	}
	s.seen[id] = now
	// Azami boyut aşıldıysa en eski girdiyi tahliye et.
	for len(s.order) > s.max {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.seen, oldest)
	}
	return false
}

// pruneLocked, penceresi geçmiş girdileri temizler (order sırası ekleme-zamanı artan
// olduğundan baştan budanır). Çağıran kilidi tutmalıdır.
func (s *Seen) pruneLocked(now time.Time) {
	cut := 0
	for cut < len(s.order) {
		id := s.order[cut]
		t, ok := s.seen[id]
		if ok && now.Sub(t) <= s.window {
			break // ilk taze girdi: bundan sonrası da taze (ekleme sırası)
		}
		delete(s.seen, id)
		cut++
	}
	if cut > 0 {
		s.order = s.order[cut:]
	}
}

// Len, izlenen girdi sayısını döner (gözlem/test).
func (s *Seen) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}
