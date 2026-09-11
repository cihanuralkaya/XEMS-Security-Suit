package ratelimit

import "sync"

// layered.go — KATMANLI hız sınırlama (§8). Tek bir istek birden çok boyutta
// (global, kiracı, ajan, hedef, API, tehdit-istihbaratı, bildirim) aynı anda
// sınırlanabilir. Herhangi bir katman reddederse istek reddedilir (en kısıtlayıcı
// kazanır). Böylece hem sistemin toplam yükü (global) hem de tekil kiracı/ajan/hedef
// aşırı-yüklenmesi ayrı ayrı kontrol edilir.

// Layer, bir hız-sınırı boyutudur.
type Layer string

const (
	Global       Layer = "global"       // tüm sistem (tek kova)
	Tenant       Layer = "tenant"       // kiracı-başına
	Agent        Layer = "agent"        // ajan/cihaz-başına
	Target       Layer = "target"       // hedef host/IP-başına (tarama)
	API          Layer = "api"          // API istemci/IP-başına
	ThreatIntel  Layer = "threat_intel" // TI sağlayıcı sorgu hızı
	Notification Layer = "notification" // giden bildirim hızı
)

// globalKey, Global katmanının tek kovasının sabit anahtarıdır.
const globalKey = "*"

// Layered, adlandırılmış katmanların birleşimidir. Yapılandırılmamış katman
// atlanır; yapılandırılmış ama anahtarı verilmeyen (Global dışı) katman da atlanır.
type Layered struct {
	mu     sync.RWMutex
	layers map[Layer]*Limiter
}

// NewLayered, boş bir katmanlı sınırlayıcı kurar. Katmanlar SetLayer ile eklenir.
func NewLayered() *Layered {
	return &Layered{layers: map[Layer]*Limiter{}}
}

// SetLayer, bir katmanı yapılandırır (rate/burst). rate<=0 → katman devre dışı
// (o boyutta sınır yok). Var olan katmanı değiştirir.
func (l *Layered) SetLayer(layer Layer, ratePerSec, burst float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.layers[layer] = New(ratePerSec, burst, nil)
}

// Allow, verilen katman→anahtar eşlemesi için TÜM uygulanabilir katmanlardan jeton
// tüketmeye çalışır. Bir katman reddederse (false, o katman) döner ve istek reddedilir.
// Global katman her zaman (anahtar verilmese de) uygulanır. Hiçbir katman reddetmezse
// (true, "") döner.
func (l *Layered) Allow(keys map[Layer]string) (bool, Layer) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	// Deterministik sıra: global önce, sonra diğerleri sabit sırayla.
	order := []Layer{Global, Tenant, Agent, Target, API, ThreatIntel, Notification}
	for _, layer := range order {
		lim, ok := l.layers[layer]
		if !ok {
			continue
		}
		key := keys[layer]
		if layer == Global {
			key = globalKey
		} else if key == "" {
			continue // bu boyutta anahtar yok → katmanı atla
		}
		if !lim.Allow(key) {
			return false, layer
		}
	}
	return true, ""
}
