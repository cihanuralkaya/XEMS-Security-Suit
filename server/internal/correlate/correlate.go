// Package correlate, ilişkili tespitleri tek bir OLAYA (incident) gruplar ve
// alarm-fırtınasını bastırır. XDR'ı bir "alarm aracı"ndan ayıran korelasyon
// pilarıdır: aynı cihaz + kural (teknik) için bir zaman penceresinde İLK tespit
// bir incident açar ve alarma izin verir; penceredeki sonraki tekrarlar aynı
// incident'e katlanır ve yinelenen alarm/webhook/SIEM satırı BASTIRILIR.
//
// Durum bellek-içidir (detect eşik-penceresi deseniyle aynı); incident'ler kalıcı
// bir sink'e (memstore/db) yazılır. Çok-düğümde her düğüm kendi penceresini tutar;
// incident kalıcılığı paylaşılır (best-effort — konsol görünürlüğü için yeterli).
package correlate

import (
	"context"
	"sync"
	"time"
)

// IncidentSink, incident'leri kalıcılaştırır (best-effort; ingest yolunu kesmez).
type IncidentSink interface {
	// OpenIncident, yeni bir incident açar ve id'sini döner.
	OpenIncident(ctx context.Context, deviceID, key, ruleID, technique, severity, message string, at time.Time) (string, error)
	// BumpIncident, mevcut bir incident'in son-görülme/sayacını günceller.
	BumpIncident(ctx context.Context, id string, at time.Time) error
}

// noopSink, sink verilmediğinde kullanılır (yalnız bastırma, kalıcılık yok).
type noopSink struct{}

func (noopSink) OpenIncident(context.Context, string, string, string, string, string, string, time.Time) (string, error) {
	return "", nil
}
func (noopSink) BumpIncident(context.Context, string, time.Time) error { return nil }

type window struct {
	incidentID string
	lastSeen   time.Time
}

// Correlator, tespitleri incident'lere gruplar ve tekrarları bastırır.
type Correlator struct {
	mu     sync.Mutex
	window time.Duration
	open   map[string]window // key -> açık pencere
	sink   IncidentSink
	now    func() time.Time
}

// New oluşturur. window <= 0 ise 10 dk kullanılır; sink nil ise yalnız bastırma yapılır.
func New(w time.Duration, sink IncidentSink) *Correlator {
	if w <= 0 {
		w = 10 * time.Minute
	}
	if sink == nil {
		sink = noopSink{}
	}
	return &Correlator{window: w, open: map[string]window{}, sink: sink, now: time.Now}
}

// Observe, bir tespiti korelasyona sokar. suppress=true ise bu tespit penceredeki
// bir incident'in TEKRARIDIR ve alarm gönderilmemelidir (yalnız gruplandı).
// suppress=false ise pencerede İLK'tir; yeni incident açıldı ve alarm gönderilmeli.
// incidentID her iki durumda da ilgili incident'i tanımlar (boş olabilir: sink hatası).
func (c *Correlator) Observe(ctx context.Context, deviceID, ruleID, technique, severity, message string) (incidentID string, suppress bool) {
	key := deviceID + "|" + ruleID
	at := c.now()
	c.mu.Lock()
	// Süresi dolan pencereleri buda (bellek sınırlama).
	for k, w := range c.open {
		if at.Sub(w.lastSeen) > c.window {
			delete(c.open, k)
		}
	}
	w, ok := c.open[key]
	if ok && at.Sub(w.lastSeen) <= c.window {
		w.lastSeen = at
		c.open[key] = w
		id := w.incidentID
		c.mu.Unlock()
		_ = c.sink.BumpIncident(ctx, id, at) // best-effort
		return id, true
	}
	c.mu.Unlock()

	// Pencerede ilk: incident aç.
	id, _ := c.sink.OpenIncident(ctx, deviceID, key, ruleID, technique, severity, message, at)
	c.mu.Lock()
	c.open[key] = window{incidentID: id, lastSeen: at}
	c.mu.Unlock()
	return id, false
}

// OpenCount, o an açık pencere sayısını döner (gözlem/test).
func (c *Correlator) OpenCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.open)
}
