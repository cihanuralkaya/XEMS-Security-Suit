package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// Bu dosya, BAKIM / BASTIRMA PENCERELERİ sağlar: planlı bakım (yama, dağıtım,
// tarama) sırasında beklenen etkinliğin SOC'u gereksiz uyandırmaması için belirli
// zaman aralıklarında (opsiyonel cihaz/kategori kapsamıyla) uyarılar bastırılır.
// Kritik uyarılar isteğe bağlı olarak yine de geçirilebilir (AllowAbove).
//
// Suppressor bir Notifier dekoratörüdür; nihai alerter'ı SARAR (en dışta) — böylece
// bastırılan uyarılar korelasyon/yükseltmeyi de beslemez.

// Window, tek bir bastırma penceresidir.
type Window struct {
	Start      time.Time
	End        time.Time
	devices    map[string]bool // boş → tüm cihazlar
	categories map[string]bool // boş → tüm kategoriler
	allowAbove int             // bu rank'ın ÜSTÜNDEKİ önem bastırılmaz (0 → hepsi)
	Reason     string
}

// Active, pencerenin verilen anda etkin olup olmadığını döner.
func (w Window) Active(now time.Time) bool {
	return !now.Before(w.Start) && now.Before(w.End)
}

// Matches, verilen anda bu pencerenin uyarıyı bastırıp bastırmayacağını döner.
func (w Window) Matches(now time.Time, a Alert) bool {
	if !w.Active(now) {
		return false
	}
	if w.devices != nil && !w.devices[a.DeviceID] {
		return false
	}
	if w.categories != nil && !w.categories[strings.ToUpper(a.Category)] {
		return false
	}
	// AllowAbove: bu eşiğin ÜSTÜNDEKİ önem bastırılmaz (kritikler geçsin).
	if w.allowAbove > 0 && sevRank(a.Severity) > w.allowAbove {
		return false
	}
	return true
}

// windowJSON, harici yapılandırma şemasıdır.
type windowJSON struct {
	Start      string   `json:"start"`       // RFC3339
	End        string   `json:"end"`         // RFC3339
	Devices    []string `json:"devices"`     // boş → tüm cihazlar
	Categories []string `json:"categories"`  // boş → tüm kategoriler
	AllowAbove string   `json:"allow_above"` // bu önemin üstü bastırılmaz (ör. "HIGH")
	Reason     string   `json:"reason"`
}

// ParseWindows, JSON bir bastırma penceresi dizisini ayrıştırır.
func ParseWindows(data []byte) ([]Window, error) {
	var raw []windowJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("notify: bastırma penceresi JSON çözülemedi: %w", err)
	}
	out := make([]Window, 0, len(raw))
	for i, r := range raw {
		start, err := time.Parse(time.RFC3339, r.Start)
		if err != nil {
			return nil, fmt.Errorf("notify: pencere[%d] start geçersiz: %w", i, err)
		}
		end, err := time.Parse(time.RFC3339, r.End)
		if err != nil {
			return nil, fmt.Errorf("notify: pencere[%d] end geçersiz: %w", i, err)
		}
		if !end.After(start) {
			return nil, fmt.Errorf("notify: pencere[%d] end, start'tan sonra olmalı", i)
		}
		out = append(out, Window{
			Start: start, End: end,
			devices:    newSetRaw(r.Devices), // cihaz kimliği büyük/küçük harf duyarlı
			categories: newSet(r.Categories), // kategori normalize (büyük harf)
			allowAbove: sevRank(r.AllowAbove),
			Reason:     r.Reason,
		})
	}
	return out, nil
}

// WindowHolder, bastırma pencerelerini atomik tutar (canlı hot-reload için).
type WindowHolder struct {
	v atomic.Pointer[[]Window]
}

// NewWindowHolder, başlangıç pencereleriyle bir tutucu oluşturur.
func NewWindowHolder(initial []Window) *WindowHolder {
	h := &WindowHolder{}
	h.Set(initial)
	return h
}

// Set, pencereleri atomik olarak değiştirir (hot-reload).
func (h *WindowHolder) Set(ws []Window) { h.v.Store(&ws) }

// Windows, geçerli pencere kümesini döner.
func (h *WindowHolder) Windows() []Window {
	if p := h.v.Load(); p != nil {
		return *p
	}
	return nil
}

// Suppressor, bir hedef Notifier'ı sarar ve etkin bir bastırma penceresine uyan
// uyarıları DÜŞÜRÜR (onSuppress çağrılır). Pencereler bir sağlayıcıdan (hot-reload
// için) çekilir.
type Suppressor struct {
	target     Notifier
	windows    func() []Window
	onSuppress func()
	now        func() time.Time
}

// NewSuppressor oluşturur. windows nil ise hiçbir şey bastırılmaz. now nil ise
// time.Now. onSuppress nil ise no-op.
func NewSuppressor(target Notifier, windows func() []Window, onSuppress func(), now func() time.Time) *Suppressor {
	if now == nil {
		now = time.Now
	}
	if onSuppress == nil {
		onSuppress = func() {}
	}
	return &Suppressor{target: target, windows: windows, onSuppress: onSuppress, now: now}
}

// Notify, uyarıyı etkin bir pencereye uymuyorsa iletir; uyuyorsa bastırır.
func (s *Suppressor) Notify(a Alert) {
	if s.windows != nil {
		now := s.now()
		for _, w := range s.windows() {
			if w.Matches(now, a) {
				s.onSuppress()
				return
			}
		}
	}
	if s.target != nil {
		s.target.Notify(a)
	}
}
