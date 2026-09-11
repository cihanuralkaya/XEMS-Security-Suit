// Package detectreg, tespit kurallarını (detect.Rule) SÜRÜMLÜ, doğrulanmış ve
// yaşam-döngüsü yönetilen bir KAYIT/DEPO (registry) altında toplar (§44). Böylece
// kurallar sürüm geçmişiyle izlenir, platform/teknik boyutunda sorgulanır ve
// draft→active→retired yaşam-döngüsüyle yönetilir. Bu, kuralların ayrı bir
// repository/registry üzerinden yönetilmesi hedefinin (Detection-as-Code, §20/§44)
// sunucu-içi çekirdeğidir.
//
// Saf-Go; dış bağımlılık yok. Depoyu değiştirmez (bellek-içi katalog).
package detectreg

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"xems.corp/suite/server/internal/detect"
)

// Platform, bir kuralın hedef platform sınıfıdır (kayıt boyutu; detect.Rule'da yok,
// registry meta verisi olarak tutulur).
type Platform string

const (
	PlatformWindows  Platform = "windows"
	PlatformLinux    Platform = "linux"
	PlatformMacOS    Platform = "macos"
	PlatformCloud    Platform = "cloud"
	PlatformIdentity Platform = "identity"
	PlatformNetwork  Platform = "network"
	PlatformAny      Platform = "any"
)

// Entry, kayıttaki tek bir kuraldır: kuralın kendisi + registry meta verisi + sürüm
// geçmişi.
type Entry struct {
	Rule     detect.Rule   `json:"rule"`
	Platform Platform      `json:"platform"`
	AddedAt  time.Time     `json:"added_at"`
	History  []detect.Rule `json:"history,omitempty"` // önceki sürümler (en eski→en yeni)
}

// Registry, kural kimliğine göre kuralları tutar (eşzamanlı-güvenli).
type Registry struct {
	mu   sync.RWMutex
	byID map[string]*Entry
	now  func() time.Time
}

// New, boş bir kayıt kurar. now nil → time.Now.
func New(now func() time.Time) *Registry {
	if now == nil {
		now = time.Now
	}
	return &Registry{byID: map[string]*Entry{}, now: now}
}

// Validate, bir kuralın registry'ye eklenebilir olup olmadığını doğrular: id, name
// ve severity zorunludur; severity bilinen bir düzey olmalıdır.
func Validate(r detect.Rule) error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("detectreg: kural id zorunlu")
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("detectreg: kural adı zorunlu (%s)", r.ID)
	}
	switch strings.ToUpper(strings.TrimSpace(r.Severity)) {
	case "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL":
	default:
		return fmt.Errorf("detectreg: geçersiz severity %q (%s)", r.Severity, r.ID)
	}
	return nil
}

// Upsert, bir kuralı ekler veya (aynı ID varsa) yeni sürüm olarak günceller. Mevcut
// kural, aynı ID ile FARKLI sürümdeyse geçmişe alınır. Doğrulama başarısızsa hata döner.
func (reg *Registry) Upsert(r detect.Rule, platform Platform) error {
	if err := Validate(r); err != nil {
		return err
	}
	if platform == "" {
		platform = PlatformAny
	}
	reg.mu.Lock()
	defer reg.mu.Unlock()
	if e, ok := reg.byID[r.ID]; ok {
		if e.Rule.Version != r.Version && e.Rule.Version != "" {
			e.History = append(e.History, e.Rule) // eski sürümü arşivle
		}
		e.Rule = r
		e.Platform = platform
		return nil
	}
	reg.byID[r.ID] = &Entry{Rule: r, Platform: platform, AddedAt: reg.now()}
	return nil
}

// Get, kimliğe göre kayıt girdisini döner.
func (reg *Registry) Get(id string) (Entry, bool) {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	e, ok := reg.byID[id]
	if !ok {
		return Entry{}, false
	}
	return *e, true
}

// SetStatus, bir kuralın yaşam-döngüsü durumunu değiştirir ("draft"|"active"|"retired").
// Bilinmeyen kural için hata döner.
func (reg *Registry) SetStatus(id, status string) error {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	e, ok := reg.byID[id]
	if !ok {
		return fmt.Errorf("detectreg: kural yok: %s", id)
	}
	e.Rule.Status = status
	return nil
}

// List, tüm girdileri kural kimliğine göre SIRALI döner (deterministik).
func (reg *Registry) List() []Entry {
	reg.mu.RLock()
	defer reg.mu.RUnlock()
	ids := make([]string, 0, len(reg.byID))
	for id := range reg.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]Entry, 0, len(ids))
	for _, id := range ids {
		out = append(out, *reg.byID[id])
	}
	return out
}

// Active, yalnız etkin (Rule.Active()) kuralların detect.Rule dilimini döner —
// doğrudan detect.NewEngine'e verilebilir (üretimde değerlendirilecek set).
// Not: kilit tekrar-girişini önlemek için List() üzerinden yinelenir (List kendi
// kilidini alır); burada ayrıca kilit ALINMAZ.
func (reg *Registry) Active() []detect.Rule {
	var out []detect.Rule
	for _, e := range reg.List() {
		if e.Rule.Active() {
			out = append(out, e.Rule)
		}
	}
	return out
}

// ByPlatform, verilen platforma (veya PlatformAny) ait girdileri döner.
func (reg *Registry) ByPlatform(p Platform) []Entry {
	var out []Entry
	for _, e := range reg.List() {
		if e.Platform == p || e.Platform == PlatformAny {
			out = append(out, e)
		}
	}
	return out
}

// ByTechnique, verilen MITRE teknik kimliğine (ör. "T1059") eşlenen girdileri döner.
func (reg *Registry) ByTechnique(techID string) []Entry {
	var out []Entry
	for _, e := range reg.List() {
		if e.Rule.Technique.ID == techID {
			out = append(out, e)
		}
	}
	return out
}

// Stats, kayıt özetidir (kapsama/gözlem).
type Stats struct {
	Total      int            `json:"total"`
	Active     int            `json:"active"`
	ByPlatform map[string]int `json:"by_platform"`
	ByTactic   map[string]int `json:"by_tactic"`
}

// Stats, kayıt istatistiklerini hesaplar.
func (reg *Registry) Stats() Stats {
	s := Stats{ByPlatform: map[string]int{}, ByTactic: map[string]int{}}
	for _, e := range reg.List() {
		s.Total++
		if e.Rule.Active() {
			s.Active++
		}
		s.ByPlatform[string(e.Platform)]++
		if t := e.Rule.Technique.Tactic; t != "" {
			s.ByTactic[t]++
		}
	}
	return s
}
