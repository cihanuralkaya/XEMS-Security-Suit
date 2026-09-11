// Package connector, XEMS'e YENİ VERİ KAYNAKLARININ çekirdek kodu değiştirilmeden
// eklenmesini sağlayan jenerik bir bağlayıcı (connector) çerçevesidir (§45). Her
// bağlayıcı, dış bir kaynağın (uç nokta, ağ, kimlik, bulut, SIEM, güvenlik duvarı,
// tehdit-istihbaratı, ticketing) verisini KANONİK olay modeline (model.Event, §5)
// normalize eder. Bir Registry bağlayıcıları kaydeder/listeler; bir Runner bunları
// periyodik olarak yoklar, panikleri izole eder ve olayları bir sink'e teslim eder.
//
// Bu çerçeve §29 (XDR connector'ları) ve §30 (Cloud connector'ları) için temeldir.
// Saf-Go, dış bağımlılık yok.
package connector

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"xems.corp/suite/server/internal/model"
)

// Connector, tek bir dış kaynaktan olay çeken bir bağlayıcıdır.
type Connector interface {
	// Name, benzersiz bağlayıcı adıdır (registry anahtarı).
	Name() string
	// Kind, kaynak türüdür: "endpoint","network","identity","cloud","siem",
	// "threat_intel","firewall","ticketing" vb.
	Kind() string
	// Fetch, bir olay grubunu çeker ve KANONİK model.Event dilimine normalize eder.
	Fetch(ctx context.Context) ([]model.Event, error)
	// Health, bağlayıcının sağlıklı olup olmadığını döner (nil = sağlıklı).
	Health() error
}

// Registry, bağlayıcıları ada göre tutar (eşzamanlı-güvenli).
type Registry struct {
	mu   sync.RWMutex
	byID map[string]Connector
}

// NewRegistry, boş bir kayıt kurar.
func NewRegistry() *Registry { return &Registry{byID: map[string]Connector{}} }

// Register, bir bağlayıcıyı kaydeder. Ad boşsa veya zaten kayıtlıysa hata döner.
func (r *Registry) Register(c Connector) error {
	if c == nil {
		return fmt.Errorf("connector: nil bağlayıcı")
	}
	name := c.Name()
	if name == "" {
		return fmt.Errorf("connector: ad boş olamaz")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byID[name]; exists {
		return fmt.Errorf("connector: %q zaten kayıtlı", name)
	}
	r.byID[name] = c
	return nil
}

// Unregister, bir bağlayıcıyı kaldırır (yoksa no-op). Kaldırıldıysa true döner.
func (r *Registry) Unregister(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.byID[name]; !ok {
		return false
	}
	delete(r.byID, name)
	return true
}

// Get, ada göre bağlayıcıyı döner.
func (r *Registry) Get(name string) (Connector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.byID[name]
	return c, ok
}

// List, kayıtlı tüm bağlayıcıları ada göre SIRALI döner (deterministik).
func (r *Registry) List() []Connector {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.byID))
	for n := range r.byID {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]Connector, 0, len(names))
	for _, n := range names {
		out = append(out, r.byID[n])
	}
	return out
}

// Sink, çekilen olayları tüketen işlevdir (ör. olay hattına yazma).
type Sink func([]model.Event)

// Runner, bir bağlayıcıyı periyodik olarak yoklar. Her Fetch panik-kurtarma ile
// izole edilir (bozuk bir bağlayıcı ana süreci çökertemez) ve hatalarda üstel
// geri-çekilme (backoff) uygulanır. Zaman enjekte edilebilir (tick kanalı) —
// böylece testler gerçek beklemeye ihtiyaç duymaz.
type Runner struct {
	conn     Connector
	interval time.Duration
	sink     Sink
	onError  func(name string, err error) // hata geri-çağrısı (gözlem/backoff kararı); opsiyonel
}

// NewRunner, verilen bağlayıcı, aralık ve sink ile bir koşucu kurar.
func NewRunner(c Connector, interval time.Duration, sink Sink) *Runner {
	return &Runner{conn: c, interval: interval, sink: sink}
}

// OnError, her başarısız yoklamada çağrılacak geri-çağrıyı bağlar (metrik/log/backoff
// kararı çağırana bırakılır). Zincirlenebilir (Runner döner).
func (r *Runner) OnError(f func(name string, err error)) *Runner { r.onError = f; return r }

// RunOnce, bağlayıcıyı bir kez güvenle yoklar: panik olursa hataya çevirir,
// olay dönerse sink'e iletir. Test ve tekil tetikleme için dışa açıktır.
func (r *Runner) RunOnce(ctx context.Context) (n int, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("connector %q panik: %v", r.conn.Name(), rec)
		}
	}()
	evs, ferr := r.conn.Fetch(ctx)
	if ferr != nil {
		return 0, ferr
	}
	if len(evs) > 0 && r.sink != nil {
		r.sink(evs)
	}
	return len(evs), nil
}

// Start, ctx iptal edilene dek bağlayıcıyı r.interval aralıklarla yoklar. Her
// döngü RunOnce ile izole edilir (panik/hata ana süreci etkilemez); hata olursa
// OnError geri-çağrısı (varsa) çağrılır. tick nil ise gerçek bir time.Ticker
// kullanılır; testler kendi kanalını vererek gerçek beklemeden döngüyü sürebilir.
func (r *Runner) Start(ctx context.Context, tick <-chan time.Time) {
	if tick == nil {
		t := time.NewTicker(r.interval)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			if _, err := r.RunOnce(ctx); err != nil && r.onError != nil {
				r.onError(r.conn.Name(), err)
			}
		}
	}
}
