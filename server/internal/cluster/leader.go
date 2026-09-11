package cluster

import (
	"context"
	"sync"
	"time"
)

// leader.go — YÜKSEK ERİŞİLEBİLİRLİK: kira-tabanlı LİDER SEÇİMİ (§38). Çok-düğümlü
// C2 kümesinde, yalnız-bir-kez çalışması gereken görevler (zamanlanmış raporlar,
// partition/retention bakımı, tekil arka-plan işleri) tek bir LİDER düğümde koşar.
// Lider, paylaşılan bir depoda (LeaseStore — ör. PostgreSQL advisory-lock / lease
// satırı) süreli bir KİRA (lease) tutar ve periyodik yeniler; yenileyemezse (çökme/
// ağ bölünmesi) kira zaman aşımına uğrar ve başka bir düğüm devralır (failover).
//
// Seçim mantığı SAF ve testlidir; depo enjekte edilir (bellek-içi sahte ile test).

// LeaseStore, paylaşılan kira deposudur (DB tarafından uygulanır). Uygulamalar
// atomik olmalıdır: TryAcquire yalnız kira boş/süresi dolmuş ya da zaten bu düğüme
// aitse başarılı olmalıdır.
type LeaseStore interface {
	// TryAcquire, key için nodeID adına ttl süreli kira almayı dener. Kira boşsa,
	// süresi dolmuşsa ya da zaten nodeID'ye aitse acquired=true döner ve kirayı yeniler.
	TryAcquire(ctx context.Context, key, nodeID string, ttl time.Duration) (acquired bool, err error)
	// Release, key kirasını (bu düğüme aitse) serbest bırakır.
	Release(ctx context.Context, key, nodeID string) error
}

// Elector, bir düğümün belirli bir anahtar için liderliğini yönetir.
type Elector struct {
	store    LeaseStore
	key      string
	nodeID   string
	ttl      time.Duration
	renew    time.Duration
	now      func() time.Time
	onChange func(isLeader bool) // liderlik değişiminde çağrılır (opsiyonel)

	mu       sync.RWMutex
	isLeader bool
}

// NewElector, bir seçmen kurar. ttl kira ömrü, renew yenileme aralığı (ttl'den küçük
// olmalı). now nil → time.Now.
func NewElector(store LeaseStore, key, nodeID string, ttl, renew time.Duration, now func() time.Time) *Elector {
	if now == nil {
		now = time.Now
	}
	if renew <= 0 || renew >= ttl {
		renew = ttl / 3
	}
	return &Elector{store: store, key: key, nodeID: nodeID, ttl: ttl, renew: renew, now: now}
}

// OnChange, liderlik durumu değiştiğinde çağrılacak geri-çağrıyı bağlar. Zincirlenebilir.
func (e *Elector) OnChange(f func(isLeader bool)) *Elector { e.onChange = f; return e }

// IsLeader, bu düğümün şu an lider olup olmadığını döner.
func (e *Elector) IsLeader() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isLeader
}

// setLeader, durum değiştiyse günceller ve geri-çağrıyı tetikler.
func (e *Elector) setLeader(v bool) {
	e.mu.Lock()
	changed := e.isLeader != v
	e.isLeader = v
	cb := e.onChange
	e.mu.Unlock()
	if changed && cb != nil {
		cb(v)
	}
}

// Step, tek bir seçim adımı: kira almayı/yenilemeyi dener ve liderlik durumunu günceller.
// Test ve elle tetikleme için dışa açıktır. Depodan hata gelirse (ör. DB erişilemez)
// liderlik GÜVENLİ tarafta bırakılır (step-down) ve hata döner.
func (e *Elector) Step(ctx context.Context) error {
	acquired, err := e.store.TryAcquire(ctx, e.key, e.nodeID, e.ttl)
	if err != nil {
		e.setLeader(false) // fail-closed: kira durumu bilinmiyorsa lider olma
		return err
	}
	e.setLeader(acquired)
	return nil
}

// Run, ctx iptal edilene dek renew aralıklarıyla Step çağırır; çıkarken (liderse)
// kirayı serbest bırakır (temiz devir). Kendi goroutine'inde çalıştırın.
func (e *Elector) Run(ctx context.Context) {
	t := time.NewTicker(e.renew)
	defer t.Stop()
	_ = e.Step(ctx) // ilk deneme hemen
	for {
		select {
		case <-ctx.Done():
			if e.IsLeader() {
				_ = e.store.Release(context.Background(), e.key, e.nodeID)
				e.setLeader(false)
			}
			return
		case <-t.C:
			_ = e.Step(ctx)
		}
	}
}

// MemLeaseStore, tek-süreç içi (test/demo) atomik kira deposudur. Gerçek HA için
// PostgreSQL advisory-lock ya da lease satırı ile uygulanmalıdır.
type MemLeaseStore struct {
	mu     sync.Mutex
	holder map[string]string    // key → nodeID
	expiry map[string]time.Time // key → son geçerlilik
	now    func() time.Time
}

// NewMemLeaseStore, bellek-içi bir kira deposu kurar. now nil → time.Now.
func NewMemLeaseStore(now func() time.Time) *MemLeaseStore {
	if now == nil {
		now = time.Now
	}
	return &MemLeaseStore{holder: map[string]string{}, expiry: map[string]time.Time{}, now: now}
}

func (m *MemLeaseStore) TryAcquire(_ context.Context, key, nodeID string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	h, ok := m.holder[key]
	exp := m.expiry[key]
	// Kira boş, süresi dolmuş ya da zaten bu düğüme ait → al/yenile.
	if !ok || h == "" || !exp.After(now) || h == nodeID {
		m.holder[key] = nodeID
		m.expiry[key] = now.Add(ttl)
		return true, nil
	}
	return false, nil // başka düğüm tutuyor
}

func (m *MemLeaseStore) Release(_ context.Context, key, nodeID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.holder[key] == nodeID {
		delete(m.holder, key)
		delete(m.expiry, key)
	}
	return nil
}
