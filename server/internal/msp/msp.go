// Package msp, çok-kiracılı temelin ÜZERİNE Yönetilen Güvenlik Hizmet Sağlayıcı
// (MSP — Managed Security Service Provider) katmanını ekler. Tek bir MSP, birden
// çok müşteriye hizmet verir; her müşteri bir kiracıya (tenant) eşlenir. Bu paket
// şunları sağlar: müşteri kaydı (Registry), yetki devri + müşteri İZOLASYONU
// (Operator/Scope), müşteri başına yapılandırma (CustomerConfig), kullanım/fatura
// ölçümü (UsageMeter) ve küresel SOC görünümü (GlobalView toplaması). İzolasyon
// sınırı "fail-closed" (bilinmeyen operatör/müşteri = reddet) olacak şekilde
// tasarlanmıştır.
package msp

import (
	"sort"
	"sync"
	"time"
)

// --- 1) Model ve Registry --------------------------------------------------

// Customer, bir MSP müşterisini temsil eder. Her müşteri tam olarak bir kiracıya
// (TenantID) eşlenir ve kendi izolasyon sınırına sahiptir.
type Customer struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	TenantID  string    `json:"tenant_id"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

// CustomerConfig, bir müşteriye özgü çalışma zamanı yapılandırmasını tutar.
type CustomerConfig struct {
	RetentionDays int      `json:"retention_days"`
	Policies      []string `json:"policies"`
	Plan          string   `json:"plan"`
}

// DefaultConfig, yapılandırması bulunmayan bir müşteri için makul varsayılanları
// döner (30 günlük saklama, boş politika listesi, "standard" plan).
func DefaultConfig() CustomerConfig {
	return CustomerConfig{
		RetentionDays: 30,
		Policies:      nil,
		Plan:          "standard",
	}
}

// Registry, MSP müşterilerini ve müşteri başına yapılandırmaları eşzamanlı-güvenli
// biçimde saklayan kayıt defteridir.
type Registry struct {
	mu        sync.RWMutex
	customers map[string]Customer
	configs   map[string]CustomerConfig
}

// NewRegistry, boş bir kayıt defteri oluşturur.
func NewRegistry() *Registry {
	return &Registry{
		customers: make(map[string]Customer),
		configs:   make(map[string]CustomerConfig),
	}
}

// Add, bir müşteriyi ekler veya (aynı ID ile) günceller. Boş ID/TenantID reddedilir
// (ok=false). CreatedAt sıfırsa geçerli zaman atanır.
func (r *Registry) Add(c Customer) (Customer, bool) {
	if c.ID == "" || c.TenantID == "" {
		return Customer{}, false
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.customers[c.ID] = c
	return c, true
}

// Get, verilen kimliğe sahip müşteriyi döner; yoksa ok=false.
func (r *Registry) Get(id string) (Customer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.customers[id]
	return c, ok
}

// List, tüm müşterileri ID'ye göre artan (deterministik) sırada döner.
func (r *Registry) List() []Customer {
	r.mu.RLock()
	out := make([]Customer, 0, len(r.customers))
	for _, c := range r.customers {
		out = append(out, c)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Deactivate, bir müşteriyi pasifleştirir (Active=false). Müşteri silinmez; kayıt
// ve yapılandırma korunur. Bulunamazsa ok=false.
func (r *Registry) Deactivate(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.customers[id]
	if !ok {
		return false
	}
	c.Active = false
	r.customers[id] = c
	return true
}

// SetConfig, bir müşterinin yapılandırmasını ayarlar. Boş ID reddedilir (ok=false).
// Müşterinin Registry'de kayıtlı olması gerekmez.
func (r *Registry) SetConfig(customerID string, cfg CustomerConfig) bool {
	if customerID == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.configs[customerID] = cfg
	return true
}

// GetConfig, bir müşterinin yapılandırmasını döner. Kayıt yoksa DefaultConfig
// (varsayılanlar) döner ve ok=false olur.
func (r *Registry) GetConfig(customerID string) (CustomerConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	cfg, ok := r.configs[customerID]
	if !ok {
		return DefaultConfig(), false
	}
	return cfg, true
}

// --- 2) Yetki devri ve İZOLASYON -------------------------------------------

// Operator, bir SOC operatörüdür. Customers, erişebileceği müşteri kimliklerini
// listeler; liste boşsa operatör MSP-genelindedir (tüm müşterilere erişir).
type Operator struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Customers []string `json:"customers"`
}

// IsGlobal, operatörün MSP-geneli (tüm müşterilere erişen) olup olmadığını döner.
// Boş kimlikli operatör MSP-geneli sayılmaz (fail-closed).
func (op Operator) IsGlobal() bool {
	return op.ID != "" && len(op.Customers) == 0
}

// CanAccess, operatörün belirtilen müşteriye erişip erişemeyeceğini döner. MSP-geneli
// operatör tüm müşterilere erişir; diğerleri yalnız listelerindeki müşterilere.
// Bilinmeyen/boş operatör veya boş müşteri kimliği reddedilir (fail-closed).
func CanAccess(op Operator, customerID string) bool {
	if op.ID == "" || customerID == "" {
		return false
	}
	if op.IsGlobal() {
		return true
	}
	for _, id := range op.Customers {
		if id == customerID {
			return true
		}
	}
	return false
}

// Scope, verilen müşteri kümesinden yalnız operatörün erişebileceklerini, girişteki
// sırayı koruyarak döner. Bu, izolasyon sınırıdır (fail-closed). Bilinmeyen/boş
// operatör için boş dilim döner.
func Scope(op Operator, all []Customer) []Customer {
	out := make([]Customer, 0, len(all))
	if op.ID == "" {
		return out
	}
	for _, c := range all {
		if CanAccess(op, c.ID) {
			out = append(out, c)
		}
	}
	return out
}

// --- 3/4) Kullanım / Fatura ölçümü -----------------------------------------

// Usage, bir müşterinin bir ölçüm penceresindeki kullanım/fatura göstergeleridir.
type Usage struct {
	CustomerID  string    `json:"customer_id"`
	Events      int64     `json:"events"`
	Agents      int       `json:"agents"`
	Incidents   int       `json:"incidents"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
}

// UsageMeter, müşteri başına kullanım göstergelerini eşzamanlı-güvenli biçimde
// biriktiren ölçüm birimidir. Zaman kaynağı test edilebilirlik için enjekte
// edilebilir (now).
type UsageMeter struct {
	mu    sync.Mutex
	now   func() time.Time
	usage map[string]*Usage
}

// NewUsageMeter, boş bir ölçüm birimi oluşturur (UTC zaman kaynağı ile).
func NewUsageMeter() *UsageMeter {
	return &UsageMeter{
		now:   func() time.Time { return time.Now().UTC() },
		usage: make(map[string]*Usage),
	}
}

// entry, bir müşteri için kayıt döner; yoksa pencere başlangıcını ayarlayarak
// oluşturur. Çağıran kilidi tutmalıdır.
func (m *UsageMeter) entry(customerID string) *Usage {
	u, ok := m.usage[customerID]
	if !ok {
		t := m.now()
		u = &Usage{CustomerID: customerID, WindowStart: t, WindowEnd: t}
		m.usage[customerID] = u
	}
	return u
}

// AddEvents, bir müşterinin olay sayacına n ekler (n<=0 ise yok sayılır).
func (m *UsageMeter) AddEvents(customerID string, n int64) {
	if customerID == "" || n <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.entry(customerID)
	u.Events += n
	u.WindowEnd = m.now()
}

// SetAgents, bir müşterinin anlık aktif ajan sayısını ayarlar (negatif yok sayılır).
func (m *UsageMeter) SetAgents(customerID string, agents int) {
	if customerID == "" || agents < 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.entry(customerID)
	u.Agents = agents
	u.WindowEnd = m.now()
}

// AddIncident, bir müşterinin olay (incident) sayacını bir artırır.
func (m *UsageMeter) AddIncident(customerID string) {
	if customerID == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.entry(customerID)
	u.Incidents++
	u.WindowEnd = m.now()
}

// Snapshot, bir müşterinin kullanımının kopyasını döner. Kayıt yoksa yalnız
// CustomerID dolu sıfır-değerli Usage ve ok=false döner.
func (m *UsageMeter) Snapshot(customerID string) (Usage, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.usage[customerID]
	if !ok {
		return Usage{CustomerID: customerID}, false
	}
	return *u, true
}

// SnapshotAll, tüm müşterilerin kullanım kopyalarını CustomerID'ye göre artan
// (deterministik) sırada döner.
func (m *UsageMeter) SnapshotAll() []Usage {
	m.mu.Lock()
	out := make([]Usage, 0, len(m.usage))
	for _, u := range m.usage {
		out = append(out, *u)
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CustomerID < out[j].CustomerID })
	return out
}

// --- 5) Küresel SOC görünümü -----------------------------------------------

// CustomerSummary, küresel toplama için bir müşterinin özet SOC göstergeleridir.
type CustomerSummary struct {
	CustomerID     string `json:"customer_id"`
	OpenIncidents  int    `json:"open_incidents"`
	CriticalAlerts int    `json:"critical_alerts"`
	Agents         int    `json:"agents"`
	RiskScore      int    `json:"risk_score"`
}

// GlobalSummary, tüm müşterilerin toplamını ve riske göre en yüksek N müşteriyi
// (TopRisk) içerir.
type GlobalSummary struct {
	Customers      int               `json:"customers"`
	OpenIncidents  int               `json:"open_incidents"`
	CriticalAlerts int               `json:"critical_alerts"`
	Agents         int               `json:"agents"`
	TopRisk        []CustomerSummary `json:"top_risk"`
}

// AggregateGlobal, müşteri özetlerinden küresel toplamı hesaplar ve riske göre
// (eşitlikte CustomerID ile) azalan sıralanmış en yüksek topN müşteriyi döner.
// topN<=0 ise TopRisk boş döner; topN özet sayısını aşarsa hepsi döner.
func AggregateGlobal(summaries []CustomerSummary, topN int) GlobalSummary {
	g := GlobalSummary{Customers: len(summaries)}
	for _, s := range summaries {
		g.OpenIncidents += s.OpenIncidents
		g.CriticalAlerts += s.CriticalAlerts
		g.Agents += s.Agents
	}
	if topN <= 0 || len(summaries) == 0 {
		g.TopRisk = []CustomerSummary{}
		return g
	}
	sorted := make([]CustomerSummary, len(summaries))
	copy(sorted, summaries)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].RiskScore != sorted[j].RiskScore {
			return sorted[i].RiskScore > sorted[j].RiskScore
		}
		return sorted[i].CustomerID < sorted[j].CustomerID
	})
	if topN > len(sorted) {
		topN = len(sorted)
	}
	g.TopRisk = sorted[:topN]
	return g
}
