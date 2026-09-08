// Package quarantine, ağ izolasyonunu (karantina) yönetir: kritik bir anomali
// veya ağır politika ihlalinde cihazın diğer lokal makinelerle iletişimi kesilir
// ve yalnız C2 sunucusuyla haberleşebilir hale getirilir (mimari 4.4).
//
// Gerçek firewall müdahalesi OS'e özgüdür ve Isolator arayüzünün arkasındadır
// (Windows: netsh, Linux: iptables). Buradaki Manager platformdan bağımsızdır,
// idempotenttir ve sahte izolatörle test edilebilir.
package quarantine

import (
	"sync"
	"time"

	"xems.corp/suite/agent/internal/collector"
)

// Isolator, OS'e özgü ağ izolasyonunu uygular.
type Isolator interface {
	// Isolate, tüm ağ iletişimini keser; yalnız allowC2 adreslerine izin verir.
	Isolate(allowC2 []string) error
	// Release, izolasyonu kaldırır (XEMS kurallarını siler).
	Release() error
}

// Manager, karantina durumunu izler ve geçişleri olay olarak raporlar.
type Manager struct {
	iso     Isolator
	buf     *collector.Buffer
	c2Allow []string

	mu     sync.Mutex
	active bool
}

// NewManager oluşturur. c2Allow, izolasyon sırasında erişime izin verilecek C2
// adres(ler)idir.
func NewManager(iso Isolator, buf *collector.Buffer, c2Allow []string) *Manager {
	return &Manager{iso: iso, buf: buf, c2Allow: c2Allow}
}

// Apply, cihazı karantinaya alır. İdempotenttir: zaten karantinadaysa hiçbir şey
// yapmaz. Başarılı geçişte SECURITY/HIGH, başarısızlıkta SECURITY/CRITICAL üretir.
func (m *Manager) Apply() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active {
		return nil
	}
	if err := m.iso.Isolate(m.c2Allow); err != nil {
		m.emit("CRITICAL", "karantina UYGULANAMADI: "+err.Error())
		return err
	}
	m.active = true
	m.emit("HIGH", "cihaz karantinaya alındı (yalnız C2 ile iletişim)")
	return nil
}

// Release, izolasyonu kaldırır. İdempotenttir.
func (m *Manager) Release() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return nil
	}
	if err := m.iso.Release(); err != nil {
		m.emit("CRITICAL", "karantina KALDIRILAMADI: "+err.Error())
		return err
	}
	m.active = false
	m.emit("HIGH", "karantina kaldırıldı")
	return nil
}

// Active, cihazın şu an karantinada olup olmadığını döner.
func (m *Manager) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

func (m *Manager) emit(severity, message string) {
	m.buf.Add(collector.Event{
		Category:   "SECURITY",
		Severity:   severity,
		Message:    message,
		OccurredAt: time.Now(),
	})
}
