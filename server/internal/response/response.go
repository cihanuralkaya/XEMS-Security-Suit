// Package response, otomatik müdahale (auto-response) mantığıdır: kritik güvenlik
// olaylarında insan beklemeden cihazı karantinaya alır (SOAR benzeri, hafif).
// Yapılandırma ile açılır (varsayılan kapalı — karantina bozucu bir eylemdir).
package response

import (
	"context"
	"fmt"

	"xems.corp/suite/server/internal/model"
)

// systemActor, otomatik müdahalenin denetim izindeki fail (adminID yerine sistem).
const systemActor = "" // boş → denetim kaydı 'sistem' kaynaklı (created_by NULL)

// Store, otomatik karantina için gereken minimal depo yeteneğidir (backend bunu
// zaten karşılar).
type Store interface {
	EnqueueCommand(ctx context.Context, deviceID, cmdType, issuedBy string) error
	SetDeviceStatus(ctx context.Context, deviceID, status string) error
	WriteAudit(ctx context.Context, adminID, action, targetType, targetID string) error
}

// AutoQuarantiner, kritik olaylara karantina ile yanıt verir.
type AutoQuarantiner struct {
	store Store
}

// New oluşturur.
func New(store Store) *AutoQuarantiner { return &AutoQuarantiner{store: store} }

// AutoQuarantine, cihaza karantina komutu kuyruğa alır, durumu QUARANTINED yapar
// ve denetim izine (sistem kaynaklı) yazar. Komut kuyruğa alınamıyorsa hata döner;
// durum/denetim yazımı best-effort (kritik yol komuttur).
func (a *AutoQuarantiner) AutoQuarantine(ctx context.Context, deviceID, reason string) error {
	if err := a.store.EnqueueCommand(ctx, deviceID, "QUARANTINE", systemActor); err != nil {
		return fmt.Errorf("response: karantina komutu kuyruğa alınamadı: %w", err)
	}
	_ = a.store.SetDeviceStatus(ctx, deviceID, "QUARANTINED")
	_ = a.store.WriteAudit(ctx, systemActor, "AUTO_QUARANTINE", "device", deviceID)
	return nil
}

// ShouldTrigger, bir olay grubunun otomatik karantinayı hak edip etmediğini söyler.
// Tetikleyici: en az bir KRİTİK önem düzeyli olay (kurcalama, sahte güncelleme/
// script reddi, karantina-kaçışı gibi). Tetikleyen ilk olayın mesajı gerekçe olur.
func ShouldTrigger(events []model.Event) (reason string, ok bool) {
	for _, e := range events {
		if e.Severity == "CRITICAL" {
			return e.Message, true
		}
	}
	return "", false
}
