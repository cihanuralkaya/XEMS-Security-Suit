// Package model, transport (grpc) ve depolama (db) katmanlarının paylaştığı
// nötr domain tiplerini barındırır. Böylece db, transport paketine bağımlı
// olmadan aynı tipleri kullanabilir (bağımlılık yönü tek taraflı kalır).
package model

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// EventSchemaVersion, KANONİK OLAY ŞEMASININ sürümüdür. Dış tüketiciler (SIEM
// dışa aktarımı, /api/report JSON, /api/events) bu sürüme göre dallanabilir.
// Kanonik olay alanları: sequence (üretici sırası), category, severity, message,
// occurred_at (uçta gözlem anı), created_at (sunucuya ulaşma), device_id (atıf) ve
// details (yapısal ek veri). 1.1'de KİMLİK/İLİŞKİ alanları eklendi (event_id, source,
// event_type, confidence, correlation_id, parent_event_id). Alan EKLENDİĞİNDE MINOR,
// uyumsuz değişiklikte MAJOR artırılır (SemVer-benzeri).
const EventSchemaVersion = "1.1"

// Event, kalıcılaştırılacak bir olayın transport-bağımsız biçimidir. Kanonik olay
// modeli (roadmap §5): kimlik + atıf + ilişki alanları ilk-sınıftır. Yeni alanlar
// omitempty ile serileştirilir — 1.0 tüketicileri geriye uyumlu kalır.
type Event struct {
	// EventID, olayın kararlı (içerik-adresli) kimliğidir. Boşsa EnsureID üretir;
	// aynı olay her zaman aynı kimliği verir (yineleme-tespiti / replay idempotensi).
	EventID  string `json:"event_id,omitempty"`
	Sequence uint64 `json:"sequence"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	// OccurredAt, ucun olayı gözlemlediği andır (created_at = sunucuya ulaşma; DB atar).
	OccurredAt time.Time `json:"occurred_at"`
	// Atıf/sınıflandırma (kanonik):
	TenantID   string  `json:"tenant_id,omitempty"`
	DeviceID   string  `json:"device_id,omitempty"`
	Source     string  `json:"source,omitempty"`     // "endpoint" | "syslog" | "cef" | "winevent" | ...
	EventType  string  `json:"event_type,omitempty"` // "PROCESS_CREATE" | "LOGIN_FAILED" | ...
	Confidence float64 `json:"confidence,omitempty"` // 0..1 (tespit/enrichment güveni)
	// İlişki (korelasyon/attack-story/replay temeli):
	CorrelationID string `json:"correlation_id,omitempty"` // aynı olay-örgüsüne ait olayları bağlar
	ParentEventID string `json:"parent_event_id,omitempty"`
	// Details, olaya iliştirilen yapılandırılmış ek veridir (serbest biçimli JSON
	// nesnesi). Boş string, ayrıntı olmadığını belirtir (DB'de NULL saklanır).
	Details string `json:"details,omitempty"`
}

// EnsureID, EventID boşsa içerik-adresli kararlı bir kimlik üretir (SHA-256 özeti;
// tenant|device|sequence|occurred|category|message). Aynı mantıksal olay her çağrıda
// aynı kimliği verir — bu, yineleme-tespiti (§6) ve replay idempotensi (§19) için
// kritiktir. Zaten kimlik varsa dokunmaz.
func (e *Event) EnsureID() string {
	if e.EventID != "" {
		return e.EventID
	}
	h := sha256.New()
	h.Write([]byte(e.TenantID))
	h.Write([]byte{0})
	h.Write([]byte(e.DeviceID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatUint(e.Sequence, 10)))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(e.OccurredAt.UnixNano(), 10)))
	h.Write([]byte{0})
	h.Write([]byte(e.Category))
	h.Write([]byte{0})
	h.Write([]byte(e.Message))
	e.EventID = "evt_" + hex.EncodeToString(h.Sum(nil))[:32]
	return e.EventID
}

// NewCorrelationID, yeni bir olay-örgüsü (korelasyon) kimliği üretir (rastgele).
// Korelasyon/attack-story motoru, ilişkili olayları aynı kimlikle etiketler.
func NewCorrelationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Rastgelelik yoksa zaman-tabanlı geri düşüş (çakışma olasılığı düşük).
		return "cor_" + strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return "cor_" + hex.EncodeToString(b[:])
}
