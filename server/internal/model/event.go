// Package model, transport (grpc) ve depolama (db) katmanlarının paylaştığı
// nötr domain tiplerini barındırır. Böylece db, transport paketine bağımlı
// olmadan aynı tipleri kullanabilir (bağımlılık yönü tek taraflı kalır).
package model

import "time"

// EventSchemaVersion, KANONİK OLAY ŞEMASININ sürümüdür. Dış tüketiciler (SIEM
// dışa aktarımı, /api/report JSON, /api/events) bu sürüme göre dallanabilir.
// Kanonik olay alanları: sequence (üretici sırası), category, severity, message,
// occurred_at (uçta gözlem anı), created_at (sunucuya ulaşma), device_id (atıf) ve
// details (yapısal ek veri). Alan EKLENDİĞİNDE MINOR, uyumsuz değişiklikte MAJOR
// artırılır (SemVer-benzeri).
const EventSchemaVersion = "1.0"

// Event, kalıcılaştırılacak bir olayın transport-bağımsız biçimidir.
type Event struct {
	Sequence   uint64
	Category   string
	Severity   string
	Message    string
	OccurredAt time.Time
	// Details, olaya iliştirilen yapılandırılmış ek veridir (serbest biçimli JSON
	// nesnesi). Boş string, ayrıntı olmadığını belirtir (DB'de NULL saklanır).
	Details string
}
