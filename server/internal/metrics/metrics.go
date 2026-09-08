// Package metrics, sunucu için bağımlılıksız Prometheus metin-exposition üretir.
// Harici bir kütüphane (client_golang) KULLANMAZ — süreç-içi atomik sayaçlar ve
// depodan alınan anlık gauge'lar elle Prometheus 0.0.4 metin formatında yazılır.
// Böylece dağıtılan ikiliye ek bağımlılık girmez (temiz izin-verici lisans
// envanteri korunur).
package metrics

import (
	"fmt"
	"io"
	"runtime"
	"sort"
	"sync/atomic"
	"time"
)

// startTime, süreç başlangıcı (uptime metriği için).
var startTime = time.Now()

// Süreç ömrü boyunca artan sayaçlar (atomik).
var (
	loginSuccess   atomic.Int64
	loginFailure   atomic.Int64
	eventsIngested atomic.Int64
	detections     atomic.Int64
	alertsRaised   atomic.Int64
	autoQuarantine atomic.Int64
	iocHits        atomic.Int64
	// Yatay ölçekleme (#10) küme fan-out sayaçları: yayınlanan (NOTIFY), alınan
	// (LISTEN→yerel dağıtım) ve yerel-dağıtıma-düşülen (NOTIFY başarısız). Fallback
	// sayacının artması DB'ye NOTIFY erişiminde sorun olduğunu gösterir.
	clusterPublished atomic.Int64
	clusterReceived  atomic.Int64
	clusterFallback  atomic.Int64
)

// buildVersion, xems_build_info etiketinde raporlanan sürümdür.
var buildVersion = "dev"

// SetBuildVersion, build bilgisini ayarlar (main tarafından bir kez).
func SetBuildVersion(v string) {
	if v != "" {
		buildVersion = v
	}
}

// Version, raporlanan build sürümünü döner (sağlık ucu vb.).
func Version() string { return buildVersion }

// Counters, süreç-içi sayaçların anlık değerlerini döner (konsol etkinlik kartı
// gibi kimlik-doğrulanmış görünümler için; /metrics ile aynı kaynak).
func Counters() map[string]int64 {
	return map[string]int64{
		"login_success":     loginSuccess.Load(),
		"login_failure":     loginFailure.Load(),
		"events_ingested":   eventsIngested.Load(),
		"detections":        detections.Load(),
		"alerts_raised":     alertsRaised.Load(),
		"auto_quarantine":   autoQuarantine.Load(),
		"ioc_hits":          iocHits.Load(),
		"cluster_published": clusterPublished.Load(),
		"cluster_received":  clusterReceived.Load(),
		"cluster_fallback":  clusterFallback.Load(),
	}
}

// UptimeSeconds, süreç çalışma süresini saniye olarak döner.
func UptimeSeconds() int64 { return int64(time.Since(startTime).Seconds()) }

// IncLoginSuccess / IncLoginFailure, giriş sonucu sayaçlarını artırır.
func IncLoginSuccess() { loginSuccess.Add(1) }
func IncLoginFailure() { loginFailure.Add(1) }

// AddEventsIngested, kabul edilen telemetri olayı sayacını artırır.
func AddEventsIngested(n int) {
	if n > 0 {
		eventsIngested.Add(int64(n))
	}
}

// AddDetections, kural-eşleşmeli tespit sayacını artırır (sunucu-taraflı motor).
func AddDetections(n int) {
	if n > 0 {
		detections.Add(int64(n))
	}
}

// IncAlertRaised, üretilen (SOC'a gönderilmeye aday) uyarı sayacını artırır.
func IncAlertRaised() { alertsRaised.Add(1) }

// IncAutoQuarantine, otomatik karantina (SOAR) sayacını artırır.
func IncAutoQuarantine() { autoQuarantine.Add(1) }

// IncIocHit, tehdit istihbaratı (IoC) eşleşme sayacını artırır.
func IncIocHit() { iocHits.Add(1) }

// IncClusterPublished, kümeye NOTIFY ile yayınlanan bildirim sayacını artırır (#10).
func IncClusterPublished() { clusterPublished.Add(1) }

// IncClusterReceived, LISTEN'den alınıp yerel dağıtılan bildirim sayacını artırır (#10).
func IncClusterReceived() { clusterReceived.Add(1) }

// IncClusterFallback, NOTIFY başarısız olup yerel dağıtıma düşülen sayacını artırır (#10).
func IncClusterFallback() { clusterFallback.Add(1) }

// Snapshot, /metrics çıktısını üretmek için depodan alınan anlık gauge'lardır.
// Sayaçlar (login/olay) paket içinden okunur; gauge'lar çağıran tarafından
// (özet + aktif SSE) doldurulur.
type Snapshot struct {
	DevicesTotal       int
	DevicesOnline      int
	DevicesOffline     int
	DevicesQuarantined int
	EventsBySeverity   map[string]int
	SSEConnections     int
}

// Write, verilen anlık görüntüyü Prometheus metin formatında w'ye yazar.
func Write(w io.Writer, s Snapshot) {
	fmt.Fprintf(w, "# HELP xems_build_info Sürüm bilgisi (etiket).\n")
	fmt.Fprintf(w, "# TYPE xems_build_info gauge\n")
	fmt.Fprintf(w, "xems_build_info{version=%q} 1\n", buildVersion)

	fmt.Fprintf(w, "# HELP xems_login_success_total Başarılı admin girişleri.\n")
	fmt.Fprintf(w, "# TYPE xems_login_success_total counter\n")
	fmt.Fprintf(w, "xems_login_success_total %d\n", loginSuccess.Load())

	fmt.Fprintf(w, "# HELP xems_login_failure_total Başarısız admin giriş denemeleri.\n")
	fmt.Fprintf(w, "# TYPE xems_login_failure_total counter\n")
	fmt.Fprintf(w, "xems_login_failure_total %d\n", loginFailure.Load())

	fmt.Fprintf(w, "# HELP xems_events_ingested_total Kabul edilen telemetri olayları.\n")
	fmt.Fprintf(w, "# TYPE xems_events_ingested_total counter\n")
	fmt.Fprintf(w, "xems_events_ingested_total %d\n", eventsIngested.Load())

	fmt.Fprintf(w, "# HELP xems_detections_total Kural-eşleşmeli sunucu-taraflı tespitler.\n")
	fmt.Fprintf(w, "# TYPE xems_detections_total counter\n")
	fmt.Fprintf(w, "xems_detections_total %d\n", detections.Load())

	fmt.Fprintf(w, "# HELP xems_alerts_raised_total Üretilen SOC uyarıları.\n")
	fmt.Fprintf(w, "# TYPE xems_alerts_raised_total counter\n")
	fmt.Fprintf(w, "xems_alerts_raised_total %d\n", alertsRaised.Load())

	fmt.Fprintf(w, "# HELP xems_auto_quarantine_total Otomatik karantina (SOAR) eylemleri.\n")
	fmt.Fprintf(w, "# TYPE xems_auto_quarantine_total counter\n")
	fmt.Fprintf(w, "xems_auto_quarantine_total %d\n", autoQuarantine.Load())

	fmt.Fprintf(w, "# HELP xems_ioc_hits_total Tehdit istihbaratı (IoC) eşleşmeleri.\n")
	fmt.Fprintf(w, "# TYPE xems_ioc_hits_total counter\n")
	fmt.Fprintf(w, "xems_ioc_hits_total %d\n", iocHits.Load())

	fmt.Fprintf(w, "# HELP xems_cluster_notices_total Küme fan-out bildirimleri (yön etiketli, #10 HA).\n")
	fmt.Fprintf(w, "# TYPE xems_cluster_notices_total counter\n")
	fmt.Fprintf(w, "xems_cluster_notices_total{direction=\"published\"} %d\n", clusterPublished.Load())
	fmt.Fprintf(w, "xems_cluster_notices_total{direction=\"received\"} %d\n", clusterReceived.Load())
	fmt.Fprintf(w, "xems_cluster_notices_total{direction=\"fallback\"} %d\n", clusterFallback.Load())

	fmt.Fprintf(w, "# HELP xems_devices Cihaz sayıları (duruma göre).\n")
	fmt.Fprintf(w, "# TYPE xems_devices gauge\n")
	fmt.Fprintf(w, "xems_devices{state=\"total\"} %d\n", s.DevicesTotal)
	fmt.Fprintf(w, "xems_devices{state=\"online\"} %d\n", s.DevicesOnline)
	fmt.Fprintf(w, "xems_devices{state=\"offline\"} %d\n", s.DevicesOffline)
	fmt.Fprintf(w, "xems_devices{state=\"quarantined\"} %d\n", s.DevicesQuarantined)

	fmt.Fprintf(w, "# HELP xems_events_by_severity Son penceredeki olaylar (önem düzeyine göre).\n")
	fmt.Fprintf(w, "# TYPE xems_events_by_severity gauge\n")
	sevs := make([]string, 0, len(s.EventsBySeverity))
	for k := range s.EventsBySeverity {
		sevs = append(sevs, k)
	}
	sort.Strings(sevs) // deterministik çıktı (test edilebilirlik)
	for _, sev := range sevs {
		fmt.Fprintf(w, "xems_events_by_severity{severity=%q} %d\n", sev, s.EventsBySeverity[sev])
	}

	fmt.Fprintf(w, "# HELP xems_sse_connections Aktif konsol SSE akış bağlantıları.\n")
	fmt.Fprintf(w, "# TYPE xems_sse_connections gauge\n")
	fmt.Fprintf(w, "xems_sse_connections %d\n", s.SSEConnections)

	// Çalışma-zamanı (ops) — bağımlılıksız Go runtime metrikleri.
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fmt.Fprintf(w, "# HELP xems_uptime_seconds Süreç çalışma süresi (saniye).\n")
	fmt.Fprintf(w, "# TYPE xems_uptime_seconds gauge\n")
	fmt.Fprintf(w, "xems_uptime_seconds %d\n", int64(time.Since(startTime).Seconds()))
	fmt.Fprintf(w, "# HELP xems_goroutines Aktif goroutine sayısı.\n")
	fmt.Fprintf(w, "# TYPE xems_goroutines gauge\n")
	fmt.Fprintf(w, "xems_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "# HELP xems_memory_alloc_bytes Ayrılmış heap belleği (bayt).\n")
	fmt.Fprintf(w, "# TYPE xems_memory_alloc_bytes gauge\n")
	fmt.Fprintf(w, "xems_memory_alloc_bytes %d\n", ms.Alloc)
}
