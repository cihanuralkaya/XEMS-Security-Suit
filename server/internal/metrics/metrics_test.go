package metrics

import (
	"strings"
	"testing"
)

func TestWriteExposition(t *testing.T) {
	SetBuildVersion("1.2.3")
	IncLoginSuccess()
	IncLoginFailure()
	IncLoginFailure()
	AddEventsIngested(5)
	AddDetections(3)
	IncAlertRaised()
	IncAutoQuarantine()
	IncIocHit()
	IncClusterPublished()
	IncClusterPublished()
	IncClusterReceived()
	IncClusterFallback()

	var sb strings.Builder
	Write(&sb, Snapshot{
		DevicesTotal:       10,
		DevicesOnline:      7,
		DevicesOffline:     3,
		DevicesQuarantined: 1,
		EventsBySeverity:   map[string]int{"HIGH": 4, "INFO": 20},
		SSEConnections:     2,
	})
	out := sb.String()

	wants := []string{
		`xems_build_info{version="1.2.3"} 1`,
		"xems_login_success_total 1",
		"xems_login_failure_total 2",
		"xems_events_ingested_total 5",
		"xems_detections_total 3",
		"xems_alerts_raised_total 1",
		"xems_auto_quarantine_total 1",
		"xems_ioc_hits_total 1",
		`xems_cluster_notices_total{direction="published"} 2`,
		`xems_cluster_notices_total{direction="received"} 1`,
		`xems_cluster_notices_total{direction="fallback"} 1`,
		`xems_devices{state="total"} 10`,
		`xems_devices{state="online"} 7`,
		`xems_devices{state="quarantined"} 1`,
		`xems_events_by_severity{severity="HIGH"} 4`,
		`xems_events_by_severity{severity="INFO"} 20`,
		"xems_sse_connections 2",
		"xems_uptime_seconds ",
		"xems_goroutines ",
		"xems_memory_alloc_bytes ",
		"# TYPE xems_login_failure_total counter",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("exposition %q satırını içermeliydi.\n---\n%s", w, out)
		}
	}
	// Önem düzeyi satırları deterministik (alfabetik) sırada olmalı: HIGH < INFO.
	if strings.Index(out, `severity="HIGH"`) > strings.Index(out, `severity="INFO"`) {
		t.Error("önem düzeyi satırları alfabetik sıralı değil")
	}
}
