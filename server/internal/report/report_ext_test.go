package report

import (
	"strings"
	"testing"
	"time"
)

func sampleExtData() Data {
	return Data{
		GeneratedAt:  time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC),
		TenantID:     "acme",
		DevicesTotal: 100, DevicesOnline: 80, DevicesOffline: 20, DevicesQuarantined: 3,
		NonCompliant: 10, Detections: 42, AlertsRaised: 12, IocHits: 5,
		EventsBySeverity: map[string]int{"CRITICAL": 2, "HIGH": 8, "LOW": 30},
		TopIncidents: []Incident{
			{DeviceID: "d1", RuleID: "XEMS-0001", Severity: "HIGH", Count: 4, LastSeen: time.Now()},
			{DeviceID: "d2", RuleID: "XEMS-0002", Severity: "CRITICAL", Count: 9, LastSeen: time.Now()},
		},
	}
}

func TestRenderMarkdownTechnical(t *testing.T) {
	md := RenderMarkdown(sampleExtData(), KindTechnical)
	for _, want := range []string{"# Teknik Güvenlik Raporu", "## Filo durumu", "## Tehdit etkinliği",
		"## Önem dağılımı", "| CRITICAL | 2 |", "## Öne çıkan olaylar", "XEMS-0002", "kiracı: acme"} {
		if !strings.Contains(md, want) {
			t.Errorf("technical markdown %q içermeli", want)
		}
	}
}

func TestRenderMarkdownExecutive(t *testing.T) {
	md := RenderMarkdown(sampleExtData(), KindExecutive)
	if !strings.Contains(md, "# Yönetici Güvenlik Özeti") {
		t.Error("executive başlığı")
	}
	if !strings.Contains(md, "## Değerlendirme") {
		t.Error("executive değerlendirme bölümü içermeli")
	}
	// executive teknik önem-dağılımını içermez
	if strings.Contains(md, "## Önem dağılımı") {
		t.Error("executive önem-dağılımı içermemeli")
	}
}

func TestRenderMarkdownIncident(t *testing.T) {
	md := RenderMarkdown(sampleExtData(), KindIncident)
	// incident filo KPI bloğunu içermez, olayları içerir
	if strings.Contains(md, "## Filo durumu") {
		t.Error("incident filo durumu içermemeli")
	}
	if !strings.Contains(md, "## Öne çıkan olaylar") {
		t.Error("incident olayları içermeli")
	}
}

func TestTopOSByCount(t *testing.T) {
	got := TopOSByCount(map[string]int{"win": 5, "linux": 5, "mac": 9})
	if got[0].OS != "mac" || got[0].Count != 9 {
		t.Fatalf("en yüksek mac olmalı: %+v", got[0])
	}
	// eşit sayıda alfabetik (linux < win)
	if got[1].OS != "linux" || got[2].OS != "win" {
		t.Errorf("eşitlikte alfabetik sıralanmalı: %+v", got)
	}
}
