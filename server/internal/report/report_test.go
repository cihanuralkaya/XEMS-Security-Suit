package report

import (
	"strings"
	"testing"
	"time"
)

func sampleData() Data {
	return Data{
		GeneratedAt:  time.Date(2026, 9, 9, 10, 0, 0, 0, time.UTC),
		DevicesTotal: 10, DevicesOnline: 7, DevicesOffline: 3, DevicesQuarantined: 1,
		NonCompliant: 2, Detections: 42, AlertsRaised: 12, AlertsSuppressed: 30, IocHits: 3,
		EventsBySeverity: map[string]int{"HIGH": 5, "INFO": 20},
		TopIncidents:     []Incident{{DeviceID: "dev-1", RuleID: "XEMS-0001", Severity: "CRITICAL", Count: 4, LastSeen: time.Now()}},
	}
}

func TestRenderHTMLContainsKPIsAndEscapes(t *testing.T) {
	d := sampleData()
	// XSS güvenliği: kötü niyetli kural id'si HTML kaçışından geçmeli (html/template).
	d.TopIncidents[0].RuleID = `<script>alert(1)</script>`
	out, err := RenderHTML(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Toplam cihaz", ">10<", "Bastırılan", "XEMS Security Suite"} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML %q içermeliydi", want)
		}
	}
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Fatal("kural id HTML olarak kaçışsız gömülmemeliydi (XSS)")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Fatal("kural id kaçışlı gömülmeliydi")
	}
}

func TestRenderCSV(t *testing.T) {
	out := RenderCSV(sampleData())
	if !strings.HasPrefix(out, "metrik,deger\n") {
		t.Fatalf("CSV başlığı beklenmedik: %q", out[:20])
	}
	for _, want := range []string{"cihaz_toplam,10", "alarm_bastirilan,30", "onem_high,5"} {
		if !strings.Contains(out, want) {
			t.Fatalf("CSV %q içermeliydi:\n%s", want, out)
		}
	}
}
