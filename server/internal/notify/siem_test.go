package notify

import (
	"strings"
	"testing"
	"time"
)

func sampleAlert() Alert {
	return Alert{
		DeviceID: "dev-1", Category: "SECURITY", Severity: "CRITICAL",
		Message:     "kurcalama girişimi | tespit",
		OccurredAt:  time.Unix(1700000000, 0),
		TechniqueID: "T1562", TechniqueName: "Impair Defenses", Tactic: "Defense Evasion",
	}
}

func TestFormatCEF(t *testing.T) {
	s := formatCEF(sampleAlert(), "Suite", "1.2.3")
	if !strings.HasPrefix(s, "CEF:0|XEMS|Suite|1.2.3|SECURITY|") {
		t.Fatalf("CEF başlığı hatalı: %q", s)
	}
	// | başlıkta kaçırılmalı (mesajdaki | → \|).
	if !strings.Contains(s, `kurcalama girişimi \| tespit`) {
		t.Fatalf("CEF | kaçırması hatalı: %q", s)
	}
	// severity CRITICAL → 10.
	if !strings.Contains(s, "|10|") {
		t.Fatalf("CEF önem düzeyi 10 olmalı: %q", s)
	}
	if !strings.Contains(s, "deviceExternalId=dev-1") || !strings.Contains(s, "cs1=T1562") {
		t.Fatalf("CEF uzantıları eksik: %q", s)
	}
}

func TestFormatCEFEscapesExtEquals(t *testing.T) {
	a := sampleAlert()
	a.DeviceID = "a=b"
	s := formatCEF(a, "Suite", "1")
	if !strings.Contains(s, `deviceExternalId=a\=b`) {
		t.Fatalf("uzantıda = kaçırılmalı: %q", s)
	}
}

func TestFormatLEEF(t *testing.T) {
	s := formatLEEF(sampleAlert(), "Suite", "1.0")
	if !strings.HasPrefix(s, "LEEF:2.0|XEMS|Suite|1.0|SECURITY|") {
		t.Fatalf("LEEF başlığı hatalı: %q", s)
	}
	if !strings.Contains(s, "src=dev-1") || !strings.Contains(s, "mitreTechnique=T1562") {
		t.Fatalf("LEEF alanları eksik: %q", s)
	}
}

func TestSevToCEF(t *testing.T) {
	if sevToCEF("CRITICAL") != 10 || sevToCEF("HIGH") != 8 || sevToCEF("INFO") != 2 || sevToCEF("?") != 0 {
		t.Fatal("sevToCEF eşlemesi hatalı")
	}
}

// Multi fan-out: her alt notifier'a iletir.
type capture struct{ got []Alert }

func (c *capture) Notify(a Alert) { c.got = append(c.got, a) }

func TestMultiFanOut(t *testing.T) {
	a, b := &capture{}, &capture{}
	m := NewMulti(a, nil, b) // nil atlanmalı
	if m.Len() != 2 {
		t.Fatalf("2 notifier beklenirdi, %d", m.Len())
	}
	m.Notify(sampleAlert())
	if len(a.got) != 1 || len(b.got) != 1 {
		t.Fatalf("her ikisi de almalıydı: a=%d b=%d", len(a.got), len(b.got))
	}
}

func TestSyslogNotifierThreshold(t *testing.T) {
	// Eşik altı düşürülür (kuyruğa girmez). minSeverity HIGH; INFO düşer.
	n, err := NewSyslogNotifier("127.0.0.1:0", "udp", "cef", "HIGH", "1")
	if err != nil {
		t.Fatal(err)
	}
	low := sampleAlert()
	low.Severity = "INFO"
	n.Notify(low) // düşmeli (eşik altı) — panik/bloke olmamalı
}
