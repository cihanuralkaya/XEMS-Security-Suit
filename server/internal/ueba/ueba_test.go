package ueba

import (
	"testing"
	"time"
)

func TestIsDestructive(t *testing.T) {
	for _, a := range []string{"WIPE_REQUEST", "device.quarantine", "REVOKE_CERT", "cert-DELETE"} {
		if !IsDestructive(a) {
			t.Errorf("%q yıkıcı sayılmalı", a)
		}
	}
	for _, a := range []string{"LOGIN", "EVENT_CASE", "COLLECT_DIAGNOSTICS", "VIEW"} {
		if IsDestructive(a) {
			t.Errorf("%q yıkıcı sayılmamalı", a)
		}
	}
}

func TestAnalyzeProfiles(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	entries := []Entry{
		{Admin: "a@corp", Action: "LOGIN", At: base},
		{Admin: "a@corp", Action: "QUARANTINE", At: base.Add(time.Minute)},
		{Admin: "b@corp", Action: "EVENT_CASE", At: base},
	}
	rep := Analyze(entries, Options{})
	if len(rep.Profiles) != 2 {
		t.Fatalf("2 profil beklenirdi, %d", len(rep.Profiles))
	}
	// Profiller ada göre sıralı (a önce).
	if rep.Profiles[0].Admin != "a@corp" || rep.Profiles[0].Total != 2 || rep.Profiles[0].Destructive != 1 {
		t.Fatalf("a@corp profili yanlış: %+v", rep.Profiles[0])
	}
}

func TestAnalyzeDestructiveBurst(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	var entries []Entry
	// 6 yıkıcı eylem 5 dk içinde → burst (eşik 5).
	for i := 0; i < 6; i++ {
		entries = append(entries, Entry{Admin: "rogue@corp", Action: "WIPE", At: base.Add(time.Duration(i) * 30 * time.Second)})
	}
	rep := Analyze(entries, Options{})
	found := false
	for _, f := range rep.Findings {
		if f.Admin == "rogue@corp" && f.Severity == "HIGH" {
			found = true
		}
	}
	if !found {
		t.Fatalf("yıkıcı-eylem serisi HIGH bulgu üretmeli, %+v", rep.Findings)
	}
}

func TestAnalyzeBurstWindowRespected(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	var entries []Entry
	// 6 yıkıcı eylem ama 2 saate yayılmış → pencere (10dk) içinde eşik dolmaz.
	for i := 0; i < 6; i++ {
		entries = append(entries, Entry{Admin: "ops@corp", Action: "QUARANTINE", At: base.Add(time.Duration(i) * 20 * time.Minute)})
	}
	rep := Analyze(entries, Options{})
	for _, f := range rep.Findings {
		if f.Severity == "HIGH" {
			t.Fatalf("pencereye yayılmış eylemler burst tetiklememeli, %+v", f)
		}
	}
}

func TestAnalyzeHighRatioMedium(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	var entries []Entry
	// 12 eylem, 8'i yıkıcı ama zamana yayılmış (burst yok) → oran > 0.5 → MEDIUM.
	for i := 0; i < 12; i++ {
		act := "VIEW"
		if i < 8 {
			act = "LOCK"
		}
		entries = append(entries, Entry{Admin: "x@corp", Action: act, At: base.Add(time.Duration(i) * time.Hour)})
	}
	rep := Analyze(entries, Options{})
	found := false
	for _, f := range rep.Findings {
		if f.Admin == "x@corp" && f.Severity == "MEDIUM" {
			found = true
		}
	}
	if !found {
		t.Fatalf("yüksek yıkıcı oran MEDIUM bulgu üretmeli, %+v", rep.Findings)
	}
}

func TestAnalyzeQuietAdminNoFinding(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	rep := Analyze([]Entry{
		{Admin: "calm@corp", Action: "LOGIN", At: base},
		{Admin: "calm@corp", Action: "EVENT_CASE", At: base.Add(time.Hour)},
	}, Options{})
	if len(rep.Findings) != 0 {
		t.Fatalf("sakin yönetici bulgu üretmemeli, %+v", rep.Findings)
	}
}

func TestEntityAnomalies(t *testing.T) {
	base := time.Date(2026, 9, 11, 3, 12, 0, 0, time.UTC) // 03:12 UTC — mesai dışı
	opts := DefaultOptions()
	opts.BusinessStartHour, opts.BusinessEndHour = 9, 18
	opts.KnownDevices = map[string]map[string]bool{"bob": {"laptop-1": true}}
	opts.KnownLocations = map[string]map[string]bool{"bob": {"HQ": true}}

	entries := []Entry{
		{Admin: "bob", Action: "WIPE", At: base, Device: "unknown-pc", Location: "Anonim"},
	}
	rep := Analyze(entries, opts)
	if len(rep.Profiles) != 1 {
		t.Fatalf("1 profil beklenir")
	}
	p := rep.Profiles[0]
	if p.OffHours != 1 || p.NewDevices != 1 || p.NewLocs != 1 {
		t.Fatalf("varlık sinyalleri: offHours=%d newDev=%d newLoc=%d", p.OffHours, p.NewDevices, p.NewLocs)
	}
	if p.RiskScore == 0 {
		t.Error("risk skoru sinyallerle > 0 olmalı")
	}
	// bilinmeyen cihaz + konum + mesai-dışı(+yıkıcı) → en az 3 finding
	var dev, loc, off bool
	for _, f := range rep.Findings {
		switch {
		case f.Reason == "bilinmeyen cihazdan 1 eylem":
			dev = true
		case f.Reason == "bilinmeyen konumdan 1 eylem":
			loc = true
		case f.Reason == "mesai-dışı 1 eylem (yıkıcı etkinlikle birlikte)":
			off = true
		}
	}
	if !dev || !loc || !off {
		t.Errorf("beklenen bulgular eksik: dev=%v loc=%v off=%v", dev, loc, off)
	}
}

func TestKnownDeviceNoFalsePositive(t *testing.T) {
	opts := DefaultOptions()
	opts.KnownDevices = map[string]map[string]bool{"bob": {"laptop-1": true}}
	entries := []Entry{{Admin: "bob", Action: "VIEW", At: time.Now(), Device: "laptop-1"}}
	rep := Analyze(entries, opts)
	if rep.Profiles[0].NewDevices != 0 {
		t.Error("bilinen cihaz yanlış-pozitif üretmemeli")
	}
}
