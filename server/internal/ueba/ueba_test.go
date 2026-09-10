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
