package detectreg

import (
	"testing"
	"time"

	"xems.corp/suite/server/internal/detect"
	"xems.corp/suite/server/internal/mitre"
)

func fixedNow() func() time.Time {
	t := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func TestValidate(t *testing.T) {
	if err := Validate(detect.Rule{ID: "R1", Name: "n", Severity: "HIGH"}); err != nil {
		t.Errorf("geçerli kural kabul edilmeli: %v", err)
	}
	for _, bad := range []detect.Rule{
		{Name: "n", Severity: "HIGH"},         // id yok
		{ID: "R", Severity: "HIGH"},           // ad yok
		{ID: "R", Name: "n", Severity: "ZZZ"}, // geçersiz severity
	} {
		if err := Validate(bad); err == nil {
			t.Errorf("geçersiz kural reddedilmeli: %+v", bad)
		}
	}
}

func TestUpsertVersioning(t *testing.T) {
	reg := New(fixedNow())
	if err := reg.Upsert(detect.Rule{ID: "R1", Name: "v1", Severity: "HIGH", Version: "1.0.0"}, PlatformWindows); err != nil {
		t.Fatal(err)
	}
	// yeni sürüm → eskisi geçmişe
	if err := reg.Upsert(detect.Rule{ID: "R1", Name: "v2", Severity: "HIGH", Version: "1.1.0"}, PlatformWindows); err != nil {
		t.Fatal(err)
	}
	e, ok := reg.Get("R1")
	if !ok || e.Rule.Version != "1.1.0" {
		t.Fatalf("güncel sürüm 1.1.0 olmalı: %+v", e.Rule)
	}
	if len(e.History) != 1 || e.History[0].Version != "1.0.0" {
		t.Fatalf("eski sürüm geçmişte olmalı: %+v", e.History)
	}
}

func TestLifecycleAndActive(t *testing.T) {
	reg := New(fixedNow())
	reg.Upsert(detect.Rule{ID: "A", Name: "a", Severity: "HIGH", Status: "active"}, PlatformAny)
	reg.Upsert(detect.Rule{ID: "B", Name: "b", Severity: "LOW", Status: "draft"}, PlatformAny)
	if got := reg.Active(); len(got) != 1 || got[0].ID != "A" {
		t.Fatalf("yalnız etkin kural dönmeli: %v", got)
	}
	// B'yi etkinleştir
	if err := reg.SetStatus("B", "active"); err != nil {
		t.Fatal(err)
	}
	if got := reg.Active(); len(got) != 2 {
		t.Fatalf("iki etkin kural olmalı: %d", len(got))
	}
	// A'yı emekliye ayır
	reg.SetStatus("A", "retired")
	if got := reg.Active(); len(got) != 1 || got[0].ID != "B" {
		t.Fatalf("emekli kural değerlendirilmemeli: %v", got)
	}
	if err := reg.SetStatus("YOK", "active"); err == nil {
		t.Error("bilinmeyen kural için hata dönmeli")
	}
}

func TestQueriesAndStats(t *testing.T) {
	reg := New(fixedNow())
	reg.Upsert(detect.Rule{ID: "W", Name: "w", Severity: "HIGH", Status: "active",
		Technique: mitre.Technique{ID: "T1059", Tactic: "Execution"}}, PlatformWindows)
	reg.Upsert(detect.Rule{ID: "L", Name: "l", Severity: "MEDIUM", Status: "active",
		Technique: mitre.Technique{ID: "T1046", Tactic: "Discovery"}}, PlatformLinux)

	if got := reg.ByPlatform(PlatformWindows); len(got) != 1 || got[0].Rule.ID != "W" {
		t.Fatalf("platform sorgusu W dönmeli: %v", got)
	}
	if got := reg.ByTechnique("T1059"); len(got) != 1 || got[0].Rule.ID != "W" {
		t.Fatalf("teknik sorgusu W dönmeli: %v", got)
	}
	s := reg.Stats()
	if s.Total != 2 || s.Active != 2 || s.ByPlatform["windows"] != 1 || s.ByTactic["Execution"] != 1 {
		t.Fatalf("istatistik hatalı: %+v", s)
	}
}
