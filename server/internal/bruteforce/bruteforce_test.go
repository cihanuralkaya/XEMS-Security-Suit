package bruteforce

import (
	"testing"
	"time"
)

func TestAnalyzeFlagsBurst(t *testing.T) {
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	// host-A: 6 deneme 5dk içinde → kampanya. host-B: 2 deneme → altında.
	var att []Attempt
	for i := 0; i < 6; i++ {
		att = append(att, Attempt{DeviceID: "host-A", At: base.Add(time.Duration(i) * 30 * time.Second)})
	}
	att = append(att,
		Attempt{DeviceID: "host-B", At: base},
		Attempt{DeviceID: "host-B", At: base.Add(time.Minute)},
	)
	got := Analyze(att, 5, 5*time.Minute)
	if len(got) != 1 {
		t.Fatalf("1 bulgu beklenirdi (host-A), %d: %+v", len(got), got)
	}
	if got[0].DeviceID != "host-A" || got[0].Count != 6 {
		t.Fatalf("host-A 6 deneme beklenirdi, %+v", got[0])
	}
}

func TestAnalyzeWindowResets(t *testing.T) {
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	// 4 deneme ama ikişerli, aralarında 10dk → hiçbir 5dk pencerede 5'e ulaşmaz.
	att := []Attempt{
		{DeviceID: "h", At: base},
		{DeviceID: "h", At: base.Add(1 * time.Minute)},
		{DeviceID: "h", At: base.Add(11 * time.Minute)},
		{DeviceID: "h", At: base.Add(12 * time.Minute)},
	}
	if got := Analyze(att, 5, 5*time.Minute); len(got) != 0 {
		t.Fatalf("dağınık denemeler kampanya olmamalı, %+v", got)
	}
	// Eşik 2'ye (min→3 zorlanır) inince yine de en fazla 2 → yakalanmaz;
	// eşik 3, 3 deneme 5dk içinde → yakalanır.
	att = append(att, Attempt{DeviceID: "h", At: base.Add(2 * time.Minute)})
	if got := Analyze(att, 3, 5*time.Minute); len(got) != 1 || got[0].Count != 3 {
		t.Fatalf("3 deneme 5dk içinde yakalanmalı, %+v", got)
	}
}

func TestAnalyzeAttribution(t *testing.T) {
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	// Aynı kaynak IP, 3 farklı hedef hesap → püskürtme öznitelikleri.
	att := []Attempt{
		{DeviceID: "dc", At: base, SourceIP: "9.9.9.9", TargetUser: "alice"},
		{DeviceID: "dc", At: base.Add(1 * time.Minute), SourceIP: "9.9.9.9", TargetUser: "bob"},
		{DeviceID: "dc", At: base.Add(2 * time.Minute), SourceIP: "9.9.9.9", TargetUser: "carol"},
		{DeviceID: "dc", At: base.Add(3 * time.Minute), SourceIP: "8.8.8.8", TargetUser: "alice"},
	}
	got := Analyze(att, 3, 5*time.Minute)
	if len(got) != 1 {
		t.Fatalf("1 bulgu beklenirdi, %d", len(got))
	}
	f := got[0]
	if f.TopSource != "9.9.9.9" {
		t.Errorf("en sık kaynak 9.9.9.9 olmalı, %q", f.TopSource)
	}
	if f.DistinctSources != 2 {
		t.Errorf("2 farklı kaynak beklenirdi, %d", f.DistinctSources)
	}
	if f.DistinctTargets != 3 {
		t.Errorf("3 farklı hedef hesap beklenirdi, %d", f.DistinctTargets)
	}
}

func TestAnalyzeSuccessAfterBurst(t *testing.T) {
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	var evs []LogonEvent
	// host-A: 5 başarısız sonra 1 başarılı (2dk) → başarılı kaba-kuvvet.
	for i := 0; i < 5; i++ {
		evs = append(evs, LogonEvent{DeviceID: "host-A", At: base.Add(time.Duration(i) * 20 * time.Second), Success: false})
	}
	evs = append(evs, LogonEvent{DeviceID: "host-A", At: base.Add(2 * time.Minute), SourceIP: "6.6.6.6", Success: true})
	// host-B: 5 başarısız ama başarı YOK → bulgu yok.
	for i := 0; i < 5; i++ {
		evs = append(evs, LogonEvent{DeviceID: "host-B", At: base.Add(time.Duration(i) * 20 * time.Second), Success: false})
	}
	// host-C: başarı var ama yalnız 2 başarısız → eşik altında.
	evs = append(evs,
		LogonEvent{DeviceID: "host-C", At: base, Success: false},
		LogonEvent{DeviceID: "host-C", At: base.Add(time.Minute), Success: false},
		LogonEvent{DeviceID: "host-C", At: base.Add(90 * time.Second), Success: true},
	)
	got := AnalyzeSuccessAfterBurst(evs, 5, 5*time.Minute)
	if len(got) != 1 {
		t.Fatalf("1 bulgu beklenirdi (host-A), %d: %+v", len(got), got)
	}
	if got[0].DeviceID != "host-A" || got[0].FailuresBefore != 5 || got[0].SourceIP != "6.6.6.6" {
		t.Fatalf("host-A: 5 başarısız + kaynak IP beklenirdi, %+v", got[0])
	}
}

func TestAnalyzeSuccessWindowExpiry(t *testing.T) {
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	var evs []LogonEvent
	// 5 başarısız, sonra 10dk BOŞLUK, sonra başarı → başarısızlar pencereden düştü.
	for i := 0; i < 5; i++ {
		evs = append(evs, LogonEvent{DeviceID: "h", At: base.Add(time.Duration(i) * 20 * time.Second), Success: false})
	}
	evs = append(evs, LogonEvent{DeviceID: "h", At: base.Add(10 * time.Minute), Success: true})
	if got := AnalyzeSuccessAfterBurst(evs, 5, 5*time.Minute); len(got) != 0 {
		t.Fatalf("pencere dışı başarısızlar sayılmamalı, %+v", got)
	}
}

func TestAnalyzeDeterministicOrder(t *testing.T) {
	base := time.Now()
	var att []Attempt
	for _, d := range []string{"z", "a", "m"} {
		for i := 0; i < 4; i++ {
			att = append(att, Attempt{DeviceID: d, At: base.Add(time.Duration(i) * time.Second)})
		}
	}
	got := Analyze(att, 3, time.Minute)
	if len(got) != 3 || got[0].DeviceID != "a" || got[2].DeviceID != "z" {
		t.Fatalf("cihaz kimliğine göre sıralı olmalı, %+v", got)
	}
}
