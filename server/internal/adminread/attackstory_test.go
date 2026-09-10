package adminread

import (
	"testing"
	"time"
)

func TestClassifyStage(t *testing.T) {
	cases := []struct {
		cat, msg, want string
	}{
		{"PROCESS", "yeni süreç: powershell", "Execution"},
		{"POLICY_VIOLATION", "yeni kalıcılık girdisi", "Persistence"},
		{"NETWORK_DISCOVERY", "yeni komşu", "Discovery"},
		{"NETWORK_CONN", "giden bağlantı", "Command & Control"},
		{"SECURITY", "DGA-şüpheli DNS sorgusu: x.com", "Command & Control"},
		{"SECURITY", "IoC eşleşmesi [bad] 1.2.3.4", "Command & Control"},
		{"SECURITY", "DLP: hassas veri tespit edildi", "Exfiltration"},
		{"SECURITY", "ajan kurcalama tespit edildi", "Defense Evasion"},
		{"SECURITY", "cihaz karantinaya alındı", "Impact"},
		{"SECURITY", "olası yanal hareket: 9 iç hedef", "Discovery"},
		{"SECURITY", "olası DNS tünelleme: evil.com 25 alt alan", "Command & Control"},
		{"SECURITY", "genel güvenlik olayı", "Detection"},
	}
	for _, c := range cases {
		if got, _ := classifyStage(c.cat, c.msg); got != c.want {
			t.Errorf("classifyStage(%q,%q)=%q beklenen %q", c.cat, c.msg, got, c.want)
		}
	}
}

func TestBuildAttackStoryOrdersAndFilters(t *testing.T) {
	base := time.Date(2026, 3, 10, 9, 0, 0, 0, time.UTC)
	events := []EventDTO{
		{Category: "SECURITY", Severity: "CRITICAL", Message: "IoC eşleşmesi", OccurredAt: base.Add(3 * time.Minute)},
		{Category: "SYSTEM", Severity: "INFO", Message: "rutin", OccurredAt: base.Add(1 * time.Minute)},
		{Category: "PROCESS", Severity: "MEDIUM", Message: "powershell çalıştı", OccurredAt: base.Add(2 * time.Minute)},
		{Category: "POLICY_VIOLATION", Severity: "HIGH", Message: "kalıcılık girdisi", OccurredAt: base.Add(4 * time.Minute)},
	}
	story := BuildAttackStory("dev-1", events)
	// SYSTEM olayı hikâyeden çıkarılmalı → 3 adım.
	if len(story.Steps) != 3 {
		t.Fatalf("3 adım beklenirdi (SYSTEM hariç), %d", len(story.Steps))
	}
	// Kronolojik sıra: 2dk (Execution) < 3dk (C2) < 4dk (Persistence).
	if story.Steps[0].Stage != "Execution" || story.Steps[2].Stage != "Persistence" {
		t.Fatalf("kronolojik sıra yanlış: %+v", story.Steps)
	}
	if story.MaxSeverity != "CRITICAL" {
		t.Fatalf("en yüksek önem CRITICAL olmalı, %q", story.MaxSeverity)
	}
	// Aşamalar kill-chain sırasına göre: Execution(2) < Persistence(3) < C2(6).
	if len(story.Stages) != 3 || story.Stages[0] != "Execution" || story.Stages[2] != "Command & Control" {
		t.Fatalf("aşama sıralaması yanlış: %v", story.Stages)
	}
}

func TestBuildAttackStoryEmpty(t *testing.T) {
	story := BuildAttackStory("d", []EventDTO{
		{Category: "SYSTEM", Message: "x", OccurredAt: time.Now()},
	})
	if len(story.Steps) != 0 {
		t.Fatalf("yalnız SYSTEM olayları → boş hikâye, %d", len(story.Steps))
	}
}
