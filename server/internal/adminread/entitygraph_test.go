package adminread

import (
	"encoding/json"
	"testing"
	"time"
)

func raw(m map[string]any) json.RawMessage {
	b, _ := json.Marshal(m)
	return b
}

func TestBuildEntityGraph(t *testing.T) {
	now := time.Now()
	events := []EventDTO{
		{Category: "PROCESS", Severity: "MEDIUM", OccurredAt: now, Details: raw(map[string]any{"process": "powershell.exe"})},
		{Category: "NETWORK_CONN", Severity: "HIGH", OccurredAt: now, Details: raw(map[string]any{"remote_ip": "1.2.3.4"})},
		{Category: "SECURITY", Severity: "HIGH", OccurredAt: now, Details: raw(map[string]any{"domain": "evil.com", "dns": true})},
		{Category: "SECURITY", Severity: "CRITICAL", OccurredAt: now, Details: raw(map[string]any{"path": "/etc/passwd", "fim": true})},
		{Category: "SYSTEM", Severity: "INFO", OccurredAt: now, Details: raw(map[string]any{"x": "y"})}, // varlık yok
	}
	g := BuildEntityGraph("dev-1", events)
	// device + 4 varlık = 5 düğüm.
	if len(g.Nodes) != 5 {
		t.Fatalf("5 düğüm beklenirdi, %d (%+v)", len(g.Nodes), g.Nodes)
	}
	// 4 kenar (cihaz → her varlık).
	if len(g.Edges) != 4 {
		t.Fatalf("4 kenar beklenirdi, %d", len(g.Edges))
	}
	// Kenar fiilleri doğru.
	kinds := map[string]string{}
	for _, e := range g.Edges {
		kinds[e.To] = e.Kind
	}
	if kinds["process:powershell.exe"] != "ran" || kinds["ip:1.2.3.4"] != "connected" ||
		kinds["domain:evil.com"] != "resolved" || kinds["file:/etc/passwd"] != "touched" {
		t.Fatalf("kenar fiilleri yanlış: %+v", kinds)
	}
}

func TestBuildEntityGraphDedupAndSeverity(t *testing.T) {
	now := time.Now()
	events := []EventDTO{
		{Category: "NETWORK_CONN", Severity: "LOW", OccurredAt: now, Details: raw(map[string]any{"remote_ip": "9.9.9.9"})},
		{Category: "NETWORK_CONN", Severity: "CRITICAL", OccurredAt: now, Details: raw(map[string]any{"remote_ip": "9.9.9.9"})},
	}
	g := BuildEntityGraph("d", events)
	// Aynı IP → tek düğüm (device + 1 = 2).
	if len(g.Nodes) != 2 || len(g.Edges) != 1 {
		t.Fatalf("tekilleştirme başarısız: %d düğüm, %d kenar", len(g.Nodes), len(g.Edges))
	}
	// Kenar en yüksek önemi tutmalı.
	if g.Edges[0].Severity != "CRITICAL" {
		t.Fatalf("kenar en yüksek önemi tutmalı, %q", g.Edges[0].Severity)
	}
}

func TestBuildEntityGraphEmpty(t *testing.T) {
	g := BuildEntityGraph("d", []EventDTO{
		{Category: "SYSTEM", Severity: "INFO", Details: raw(map[string]any{"a": 1})},
	})
	// Yalnız cihaz düğümü, kenar yok.
	if len(g.Nodes) != 1 || len(g.Edges) != 0 {
		t.Fatalf("yalnız cihaz düğümü beklenirdi, %d/%d", len(g.Nodes), len(g.Edges))
	}
}
