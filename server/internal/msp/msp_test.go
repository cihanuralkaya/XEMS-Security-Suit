package msp

import (
	"sync"
	"testing"
	"time"
)

// --- Registry: CRUD + sıralama ---------------------------------------------

func TestRegistryAddGet(t *testing.T) {
	tests := []struct {
		name   string
		c      Customer
		wantOK bool
	}{
		{"gecerli", Customer{ID: "c1", Name: "Acme", TenantID: "t1"}, true},
		{"bos-id", Customer{ID: "", Name: "X", TenantID: "t1"}, false},
		{"bos-tenant", Customer{ID: "c2", Name: "Y", TenantID: ""}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry()
			got, ok := r.Add(tt.c)
			if ok != tt.wantOK {
				t.Fatalf("Add ok = %v, beklenen %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				if _, found := r.Get(tt.c.ID); found && tt.c.ID != "" {
					t.Fatalf("reddedilen müşteri kayıtlı görünüyor")
				}
				return
			}
			if got.CreatedAt.IsZero() {
				t.Errorf("CreatedAt atanmadı")
			}
			back, found := r.Get(tt.c.ID)
			if !found || back.ID != tt.c.ID {
				t.Fatalf("Get(%q) bulunamadı", tt.c.ID)
			}
		})
	}
}

func TestRegistryAddPreservesCreatedAt(t *testing.T) {
	r := NewRegistry()
	ts := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	got, _ := r.Add(Customer{ID: "c1", TenantID: "t1", CreatedAt: ts})
	if !got.CreatedAt.Equal(ts) {
		t.Fatalf("CreatedAt korunmadı: %v", got.CreatedAt)
	}
}

func TestRegistryListOrdering(t *testing.T) {
	r := NewRegistry()
	for _, id := range []string{"c3", "c1", "c2"} {
		r.Add(Customer{ID: id, TenantID: "t-" + id})
	}
	got := r.List()
	want := []string{"c1", "c2", "c3"}
	if len(got) != len(want) {
		t.Fatalf("List uzunluğu = %d, beklenen %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("List[%d] = %q, beklenen %q", i, got[i].ID, id)
		}
	}
}

func TestRegistryDeactivate(t *testing.T) {
	r := NewRegistry()
	r.Add(Customer{ID: "c1", TenantID: "t1", Active: true})
	if ok := r.Deactivate("yok"); ok {
		t.Errorf("olmayan müşteri için Deactivate true döndü")
	}
	if ok := r.Deactivate("c1"); !ok {
		t.Fatalf("Deactivate(c1) false döndü")
	}
	c, _ := r.Get("c1")
	if c.Active {
		t.Errorf("müşteri hâlâ aktif")
	}
}

// --- Yapılandırma: varsayılanlar + set/get ---------------------------------

func TestConfigDefaults(t *testing.T) {
	r := NewRegistry()
	cfg, ok := r.GetConfig("yok")
	if ok {
		t.Errorf("eksik yapılandırma için ok=true döndü")
	}
	def := DefaultConfig()
	if cfg.RetentionDays != def.RetentionDays || cfg.Plan != def.Plan || len(cfg.Policies) != 0 {
		t.Errorf("varsayılan yapılandırma beklenmiyor: %+v", cfg)
	}
}

func TestConfigSetGet(t *testing.T) {
	r := NewRegistry()
	if ok := r.SetConfig("", CustomerConfig{}); ok {
		t.Errorf("boş ID için SetConfig true döndü")
	}
	want := CustomerConfig{RetentionDays: 90, Policies: []string{"pci", "hipaa"}, Plan: "enterprise"}
	if ok := r.SetConfig("c1", want); !ok {
		t.Fatalf("SetConfig başarısız")
	}
	got, ok := r.GetConfig("c1")
	if !ok {
		t.Fatalf("GetConfig ok=false")
	}
	if got.RetentionDays != 90 || got.Plan != "enterprise" || len(got.Policies) != 2 {
		t.Errorf("yapılandırma yuvarlak-gidiş başarısız: %+v", got)
	}
}

// --- İzolasyon: CanAccess / Scope ------------------------------------------

func TestCanAccess(t *testing.T) {
	global := Operator{ID: "op-g", Name: "Global"}
	scoped := Operator{ID: "op-s", Name: "Scoped", Customers: []string{"c1", "c2"}}
	tests := []struct {
		name       string
		op         Operator
		customerID string
		want       bool
	}{
		{"global-herhangi", global, "cX", true},
		{"scoped-izinli", scoped, "c1", true},
		{"scoped-izinli-2", scoped, "c2", true},
		{"scoped-reddedilen", scoped, "c3", false},
		{"bilinmeyen-operator", Operator{ID: ""}, "c1", false},
		{"bos-musteri", scoped, "", false},
		{"bos-operator-bos-liste", Operator{ID: "", Customers: nil}, "c1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CanAccess(tt.op, tt.customerID); got != tt.want {
				t.Errorf("CanAccess = %v, beklenen %v", got, tt.want)
			}
		})
	}
}

func TestIsGlobal(t *testing.T) {
	if !(Operator{ID: "x"}).IsGlobal() {
		t.Errorf("boş listeli kimlikli operatör global olmalı")
	}
	if (Operator{ID: ""}).IsGlobal() {
		t.Errorf("kimliksiz operatör global olmamalı (fail-closed)")
	}
	if (Operator{ID: "x", Customers: []string{"c1"}}).IsGlobal() {
		t.Errorf("kapsamlı operatör global olmamalı")
	}
}

func TestScope(t *testing.T) {
	all := []Customer{
		{ID: "c1", TenantID: "t1"},
		{ID: "c2", TenantID: "t2"},
		{ID: "c3", TenantID: "t3"},
	}
	tests := []struct {
		name    string
		op      Operator
		wantIDs []string
	}{
		{"global-hepsi", Operator{ID: "g"}, []string{"c1", "c2", "c3"}},
		{"kapsamli", Operator{ID: "s", Customers: []string{"c1", "c3"}}, []string{"c1", "c3"}},
		{"bilinmeyen-bos", Operator{ID: ""}, []string{}},
		{"hicbirine-izin-yok", Operator{ID: "s", Customers: []string{"yok"}}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Scope(tt.op, all)
			if len(got) != len(tt.wantIDs) {
				t.Fatalf("Scope uzunluğu = %d, beklenen %d", len(got), len(tt.wantIDs))
			}
			for i, id := range tt.wantIDs {
				if got[i].ID != id {
					t.Errorf("Scope[%d] = %q, beklenen %q", i, got[i].ID, id)
				}
			}
		})
	}
}

// --- UsageMeter: birikim + anlık kopyalar ----------------------------------

func TestUsageMeterAccumulation(t *testing.T) {
	m := NewUsageMeter()
	m.AddEvents("c1", 10)
	m.AddEvents("c1", 5)
	m.AddEvents("c1", -3) // yok sayılır
	m.AddEvents("", 100)  // yok sayılır
	m.SetAgents("c1", 7)
	m.SetAgents("c1", -1) // yok sayılır, 7 kalır
	m.AddIncident("c1")
	m.AddIncident("c1")

	u, ok := m.Snapshot("c1")
	if !ok {
		t.Fatalf("Snapshot ok=false")
	}
	if u.Events != 15 {
		t.Errorf("Events = %d, beklenen 15", u.Events)
	}
	if u.Agents != 7 {
		t.Errorf("Agents = %d, beklenen 7", u.Agents)
	}
	if u.Incidents != 2 {
		t.Errorf("Incidents = %d, beklenen 2", u.Incidents)
	}
}

func TestUsageMeterSnapshotMissing(t *testing.T) {
	m := NewUsageMeter()
	u, ok := m.Snapshot("yok")
	if ok {
		t.Errorf("olmayan müşteri için ok=true döndü")
	}
	if u.CustomerID != "yok" || u.Events != 0 {
		t.Errorf("sıfır-değerli Usage beklenirdi: %+v", u)
	}
}

func TestUsageMeterSnapshotAllOrdering(t *testing.T) {
	m := NewUsageMeter()
	m.AddEvents("c3", 1)
	m.AddEvents("c1", 1)
	m.AddEvents("c2", 1)
	all := m.SnapshotAll()
	want := []string{"c1", "c2", "c3"}
	if len(all) != 3 {
		t.Fatalf("SnapshotAll uzunluğu = %d", len(all))
	}
	for i, id := range want {
		if all[i].CustomerID != id {
			t.Errorf("SnapshotAll[%d] = %q, beklenen %q", i, all[i].CustomerID, id)
		}
	}
}

func TestUsageMeterSnapshotIsCopy(t *testing.T) {
	m := NewUsageMeter()
	m.AddEvents("c1", 5)
	u, _ := m.Snapshot("c1")
	u.Events = 999 // kopyayı değiştir
	again, _ := m.Snapshot("c1")
	if again.Events != 5 {
		t.Errorf("Snapshot kopya değil, içsel durum değişti: %d", again.Events)
	}
}

func TestUsageMeterConcurrent(t *testing.T) {
	m := NewUsageMeter()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.AddEvents("c1", 2)
			m.AddIncident("c1")
		}()
	}
	wg.Wait()
	u, _ := m.Snapshot("c1")
	if u.Events != 100 {
		t.Errorf("Events = %d, beklenen 100", u.Events)
	}
	if u.Incidents != 50 {
		t.Errorf("Incidents = %d, beklenen 50", u.Incidents)
	}
}

// --- Küresel toplama + top-N -----------------------------------------------

func TestAggregateGlobalTotals(t *testing.T) {
	summaries := []CustomerSummary{
		{CustomerID: "c1", OpenIncidents: 2, CriticalAlerts: 1, Agents: 10, RiskScore: 50},
		{CustomerID: "c2", OpenIncidents: 3, CriticalAlerts: 4, Agents: 20, RiskScore: 90},
		{CustomerID: "c3", OpenIncidents: 0, CriticalAlerts: 0, Agents: 5, RiskScore: 70},
	}
	g := AggregateGlobal(summaries, 2)
	if g.Customers != 3 {
		t.Errorf("Customers = %d, beklenen 3", g.Customers)
	}
	if g.OpenIncidents != 5 || g.CriticalAlerts != 5 || g.Agents != 35 {
		t.Errorf("toplamlar yanlış: %+v", g)
	}
	if len(g.TopRisk) != 2 {
		t.Fatalf("TopRisk uzunluğu = %d, beklenen 2", len(g.TopRisk))
	}
	if g.TopRisk[0].CustomerID != "c2" || g.TopRisk[1].CustomerID != "c3" {
		t.Errorf("TopRisk sırası yanlış: %v, %v", g.TopRisk[0].CustomerID, g.TopRisk[1].CustomerID)
	}
}

func TestAggregateGlobalTopNTieBreak(t *testing.T) {
	// Eşit risk skorunda CustomerID'ye göre artan sıralama.
	summaries := []CustomerSummary{
		{CustomerID: "cb", RiskScore: 80},
		{CustomerID: "ca", RiskScore: 80},
		{CustomerID: "cc", RiskScore: 80},
	}
	g := AggregateGlobal(summaries, 3)
	want := []string{"ca", "cb", "cc"}
	for i, id := range want {
		if g.TopRisk[i].CustomerID != id {
			t.Errorf("TopRisk[%d] = %q, beklenen %q", i, g.TopRisk[i].CustomerID, id)
		}
	}
}

func TestAggregateGlobalEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		summaries []CustomerSummary
		topN      int
		wantTop   int
	}{
		{"bos-girdi", nil, 5, 0},
		{"topN-sifir", []CustomerSummary{{CustomerID: "c1", RiskScore: 1}}, 0, 0},
		{"topN-negatif", []CustomerSummary{{CustomerID: "c1", RiskScore: 1}}, -1, 0},
		{"topN-asiri", []CustomerSummary{{CustomerID: "c1"}, {CustomerID: "c2"}}, 10, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := AggregateGlobal(tt.summaries, tt.topN)
			if len(g.TopRisk) != tt.wantTop {
				t.Errorf("TopRisk uzunluğu = %d, beklenen %d", len(g.TopRisk), tt.wantTop)
			}
			if g.TopRisk == nil {
				t.Errorf("TopRisk nil olmamalı, boş dilim beklenir")
			}
		})
	}
}

func TestAggregateGlobalDoesNotMutateInput(t *testing.T) {
	summaries := []CustomerSummary{
		{CustomerID: "c1", RiskScore: 10},
		{CustomerID: "c2", RiskScore: 90},
	}
	AggregateGlobal(summaries, 2)
	if summaries[0].CustomerID != "c1" || summaries[1].CustomerID != "c2" {
		t.Errorf("girdi dilimi değiştirildi: %+v", summaries)
	}
}
