package notify

import (
	"testing"
	"time"
)

// collector, aldığı uyarıları kaydeden test notifier'ı.
type collector struct{ got []Alert }

func (c *collector) Notify(a Alert) { c.got = append(c.got, a) }

func TestRouteMatches(t *testing.T) {
	r := NewRoute("r", "HIGH", []string{"SECURITY"}, nil, &collector{})
	if !r.Matches(Alert{Severity: "HIGH", Category: "SECURITY"}) {
		t.Fatal("HIGH/SECURITY eşleşmeliydi")
	}
	if r.Matches(Alert{Severity: "MEDIUM", Category: "SECURITY"}) {
		t.Fatal("MEDIUM eşik altında, eşleşmemeliydi")
	}
	if r.Matches(Alert{Severity: "CRITICAL", Category: "PROCESS"}) {
		t.Fatal("PROCESS kategorisi süzgeç dışı, eşleşmemeliydi")
	}
}

func TestRouteTechniqueFilter(t *testing.T) {
	r := NewRoute("r", "", nil, []string{"T1055"}, &collector{})
	if !r.Matches(Alert{Severity: "LOW", TechniqueID: "T1055"}) {
		t.Fatal("T1055 eşleşmeliydi")
	}
	if r.Matches(Alert{Severity: "CRITICAL", TechniqueID: "T1003"}) {
		t.Fatal("T1003 süzgeç dışı, eşleşmemeliydi")
	}
}

func TestRouterFanOut(t *testing.T) {
	sec := &collector{}
	proc := &collector{}
	router := NewRouter(
		NewRoute("sec", "HIGH", []string{"SECURITY"}, nil, sec),
		NewRoute("proc", "", []string{"PROCESS"}, nil, proc),
		NewRoute("nil-skip", "", nil, nil, nil), // nil hedef atlanır
	)
	if router.Len() != 2 {
		t.Fatalf("nil hedefli rota atlanmalı, Len=%d", router.Len())
	}
	router.Notify(Alert{Severity: "HIGH", Category: "SECURITY"})
	router.Notify(Alert{Severity: "LOW", Category: "PROCESS"})
	router.Notify(Alert{Severity: "MEDIUM", Category: "NETWORK_CONN"}) // hiçbir rotaya uymaz

	if len(sec.got) != 1 || sec.got[0].Category != "SECURITY" {
		t.Fatalf("sec rotası 1 SECURITY almalı, %+v", sec.got)
	}
	if len(proc.got) != 1 || proc.got[0].Category != "PROCESS" {
		t.Fatalf("proc rotası 1 PROCESS almalı, %+v", proc.got)
	}
}

func TestEscalatorForwardsAlways(t *testing.T) {
	c := &collector{}
	e := NewEscalator(c, "HIGH", 0, 0, nil) // yükseltme kapalı
	e.Notify(Alert{Severity: "LOW", DeviceID: "d1"})
	e.Notify(Alert{Severity: "HIGH", DeviceID: "d1"})
	if len(c.got) != 2 {
		t.Fatalf("yükseltme kapalıyken tüm uyarılar iletilmeli, %d", len(c.got))
	}
}

func TestEscalatorEscalatesOnThreshold(t *testing.T) {
	c := &collector{}
	now := time.Unix(1000, 0)
	clock := &now
	e := NewEscalator(c, "HIGH", 3, time.Minute, func() time.Time { return *clock })

	// Aynı anahtar (d1|SECURITY) için 3 HIGH uyarı → 3.'de yükseltme.
	for i := 0; i < 3; i++ {
		e.Notify(Alert{Severity: "HIGH", DeviceID: "d1", Category: "SECURITY", Message: "x"})
		*clock = clock.Add(time.Second)
	}
	// 3 orijinal + 1 escalated = 4.
	if len(c.got) != 4 {
		t.Fatalf("3 orijinal + 1 yükseltme = 4 beklenirdi, %d (%+v)", len(c.got), c.got)
	}
	esc := c.got[3]
	if esc.Severity != "CRITICAL" {
		t.Fatalf("yükseltilen uyarı CRITICAL olmalı, %q", esc.Severity)
	}
}

func TestEscalatorOncePerWindow(t *testing.T) {
	c := &collector{}
	now := time.Unix(1000, 0)
	clock := &now
	e := NewEscalator(c, "HIGH", 2, time.Minute, func() time.Time { return *clock })

	// 4 hızlı uyarı (pencere içinde): yalnız BİR yükseltme olmalı.
	for i := 0; i < 4; i++ {
		e.Notify(Alert{Severity: "HIGH", DeviceID: "d1", Category: "SECURITY"})
		*clock = clock.Add(time.Second)
	}
	escCount := 0
	for _, a := range c.got {
		if a.Severity == "CRITICAL" {
			escCount++
		}
	}
	if escCount != 1 {
		t.Fatalf("pencere başına bir yükseltme beklenirdi, %d", escCount)
	}
}

func TestEscalatorWindowExpiry(t *testing.T) {
	c := &collector{}
	now := time.Unix(1000, 0)
	clock := &now
	e := NewEscalator(c, "HIGH", 2, time.Minute, func() time.Time { return *clock })

	// İki uyarı ama aralarında pencereden fazla süre → eşik hiç dolmaz.
	e.Notify(Alert{Severity: "HIGH", DeviceID: "d1", Category: "SECURITY"})
	*clock = clock.Add(2 * time.Minute)
	e.Notify(Alert{Severity: "HIGH", DeviceID: "d1", Category: "SECURITY"})
	for _, a := range c.got {
		if a.Severity == "CRITICAL" {
			t.Fatal("pencere dışı uyarılar yükseltme tetiklememeli")
		}
	}
}

func TestEscalatorIgnoresLowSeverity(t *testing.T) {
	c := &collector{}
	now := time.Unix(1000, 0)
	clock := &now
	e := NewEscalator(c, "HIGH", 2, time.Minute, func() time.Time { return *clock })
	for i := 0; i < 5; i++ {
		e.Notify(Alert{Severity: "MEDIUM", DeviceID: "d1", Category: "SECURITY"})
		*clock = clock.Add(time.Second)
	}
	for _, a := range c.got {
		if a.Severity == "CRITICAL" {
			t.Fatal("eşik-altı önem yükseltmeye sayılmamalı")
		}
	}
}

func TestTenantStamper(t *testing.T) {
	c := &collector{}
	st := NewTenantStamper("acme", c)
	st.Notify(Alert{DeviceID: "d1", Severity: "HIGH"})
	if len(c.got) != 1 || c.got[0].Tenant != "acme" {
		t.Fatalf("uyarı 'acme' kiracısıyla damgalanmalı, %+v", c.got)
	}
	// "default" → damgalama yok (boş kalır).
	c2 := &collector{}
	NewTenantStamper("default", c2).Notify(Alert{DeviceID: "d1"})
	if c2.got[0].Tenant != "" {
		t.Fatalf("default kiracı damgalanmamalı, %q", c2.got[0].Tenant)
	}
}
