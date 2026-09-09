package notify

import (
	"testing"
	"time"
)

func mkWindow(start, end time.Time, devices, cats []string, allowAbove string) Window {
	return Window{
		Start: start, End: end,
		devices: newSetRaw(devices), categories: newSet(cats),
		allowAbove: sevRank(allowAbove),
	}
}

func TestWindowActiveAndMatch(t *testing.T) {
	now := time.Unix(1000, 0)
	w := mkWindow(now.Add(-time.Hour), now.Add(time.Hour), nil, nil, "")
	if !w.Active(now) {
		t.Fatal("pencere etkin olmalı")
	}
	if !w.Matches(now, Alert{Severity: "HIGH", DeviceID: "d1"}) {
		t.Fatal("kapsamsız pencere her uyarıyı bastırmalı")
	}
	// Pencere dışı zaman.
	if w.Matches(now.Add(2*time.Hour), Alert{Severity: "HIGH"}) {
		t.Fatal("pencere dışı bastırılmamalı")
	}
}

func TestWindowDeviceCategoryScope(t *testing.T) {
	now := time.Unix(1000, 0)
	w := mkWindow(now.Add(-time.Hour), now.Add(time.Hour), []string{"d1"}, []string{"SECURITY"}, "")
	if !w.Matches(now, Alert{DeviceID: "d1", Category: "SECURITY", Severity: "HIGH"}) {
		t.Fatal("kapsamdaki uyarı bastırılmalı")
	}
	if w.Matches(now, Alert{DeviceID: "d2", Category: "SECURITY", Severity: "HIGH"}) {
		t.Fatal("kapsam dışı cihaz bastırılmamalı")
	}
	if w.Matches(now, Alert{DeviceID: "d1", Category: "PROCESS", Severity: "HIGH"}) {
		t.Fatal("kapsam dışı kategori bastırılmamalı")
	}
}

func TestWindowAllowAbove(t *testing.T) {
	now := time.Unix(1000, 0)
	// HIGH üstü (yani CRITICAL) bastırılmaz.
	w := mkWindow(now.Add(-time.Hour), now.Add(time.Hour), nil, nil, "HIGH")
	if !w.Matches(now, Alert{Severity: "HIGH"}) {
		t.Fatal("HIGH bastırılmalı (üstü değil)")
	}
	if w.Matches(now, Alert{Severity: "CRITICAL"}) {
		t.Fatal("CRITICAL (HIGH üstü) bastırılmamalı")
	}
}

func TestParseWindows(t *testing.T) {
	data := []byte(`[
	  {"start":"2026-03-10T00:00:00Z","end":"2026-03-10T04:00:00Z",
	   "devices":["d1"],"categories":["SECURITY"],"allow_above":"HIGH","reason":"bakım"}
	]`)
	ws, err := ParseWindows(data)
	if err != nil {
		t.Fatalf("ParseWindows: %v", err)
	}
	if len(ws) != 1 || ws[0].Reason != "bakım" {
		t.Fatalf("pencere yanlış: %+v", ws)
	}
}

func TestParseWindowsRejectsBad(t *testing.T) {
	for _, bad := range []string{
		`not json`,
		`[{"start":"bad","end":"2026-03-10T04:00:00Z"}]`,
		`[{"start":"2026-03-10T04:00:00Z","end":"2026-03-10T00:00:00Z"}]`, // end<start
	} {
		if _, err := ParseWindows([]byte(bad)); err == nil {
			t.Fatalf("ParseWindows(%q) hata döndürmeliydi", bad)
		}
	}
}

func TestSuppressorDropsAndForwards(t *testing.T) {
	c := &collector{}
	now := time.Unix(1000, 0)
	dropped := 0
	holder := NewWindowHolder([]Window{
		mkWindow(now.Add(-time.Hour), now.Add(time.Hour), []string{"d1"}, nil, ""),
	})
	s := NewSuppressor(c, holder.Windows, func() { dropped++ }, func() time.Time { return now })

	s.Notify(Alert{DeviceID: "d1", Severity: "HIGH"}) // bastırılmalı
	s.Notify(Alert{DeviceID: "d2", Severity: "HIGH"}) // iletilmeli
	if dropped != 1 {
		t.Fatalf("1 bastırma beklenirdi, %d", dropped)
	}
	if len(c.got) != 1 || c.got[0].DeviceID != "d2" {
		t.Fatalf("yalnız d2 iletilmeli, %+v", c.got)
	}
}

func TestSuppressorHotReload(t *testing.T) {
	c := &collector{}
	now := time.Unix(1000, 0)
	holder := NewWindowHolder(nil) // başta pencere yok
	s := NewSuppressor(c, holder.Windows, nil, func() time.Time { return now })

	s.Notify(Alert{DeviceID: "d1", Severity: "HIGH"}) // iletilmeli (pencere yok)
	// Pencere ekle (hot-reload).
	holder.Set([]Window{mkWindow(now.Add(-time.Hour), now.Add(time.Hour), nil, nil, "")})
	s.Notify(Alert{DeviceID: "d1", Severity: "HIGH"}) // artık bastırılmalı
	if len(c.got) != 1 {
		t.Fatalf("hot-reload sonrası yalnız ilk uyarı iletilmeli, %+v", c.got)
	}
}
