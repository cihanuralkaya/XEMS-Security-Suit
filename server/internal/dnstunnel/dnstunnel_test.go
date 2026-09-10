package dnstunnel

import (
	"testing"
	"time"
)

func TestRegisteredDomain(t *testing.T) {
	cases := map[string]string{
		"a.b.evil.com":     "evil.com",
		"data.exfil.co":    "exfil.co",
		"example.com":      "example.com",
		"localhost":        "localhost",
		"x.y.z.corp.local": "corp.local",
	}
	for in, want := range cases {
		if got := registeredDomain(in); got != want {
			t.Errorf("registeredDomain(%q)=%q beklenen %q", in, got, want)
		}
	}
}

func TestAnalyzeDetectsTunnel(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	var qs []Query
	// d1: tek üst alan (evil.com) altında 8 farklı alt alan, 2 dk içinde → tünel.
	for i := 0; i < 8; i++ {
		qs = append(qs, Query{DeviceID: "d1", Domain: "chunk" + itoa(i) + ".data.evil.com", At: base.Add(time.Duration(i) * 15 * time.Second)})
	}
	f := Analyze(qs, 5, 5*time.Minute)
	if len(f) != 1 || f[0].Parent != "evil.com" || f[0].DistinctSubdomains < 8 {
		t.Fatalf("evil.com tüneli bulunmalı, %+v", f)
	}
}

func TestAnalyzeIgnoresFewSubdomains(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	qs := []Query{
		{DeviceID: "d1", Domain: "www.example.com", At: base},
		{DeviceID: "d1", Domain: "api.example.com", At: base.Add(time.Second)},
		{DeviceID: "d1", Domain: "cdn.example.com", At: base.Add(2 * time.Second)},
	}
	// 3 alt alan eşik (5) altında → tetiklememeli.
	if f := Analyze(qs, 5, 5*time.Minute); len(f) != 0 {
		t.Fatalf("normal çok-alt-alan kullanımı tetiklememeli, %+v", f)
	}
}

func TestAnalyzeWindowRespected(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	var qs []Query
	// 8 alt alan ama her biri 2dk arayla → pencere (5dk) içinde eşik dolmaz... aslında
	// 5dk penceresine ~3 tanesi düşer; eşik 5 → tetiklemez.
	for i := 0; i < 8; i++ {
		qs = append(qs, Query{DeviceID: "d1", Domain: "c" + itoa(i) + ".x.evil.com", At: base.Add(time.Duration(i) * 2 * time.Minute)})
	}
	if f := Analyze(qs, 5, 5*time.Minute); len(f) != 0 {
		t.Fatalf("pencereye yayılmış sorgular tetiklememeli, %+v", f)
	}
}

func TestAnalyzeParentOnlyNotCounted(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	var qs []Query
	// Sadece üst alanın kendisi tekrarlanıyor → alt alan yok → tetiklemez.
	for i := 0; i < 10; i++ {
		qs = append(qs, Query{DeviceID: "d1", Domain: "evil.com", At: base.Add(time.Duration(i) * time.Second)})
	}
	if f := Analyze(qs, 3, 5*time.Minute); len(f) != 0 {
		t.Fatalf("üst-alanın kendisi alt-alan sayılmamalı, %+v", f)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
