package tamperprotect

import (
	"strings"
	"testing"
)

func TestAssessUserland(t *testing.T) {
	p := Assess(Defenses{Watchdog: true, Liveness: true, FIM: true, SelfAttest: true, SignedOTA: true}, false, "")
	if p.Level != "userland" {
		t.Fatalf("seviye userland olmalı, %q", p.Level)
	}
	if len(p.Userland) != 5 {
		t.Fatalf("5 userland savunması beklenirdi, %v", p.Userland)
	}
	// Sıralı olmalı (deterministik).
	for i := 1; i < len(p.Userland); i++ {
		if p.Userland[i-1] > p.Userland[i] {
			t.Fatalf("userland listesi sıralı olmalı: %v", p.Userland)
		}
	}
	if !strings.Contains(p.Summary, "USERLAND") || p.KernelDriver {
		t.Fatalf("özet/durum yanlış: %+v", p)
	}
}

func TestAssessKernel(t *testing.T) {
	p := Assess(Defenses{Watchdog: true}, true, "xemsflt")
	if p.Level != "kernel" || !p.KernelDriver || p.KernelDriverName != "xemsflt" {
		t.Fatalf("çekirdek durumu yanlış: %+v", p)
	}
	if !strings.Contains(p.Summary, "ÇEKİRDEK") {
		t.Fatalf("özet çekirdeği belirtmeli: %q", p.Summary)
	}
}

func TestAssessNone(t *testing.T) {
	p := Assess(Defenses{}, false, "")
	if p.Level != "none" || len(p.Userland) != 0 {
		t.Fatalf("hiç savunma yokken 'none' beklenirdi: %+v", p)
	}
}

func TestKernelDriverProbeDefaultAbsent(t *testing.T) {
	// Bu depoda sürücü sevk edilmez → yoklama false dönmeli (her platformda).
	present, _ := KernelDriverProbe()
	if present {
		t.Skip("beklenmedik: ortamda bir xemsflt.sys mevcut — atlanıyor")
	}
}
