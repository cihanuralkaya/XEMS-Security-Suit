package hardening

import (
	"strings"
	"testing"
)

func TestSummarizeLevels(t *testing.T) {
	strong := Summarize(Posture{Platform: "linux", NoNewPrivs: true, Seccomp: SeccompFilter, Privileged: false})
	if !strings.Contains(strong.Summary, "güçlü") {
		t.Errorf("no-new-privs + seccomp-filter → güçlü: %q", strong.Summary)
	}
	if len(strong.Measures) != 3 { // no-new-privs, seccomp-filter, unprivileged
		t.Errorf("3 önlem beklenir: %v", strong.Measures)
	}
	mid := Summarize(Posture{Platform: "linux", NoNewPrivs: true, Seccomp: SeccompDisabled, Privileged: true})
	if !strings.Contains(mid.Summary, "orta") {
		t.Errorf("yalnız no-new-privs → orta: %q", mid.Summary)
	}
	weak := Summarize(Posture{Platform: "linux", Privileged: true})
	if !strings.Contains(weak.Summary, "zayıf") || len(weak.Measures) != 0 {
		t.Errorf("önlemsiz → zayıf: %q %v", weak.Summary, weak.Measures)
	}
}

func TestMeasuresSorted(t *testing.T) {
	p := Summarize(Posture{NoNewPrivs: true, Seccomp: SeccompFilter, Privileged: false})
	for i := 1; i < len(p.Measures); i++ {
		if p.Measures[i-1] > p.Measures[i] {
			t.Fatalf("önlemler sıralı olmalı: %v", p.Measures)
		}
	}
}
