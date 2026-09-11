//go:build linux

package hardening

import "testing"

func TestParseProcStatus(t *testing.T) {
	content := "Name:\txems-agent\nUid:\t0\t0\t0\t0\nNoNewPrivs:\t1\nSeccomp:\t2\n"
	p := parseProcStatus(content, true)
	if !p.NoNewPrivs {
		t.Error("NoNewPrivs 1 → true")
	}
	if p.Seccomp != SeccompFilter {
		t.Errorf("Seccomp 2 → filter, got %q", p.Seccomp)
	}
	if !p.Privileged {
		t.Error("privileged geçirilmeli")
	}
	// eksik alanlar → varsayılan (disabled/false)
	p2 := parseProcStatus("Name:\tx\n", false)
	if p2.NoNewPrivs || p2.Seccomp != SeccompUnknown {
		t.Errorf("eksik alanlar unknown/false kalmalı: %+v", p2)
	}
}
