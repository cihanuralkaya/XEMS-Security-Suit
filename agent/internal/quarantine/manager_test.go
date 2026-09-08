package quarantine

import (
	"errors"
	"testing"

	"xems.corp/suite/agent/internal/collector"
)

type fakeIso struct {
	isolateCalls int
	releaseCalls int
	failIsolate  bool
}

func (f *fakeIso) Isolate(_ []string) error {
	f.isolateCalls++
	if f.failIsolate {
		return errors.New("firewall erişimi reddedildi")
	}
	return nil
}
func (f *fakeIso) Release() error {
	f.releaseCalls++
	return nil
}

func TestApplyReleaseIdempotent(t *testing.T) {
	iso := &fakeIso{}
	buf := collector.NewBuffer(100)
	m := NewManager(iso, buf, []string{"10.0.0.1"})

	// İlk Apply karantinaya alır.
	if err := m.Apply(); err != nil {
		t.Fatal(err)
	}
	if !m.Active() || iso.isolateCalls != 1 {
		t.Fatalf("bir kez izole edilmeliydi, active=%v calls=%d", m.Active(), iso.isolateCalls)
	}
	// İkinci Apply idempotent: tekrar izole ETMEMELİ.
	_ = m.Apply()
	if iso.isolateCalls != 1 {
		t.Fatalf("idempotent Apply ikinci kez izole etmemeliydi, calls=%d", iso.isolateCalls)
	}

	// Release kaldırır.
	if err := m.Release(); err != nil {
		t.Fatal(err)
	}
	if m.Active() || iso.releaseCalls != 1 {
		t.Fatalf("bir kez kaldırılmalıydı, active=%v calls=%d", m.Active(), iso.releaseCalls)
	}
	// İkinci Release idempotent.
	_ = m.Release()
	if iso.releaseCalls != 1 {
		t.Fatalf("idempotent Release ikinci kez çağırmamalıydı, calls=%d", iso.releaseCalls)
	}

	// Her başarılı geçiş bir olay üretmeli (izole + kaldır = 2).
	if buf.Len() != 2 {
		t.Fatalf("2 geçiş olayı beklenirdi, %d", buf.Len())
	}
}

func TestApplyFailureEmitsCritical(t *testing.T) {
	iso := &fakeIso{failIsolate: true}
	buf := collector.NewBuffer(100)
	m := NewManager(iso, buf, nil)

	if err := m.Apply(); err == nil {
		t.Fatal("izolasyon başarısızsa hata dönmeliydi")
	}
	if m.Active() {
		t.Fatal("başarısız izolasyonda active olmamalı")
	}
	ev := buf.Pending(1)[0]
	if ev.Severity != "CRITICAL" {
		t.Errorf("başarısız karantina CRITICAL olmalı, %s", ev.Severity)
	}
}
