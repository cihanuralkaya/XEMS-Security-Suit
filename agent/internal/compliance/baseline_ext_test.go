package compliance

import "testing"

// baseChecker, yalnız temel Checker'ı uygular (ExtendedChecker DEĞİL).
type baseChecker struct{ enc, fw string }

func (b baseChecker) DiskEncryption() string { return b.enc }
func (b baseChecker) Firewall() string       { return b.fw }

// extChecker, hem temel hem ExtendedChecker'ı uygular.
type extChecker struct {
	baseChecker
	patch, auto, lock, pass, app string
}

func (e extChecker) PatchStatus() string    { return e.patch }
func (e extChecker) AutoUpdate() string     { return e.auto }
func (e extChecker) ScreenLock() string     { return e.lock }
func (e extChecker) PasswordPolicy() string { return e.pass }
func (e extChecker) AppControl() string     { return e.app }

func TestEvaluateBaseOnly_NoExtendedChecks(t *testing.T) {
	r := Evaluate(baseChecker{enc: EncOn, fw: FwOn})
	if len(r.Checks) != 2 {
		t.Fatalf("temel checker yalnız 2 kontrol üretmeli, %d", len(r.Checks))
	}
}

func TestEvaluateExtended(t *testing.T) {
	r := Evaluate(extChecker{
		baseChecker: baseChecker{enc: EncOn, fw: FwOn},
		patch:       PatchOutdated, auto: SignalOn, lock: SignalOff, pass: SignalOn, app: "unknown",
	})
	if len(r.Checks) != 7 {
		t.Fatalf("genişletilmiş: 2 temel + 5 ek = 7 kontrol beklenir, %d", len(r.Checks))
	}
	// yama outdated → fail; ekran kilidi off → fail; app unknown → skora girmez
	byID := map[string]Check{}
	for _, c := range r.Checks {
		byID[c.ID] = c
	}
	if byID["CIS-3.1"].Status != StatusFail {
		t.Errorf("outdated yama fail olmalı: %+v", byID["CIS-3.1"])
	}
	if byID["CIS-5.1"].Status != StatusFail {
		t.Errorf("ekran kilidi off fail olmalı")
	}
	if byID["CIS-2.1"].Status != StatusUnknown {
		t.Errorf("app-control unknown olmalı")
	}
	if !r.HasFailure() {
		t.Error("HIGH yama başarısızlığı duruş ihlali sayılmalı")
	}
}
