package compliance

import "testing"

// fakeChecker, Evaluate'i sürücülemek için sabit sinyaller döndürür.
type fakeChecker struct{ enc, fw string }

func (f fakeChecker) DiskEncryption() string { return f.enc }
func (f fakeChecker) Firewall() string       { return f.fw }

func TestEvaluateAllPass(t *testing.T) {
	r := Evaluate(fakeChecker{EncOn, FwOn})
	if r.Passed != 2 || r.Failed != 0 || r.Unknown != 0 {
		t.Fatalf("beklenen 2/0/0, gelen %d/%d/%d", r.Passed, r.Failed, r.Unknown)
	}
	if r.ScorePct() != 100 {
		t.Fatalf("skor 100 beklenirdi, %d", r.ScorePct())
	}
	if r.HasFailure() {
		t.Fatal("hiç başarısızlık olmamalı")
	}
	if len(r.Checks) != 2 {
		t.Fatalf("2 kontrol beklenirdi, %d", len(r.Checks))
	}
}

func TestEvaluateMixed(t *testing.T) {
	// disk fail (HIGH), fw pass → skor 1/2 = %50, duruş ihlali.
	r := Evaluate(fakeChecker{EncOff, FwOn})
	if r.Passed != 1 || r.Failed != 1 || r.Unknown != 0 {
		t.Fatalf("beklenen 1/1/0, gelen %d/%d/%d", r.Passed, r.Failed, r.Unknown)
	}
	if r.ScorePct() != 50 {
		t.Fatalf("skor 50 beklenirdi (1/2), %d", r.ScorePct())
	}
	if !r.HasFailure() {
		t.Fatal("HIGH disk ihlali başarısızlık sayılmalı")
	}
	titles := r.FailedTitles()
	if len(titles) != 1 {
		t.Fatalf("1 başarısız başlık beklenirdi, %v", titles)
	}
}

func TestEvaluateUnknownExcludedFromScore(t *testing.T) {
	// fw pass, disk unknown → payda yalnız 1 (unknown skora dahil değil) → %100.
	r := Evaluate(fakeChecker{EncUnknown, FwOn})
	if r.Passed != 1 || r.Failed != 0 || r.Unknown != 1 {
		t.Fatalf("beklenen 1/0/1, gelen %d/%d/%d", r.Passed, r.Failed, r.Unknown)
	}
	if r.ScorePct() != 100 {
		t.Fatalf("bilinmeyen hariç skor 100 beklenirdi, %d", r.ScorePct())
	}
	if r.HasFailure() {
		t.Fatal("bilinmeyen kontrol başarısızlık sayılmamalı")
	}
}

func TestEvaluateAllUnknownScores100(t *testing.T) {
	r := Evaluate(fakeChecker{EncUnknown, FwUnknown})
	if r.ScorePct() != 100 {
		t.Fatalf("değerlendirilebilir kontrol yoksa skor 100, %d", r.ScorePct())
	}
	if r.HasFailure() {
		t.Fatal("bilinmeyen kontrol başarısızlık sayılmamalı")
	}
}

func TestOnlyLowFailureNotPostureViolation(t *testing.T) {
	// Katalogda LOW yok; bu test HasFailure'ın önem eşiğini korur (regresyon kalkanı).
	r := Report{Checks: []Check{{Severity: SevLow, Status: StatusFail}}}
	if r.HasFailure() {
		t.Fatal("yalnız LOW başarısızlık duruş ihlali sayılmamalı")
	}
}
