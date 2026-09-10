package adminapi

import (
	"testing"
	"time"
)

func TestLoginLimiterLocksAfterMaxFailures(t *testing.T) {
	base := time.Unix(1_000_000, 0)
	clock := base
	l := newLoginLimiter(3, 10*time.Minute)
	l.now = func() time.Time { return clock }

	// İlk (max-1) başarısızlık: hâlâ izinli.
	for i := 0; i < 2; i++ {
		l.recordFailure("1.2.3.4")
		if ok, _ := l.allowed("1.2.3.4"); !ok {
			t.Fatalf("%d. başarısızlıkta hâlâ izinli olmalıydı", i+1)
		}
	}
	// 3. başarısızlık: kilit.
	l.recordFailure("1.2.3.4")
	ok, retry := l.allowed("1.2.3.4")
	if ok {
		t.Fatal("eşik aşılınca kilitlenmeliydi")
	}
	if retry <= 0 || retry > 10*time.Minute {
		t.Fatalf("kalan kilit süresi makul olmalı: %v", retry)
	}

	// Başka istemci etkilenmemeli.
	if ok, _ := l.allowed("9.9.9.9"); !ok {
		t.Fatal("farklı istemci kilitlenmemeliydi")
	}

	// Pencere dolunca kilit kalkar.
	clock = base.Add(11 * time.Minute)
	if ok, _ := l.allowed("1.2.3.4"); !ok {
		t.Fatal("pencere dolunca kilit kalkmalıydı")
	}
}

func TestLoginLimiterSuccessResets(t *testing.T) {
	l := newLoginLimiter(3, time.Minute)
	l.recordFailure("ip")
	l.recordFailure("ip")
	l.recordSuccess("ip") // başarı sayacı sıfırlar
	// Sıfırlandığı için tekrar 2 başarısızlık kilitlememeli.
	l.recordFailure("ip")
	l.recordFailure("ip")
	if ok, _ := l.allowed("ip"); !ok {
		t.Fatal("başarılı giriş sonrası sayaç sıfırlanmalı, kilitlenmemeliydi")
	}
}

func TestRecordFailureReportsNewLockout(t *testing.T) {
	l := newLoginLimiter(3, time.Minute)
	if l.recordFailure("ip") { // 1
		t.Fatal("1. denemede kilit olmamalı")
	}
	if l.recordFailure("ip") { // 2
		t.Fatal("2. denemede kilit olmamalı")
	}
	if !l.recordFailure("ip") { // 3 → eşik → YENİ kilit
		t.Fatal("3. denemede yeni kilit bildirilmeliydi")
	}
	if l.recordFailure("ip") { // 4 → zaten kilitli, tekrar bildirme
		t.Fatal("zaten kilitliyken tekrar bildirilmemeli")
	}
}
