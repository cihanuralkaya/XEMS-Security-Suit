package chaos

import (
	"errors"
	"testing"
	"time"
)

// seq, enjekte edilebilen deterministik bir olasılık kaynağı döner: sırayla
// verilen değerleri üretir, tükenince son değeri tekrarlar.
func seq(vals ...float64) func() float64 {
	i := 0
	return func() float64 {
		v := vals[i]
		if i < len(vals)-1 {
			i++
		}
		return v
	}
}

func TestNoFaultRunsOpOnce(t *testing.T) {
	calls := 0
	fi := New(Config{}, seq(0.5), nil)
	if err := fi.Do(func() error { calls++; return nil }); err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if calls != 1 {
		t.Fatalf("op bir kez çalışmalı, oldu: %d", calls)
	}
}

func TestNilInjectorAndNilOp(t *testing.T) {
	var fi *FaultInjector
	calls := 0
	if err := fi.Do(func() error { calls++; return nil }); err != nil {
		t.Fatalf("nil injector op'u geçirmeli: %v", err)
	}
	if calls != 1 {
		t.Fatalf("nil injector op'u bir kez çalıştırmalı, oldu: %d", calls)
	}
	fi2 := New(Config{}, seq(0), nil)
	if err := fi2.Do(nil); err != nil {
		t.Fatalf("nil op nil dönmeli: %v", err)
	}
}

func TestTerminalFaults(t *testing.T) {
	myErr := errors.New("özel arıza")
	tests := []struct {
		name    string
		cfg     Config
		prob    float64 // fire için tek çekiliş
		wantErr error
		wantRun bool
		statOf  func(Stats) int
	}{
		{"drop", Config{DropProb: 1}, 0.0, ErrDropped, false, func(s Stats) int { return s.Dropped }},
		{"timeout", Config{TimeoutProb: 1}, 0.0, ErrTimeout, false, func(s Stats) int { return s.TimedOut }},
		{"fail-default", Config{FailProb: 1}, 0.0, ErrFault, false, func(s Stats) int { return s.Failed }},
		{"fail-custom", Config{FailProb: 1, FailErr: myErr}, 0.0, myErr, false, func(s Stats) int { return s.Failed }},
		{"drop-miss", Config{DropProb: 0.5}, 0.9, nil, true, func(s Stats) int { return s.Dropped }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ran := false
			fi := New(tc.cfg, seq(tc.prob), nil)
			err := fi.Do(func() error { ran = true; return nil })
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("hata = %v, beklenen %v", err, tc.wantErr)
			}
			if ran != tc.wantRun {
				t.Fatalf("op çalıştı=%v, beklenen %v", ran, tc.wantRun)
			}
			if tc.wantErr != nil && !tc.wantRun && tc.statOf(fi.Stats()) != 1 {
				t.Fatalf("sayaç 1 olmalı, stats=%+v", fi.Stats())
			}
		})
	}
}

func TestDelayAdvancesClockNoSleep(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	clk := NewClock(start)
	fi := New(Config{Delay: 2 * time.Second}, seq(0), clk)
	for i := 0; i < 3; i++ {
		if err := fi.Do(func() error { return nil }); err != nil {
			t.Fatalf("beklenmeyen hata: %v", err)
		}
	}
	if got := clk.Now().Sub(start); got != 6*time.Second {
		t.Fatalf("sanal saat 6s ilerlemeli, ilerledi: %v", got)
	}
	st := fi.Stats()
	if st.Delayed != 3 || st.TotalDelay != 6*time.Second {
		t.Fatalf("gecikme istatistikleri yanlış: %+v", st)
	}
}

func TestDuplicateInvokesOpTwice(t *testing.T) {
	calls := 0
	// İlk Do: duplicate çekilişi 0<1 → iki çağrı. İkinci Do: aynı.
	fi := New(Config{DuplicateProb: 1}, seq(0), nil)
	if err := fi.Do(func() error { calls++; return nil }); err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if calls != 2 {
		t.Fatalf("kopya op'u iki kez çağırmalı, oldu: %d", calls)
	}
	if fi.Stats().Duplicated != 1 {
		t.Fatalf("Duplicated sayacı 1 olmalı: %+v", fi.Stats())
	}
}

func TestDuplicateWithGuardNoDoubleDestructiveAction(t *testing.T) {
	destructive := 0
	g := NewGuard()
	fi := New(Config{DuplicateProb: 1}, seq(0), nil)
	// Kopya arızası op'u iki kez çağırsa da Guard yıkıcı eylemi bir kez işler.
	err := fi.Do(func() error {
		return g.Once("delete-host-42", func() error {
			destructive++
			return nil
		})
	})
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if destructive != 1 {
		t.Fatalf("yıkıcı eylem bir kez yürütülmeli, oldu: %d", destructive)
	}
	if g.Executed() != 1 {
		t.Fatalf("Guard bir benzersiz eylem saymalı, saydı: %d", g.Executed())
	}
}

func TestReorderOutOfOrderDelivery(t *testing.T) {
	var order []int
	mk := func(id int) func() error {
		return func() error { order = append(order, id); return nil }
	}
	// ReorderSize=2. İlk iki op tamponda tutulur (teslim yok). Üçüncü op gelince
	// tampon taşar; idx çekilişi 0.0 → en eski (id=1) bırakılır.
	fi := New(Config{ReorderSize: 2}, seq(0.0), nil)
	for _, id := range []int{1, 2, 3} {
		if err := fi.Do(mk(id)); err != nil {
			t.Fatalf("beklenmeyen hata: %v", err)
		}
	}
	if len(order) != 1 || order[0] != 1 {
		t.Fatalf("taşmada bir op teslim edilmeli (id=1), oldu: %v", order)
	}
	if fi.Pending() != 2 {
		t.Fatalf("tamponda 2 op kalmalı, kaldı: %d", fi.Pending())
	}
	// Flush kalanları boşaltır. Tampon [2,3] → sırayla teslim.
	if err := fi.Flush(); err != nil {
		t.Fatalf("flush hatası: %v", err)
	}
	if len(order) != 3 {
		t.Fatalf("tüm op'lar teslim edilmeli, teslim: %v", order)
	}
	if fi.Pending() != 0 {
		t.Fatalf("flush sonrası tampon boş olmalı, kaldı: %d", fi.Pending())
	}
}

func TestFlushPropagatesErrors(t *testing.T) {
	boom := errors.New("boom")
	fi := New(Config{ReorderSize: 5}, seq(0), nil)
	_ = fi.Do(func() error { return boom })
	_ = fi.Do(func() error { return nil })
	err := fi.Flush()
	if !errors.Is(err, boom) {
		t.Fatalf("flush birleşik hatada boom içermeli: %v", err)
	}
}

func TestRetryUntilEventualRecovery(t *testing.T) {
	// İlk iki deneme düşürülür (çekiliş 0.0<1), üçüncüde başarı (0.9 !<0.5? —
	// DropProb=0.5 için 0.9 ıska). Geçici arızadan otomatik kurtarmayı kanıtlar.
	fi := New(Config{DropProb: 0.5}, seq(0.0, 0.0, 0.9), nil)
	calls := 0
	tries, err := RetryUntil(fi, 5, func() error { calls++; return nil })
	if err != nil {
		t.Fatalf("eninde sonunda başarılı olmalı: %v", err)
	}
	if tries != 3 {
		t.Fatalf("3 denemede kurtarılmalı, oldu: %d", tries)
	}
	if calls != 1 {
		t.Fatalf("op yalnız başarılı denemede çalışmalı, çalıştı: %d", calls)
	}
}

func TestRetryUntilExhausted(t *testing.T) {
	fi := New(Config{FailProb: 1, FailErr: ErrDBUnavailable}, seq(0), nil)
	tries, err := RetryUntil(fi, 3, func() error { return nil })
	if !errors.Is(err, ErrDBUnavailable) {
		t.Fatalf("tükenince son hata dönmeli: %v", err)
	}
	if tries != 3 {
		t.Fatalf("3 deneme yapılmalı, yapıldı: %d", tries)
	}
}

func TestRetryUntilNilInjector(t *testing.T) {
	calls := 0
	tries, err := RetryUntil(nil, 3, func() error { calls++; return nil })
	if err != nil || tries != 1 || calls != 1 {
		t.Fatalf("nil injector op'u doğrudan bir kez çalıştırmalı: tries=%d calls=%d err=%v", tries, calls, err)
	}
}

func TestScenariosCompleteAndMapped(t *testing.T) {
	got := Scenarios()
	if len(got) != 10 {
		t.Fatalf("10 senaryo beklenir, bulundu: %d", len(got))
	}
	tests := []struct {
		s       Scenario
		name    string
		wantErr error // sonlandırıcı hata bekleniyorsa
		wantRun bool  // op çalışmalı mı
	}{
		{KillC2, "KillC2", ErrC2Down, false},
		{KillWorker, "KillWorker", ErrTimeout, false},
		{DisconnectDB, "DisconnectDB", ErrDBUnavailable, false},
		{NetworkDelay, "NetworkDelay", nil, true},
		{PacketLoss, "PacketLoss", ErrDropped, false},
		{DuplicateEvent, "DuplicateEvent", nil, true},
		{OutOfOrderEvent, "OutOfOrderEvent", nil, false}, // tamponlanır, hemen çalışmaz
		{AgentDisconnect, "AgentDisconnect", ErrDropped, false},
		{CertificateExpiration, "CertificateExpiration", ErrCertExpired, false},
		{QueueOverflow, "QueueOverflow", ErrQueueFull, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.s.String() != tc.name {
				t.Fatalf("String()=%q, beklenen %q", tc.s.String(), tc.name)
			}
			// PacketLoss/AgentDisconnect için çekiliş 0.0 → düşme garanti.
			fi := tc.s.Inject(seq(0.0), NewClock(time.Unix(0, 0)))
			ran := false
			err := fi.Do(func() error { ran = true; return nil })
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: hata=%v beklenen %v", tc.name, err, tc.wantErr)
			}
			if ran != tc.wantRun {
				t.Fatalf("%s: op çalıştı=%v beklenen %v", tc.name, ran, tc.wantRun)
			}
		})
	}
}

func TestScenarioStringUnknown(t *testing.T) {
	if Scenario(999).String() != "UnknownScenario" {
		t.Fatalf("bilinmeyen senaryo etiketi yanlış: %q", Scenario(999).String())
	}
}

func TestNetworkDelayScenarioAdvancesClock(t *testing.T) {
	start := time.Unix(100, 0)
	clk := NewClock(start)
	fi := NetworkDelay.Inject(seq(0), clk)
	if err := fi.Do(func() error { return nil }); err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if clk.Now().Sub(start) != 2*time.Second {
		t.Fatalf("NetworkDelay saati 2s ilerletmeli, ilerledi: %v", clk.Now().Sub(start))
	}
}

func TestGuardCachesResult(t *testing.T) {
	g := NewGuard()
	want := errors.New("kalıcı sonuç")
	runs := 0
	first := g.Once("k", func() error { runs++; return want })
	second := g.Once("k", func() error { runs++; return nil })
	if !errors.Is(first, want) || !errors.Is(second, want) {
		t.Fatalf("Guard ilk sonucu belleğe almalı: first=%v second=%v", first, second)
	}
	if runs != 1 {
		t.Fatalf("action bir kez çalışmalı, çalıştı: %d", runs)
	}
}
