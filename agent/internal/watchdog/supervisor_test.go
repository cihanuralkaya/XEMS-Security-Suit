package watchdog

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// fakeRunner, senaryolanmış çıkış sonuçları döndürür ve tükendiğinde ctx'i iptal
// ederek gözetim döngüsünü sonlandırır.
type fakeRunner struct {
	results   []error
	durations []time.Duration
	i         int
	calls     int
	clock     *fakeClock
	cancel    context.CancelFunc
}

func (r *fakeRunner) Run(_ context.Context) error {
	r.calls++
	if r.i >= len(r.results) {
		r.cancel()
		return context.Canceled
	}
	res := r.results[r.i]
	r.clock.advance(r.durations[r.i])
	r.i++
	return res
}

type fakeSwapper struct {
	staged        bool
	version       string
	swapCalls     int
	rollbackCalls int
}

func (s *fakeSwapper) PendingStaged() (string, string, bool) {
	if s.staged {
		return s.version, "p", true
	}
	return "", "", false
}
func (s *fakeSwapper) Swap() error     { s.swapCalls++; s.staged = false; return nil }
func (s *fakeSwapper) Rollback() error { s.rollbackCalls++; return nil }

func newSup(t *testing.T, runner Runner, swapper Swapper, sleeps *int) (*Supervisor, context.Context) {
	t.Helper()
	clock := &fakeClock{t: time.Unix(0, 0)}
	if fr, ok := runner.(*fakeRunner); ok {
		fr.clock = clock
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if fr, ok := runner.(*fakeRunner); ok {
		fr.cancel = cancel
	}
	sup := NewSupervisor(runner, swapper, Options{
		TrialWindow: 10 * time.Second,
		Now:         clock.now,
		Sleep:       func(time.Duration) { *sleeps++ },
	})
	return sup, ctx
}

func TestRestartOnCrash(t *testing.T) {
	crash := errors.New("çöktü")
	runner := &fakeRunner{
		results:   []error{crash, crash, nil}, // iki çökme, bir temiz çıkış
		durations: []time.Duration{time.Second, time.Second, time.Second},
	}
	sw := &fakeSwapper{}
	sleeps := 0
	sup, ctx := newSup(t, runner, sw, &sleeps)
	_ = sup.Run(ctx)

	if sleeps != 2 {
		t.Fatalf("2 çökme için 2 backoff-uykusu beklenirdi, %d", sleeps)
	}
	if runner.i != 3 {
		t.Fatalf("3 senaryolanmış çalıştırma tüketilmeliydi, %d", runner.i)
	}
}

func TestInstantCleanExitDoesNotBusyLoop(t *testing.T) {
	// Ajan anında (0 süre) ve temiz (nil) çıkarsa, her turda uyku çağrılmalı —
	// yoksa süreç sonsuz hızda yeniden başlatılır (kendine-DoS).
	runner := &fakeRunner{
		results:   []error{nil, nil},
		durations: []time.Duration{0, 0},
	}
	sleeps := 0
	sup, ctx := newSup(t, runner, &fakeSwapper{}, &sleeps)
	_ = sup.Run(ctx)

	if sleeps < 2 {
		t.Fatalf("anında temiz çıkışlarda busy-loop'u önlemek için uyku beklenirdi, %d", sleeps)
	}
}

func TestSwapThenRollbackOnFastCrash(t *testing.T) {
	crash := errors.New("yeni sürüm çöktü")
	runner := &fakeRunner{
		results:   []error{crash},               // swap sonrası ilk çalıştırma çöker
		durations: []time.Duration{time.Second}, // trialWindow (10s) içinde
	}
	sw := &fakeSwapper{staged: true, version: "2.0.0"}
	sleeps := 0
	sup, ctx := newSup(t, runner, sw, &sleeps)
	_ = sup.Run(ctx)

	if sw.swapCalls != 1 {
		t.Fatalf("bir swap beklenirdi, %d", sw.swapCalls)
	}
	if sw.rollbackCalls != 1 {
		t.Fatalf("deneme penceresinde çöküş için bir rollback beklenirdi, %d", sw.rollbackCalls)
	}
}

func TestSwapCleanNoRollback(t *testing.T) {
	runner := &fakeRunner{
		results:   []error{nil}, // swap sonrası temiz çalıştı
		durations: []time.Duration{time.Second},
	}
	sw := &fakeSwapper{staged: true, version: "2.0.0"}
	sleeps := 0
	sup, ctx := newSup(t, runner, sw, &sleeps)
	_ = sup.Run(ctx)

	if sw.swapCalls != 1 {
		t.Fatalf("bir swap beklenirdi, %d", sw.swapCalls)
	}
	if sw.rollbackCalls != 0 {
		t.Fatalf("temiz çalışan sürüm rollback ETMEMELİ, %d", sw.rollbackCalls)
	}
}

func TestStandDownStopsSupervision(t *testing.T) {
	// Runner asla çağrılmamalı: stand-down işareti daha ilk turda döngüyü durdurur.
	runner := &fakeRunner{
		results:   []error{errors.New("çöktü")},
		durations: []time.Duration{time.Second},
	}
	sw := &fakeSwapper{}
	sleeps := 0
	clock := &fakeClock{t: time.Unix(0, 0)}
	runner.clock = clock
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	runner.cancel = cancel

	sup := NewSupervisor(runner, sw, Options{
		StandDown: func() bool { return true },
		Now:       clock.now,
		Sleep:     func(time.Duration) { sleeps++ },
	})
	if err := sup.Run(ctx); err != nil {
		t.Fatalf("stand-down temiz (nil) dönmeli, %v", err)
	}
	if runner.calls != 0 {
		t.Fatalf("stand-down ajanı hiç başlatmamalı, %d çağrı", runner.calls)
	}
	if sleeps != 0 {
		t.Fatalf("stand-down uyku olmadan çıkmalı, %d", sleeps)
	}
}

func TestStandDownAfterCleanExit(t *testing.T) {
	// Ajan bir kez temiz çıkar; ikinci turda işaret görünür → yeniden başlatılmaz.
	runner := &fakeRunner{
		results:   []error{nil},
		durations: []time.Duration{100 * time.Millisecond}, // baseBackoff'tan kısa → temiz-çıkış uykusu tetiklenir
	}
	sw := &fakeSwapper{}
	sleeps := 0
	clock := &fakeClock{t: time.Unix(0, 0)}
	runner.clock = clock
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	runner.cancel = cancel

	down := false
	sup := NewSupervisor(runner, sw, Options{
		StandDown: func() bool { return down },
		Now:       clock.now,
		Sleep:     func(time.Duration) { sleeps++; down = true }, // temiz-çıkış sonrası işaret belirir
	})
	if err := sup.Run(ctx); err != nil {
		t.Fatalf("nil beklenirdi, %v", err)
	}
	if runner.calls != 1 {
		t.Fatalf("ajan tam bir kez çalışmalı, %d", runner.calls)
	}
}
