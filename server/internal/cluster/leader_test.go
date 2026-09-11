package cluster

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSingleLeaderAmongNodes(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	store := NewMemLeaseStore(func() time.Time { return cur })
	ttl := 30 * time.Second

	a := NewElector(store, "maint", "node-a", ttl, 10*time.Second, func() time.Time { return cur })
	b := NewElector(store, "maint", "node-b", ttl, 10*time.Second, func() time.Time { return cur })
	ctx := context.Background()

	// node-a önce alır → lider
	if err := a.Step(ctx); err != nil || !a.IsLeader() {
		t.Fatalf("node-a lider olmalı: %v", err)
	}
	// node-b kira dolu → lider OLAMAZ
	if err := b.Step(ctx); err != nil || b.IsLeader() {
		t.Fatalf("node-b lider olmamalı (kira a'da): %v", err)
	}
	// a yeniler → hâlâ lider
	cur = base.Add(10 * time.Second)
	_ = a.Step(ctx)
	if !a.IsLeader() {
		t.Fatal("a yenileme sonrası lider kalmalı")
	}
	// a çöker (yenilemez), kira süresi dolar → b devralır (failover)
	cur = base.Add(45 * time.Second)
	if err := b.Step(ctx); err != nil || !b.IsLeader() {
		t.Fatalf("b failover ile lider olmalı: %v", err)
	}
	// a bir sonraki step'te liderliği kaybeder (kira artık b'de)
	_ = a.Step(ctx)
	if a.IsLeader() {
		t.Fatal("a liderliği kaybetmeli (kira b'de)")
	}
}

func TestReleaseAllowsImmediateTakeover(t *testing.T) {
	store := NewMemLeaseStore(nil)
	a := NewElector(store, "k", "a", time.Minute, 20*time.Second, nil)
	b := NewElector(store, "k", "b", time.Minute, 20*time.Second, nil)
	ctx := context.Background()
	_ = a.Step(ctx)
	if err := store.Release(ctx, "k", "a"); err != nil {
		t.Fatal(err)
	}
	if err := b.Step(ctx); err != nil || !b.IsLeader() {
		t.Fatal("release sonrası b hemen devralmalı")
	}
}

type errStore struct{ err error }

func (e errStore) TryAcquire(context.Context, string, string, time.Duration) (bool, error) {
	return false, e.err
}
func (e errStore) Release(context.Context, string, string) error { return nil }

func TestStoreErrorStepsDown(t *testing.T) {
	boom := errors.New("db down")
	e := NewElector(errStore{boom}, "k", "a", time.Minute, 20*time.Second, nil)
	// önce lider yapalım (durum), sonra hata → step-down
	e.setLeader(true)
	if err := e.Step(context.Background()); !errors.Is(err, boom) {
		t.Fatalf("hata dönmeli: %v", err)
	}
	if e.IsLeader() {
		t.Fatal("depo hatasında fail-closed step-down olmalı")
	}
}

func TestOnChangeCallback(t *testing.T) {
	store := NewMemLeaseStore(nil)
	var states []bool
	e := NewElector(store, "k", "a", time.Minute, 20*time.Second, nil).
		OnChange(func(l bool) { states = append(states, l) })
	_ = e.Step(context.Background()) // false→true
	e.setLeader(false)               // true→false
	if len(states) != 2 || states[0] != true || states[1] != false {
		t.Fatalf("değişim geri-çağrıları: %v", states)
	}
}
