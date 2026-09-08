package correlate

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type fakeSink struct {
	opened, bumped, n int
}

func (f *fakeSink) OpenIncident(_ context.Context, _, _, _, _, _, _ string, _ time.Time) (string, error) {
	f.opened++
	f.n++
	return fmt.Sprintf("inc-%d", f.n), nil
}
func (f *fakeSink) BumpIncident(context.Context, string, time.Time) error {
	f.bumped++
	return nil
}

// Pencere içinde aynı cihaz+kural tekrarı BASTIRILMALI ve aynı incident'e katlanmalı;
// farklı kural yeni incident açmalı.
func TestCorrelatorSuppressesWithinWindow(t *testing.T) {
	fake := &fakeSink{}
	c := New(time.Hour, fake)
	base := time.Now()
	c.now = func() time.Time { return base }
	ctx := context.Background()

	id1, sup1 := c.Observe(ctx, "dev1", "R1", "T1", "HIGH", "msg")
	if sup1 || id1 == "" || fake.opened != 1 {
		t.Fatalf("ilk tespit yeni incident açmalı, bastırılmamalı: sup=%v id=%q opened=%d", sup1, id1, fake.opened)
	}
	id2, sup2 := c.Observe(ctx, "dev1", "R1", "T1", "HIGH", "msg2")
	if !sup2 || id2 != id1 || fake.bumped != 1 || fake.opened != 1 {
		t.Fatalf("penceredeki tekrar aynı incident'e katlanıp bastırılmalı: sup=%v id=%q bumped=%d opened=%d", sup2, id2, fake.bumped, fake.opened)
	}
	if _, sup3 := c.Observe(ctx, "dev1", "R2", "T2", "LOW", "x"); sup3 || fake.opened != 2 {
		t.Fatalf("farklı kural yeni incident açmalı: sup=%v opened=%d", sup3, fake.opened)
	}
}

// Pencere dolduktan sonra aynı anahtar YENİ incident açmalı (bastırma yok).
func TestCorrelatorReopensAfterWindow(t *testing.T) {
	fake := &fakeSink{}
	c := New(10*time.Minute, fake)
	base := time.Now()
	c.now = func() time.Time { return base }
	ctx := context.Background()

	c.Observe(ctx, "d", "R", "T", "HIGH", "m")
	base = base.Add(11 * time.Minute) // pencere geçti
	if _, sup := c.Observe(ctx, "d", "R", "T", "HIGH", "m"); sup || fake.opened != 2 {
		t.Fatalf("pencere sonrası yeni incident beklenir: sup=%v opened=%d", sup, fake.opened)
	}
	if c.OpenCount() != 1 {
		t.Fatalf("süresi dolan pencere budanmalı, açık=%d", c.OpenCount())
	}
}
