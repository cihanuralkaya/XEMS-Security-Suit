package dedup

import (
	"testing"
	"time"
)

func TestDuplicateWindow(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	s := New(5*time.Minute, 100)
	s.now = func() time.Time { return cur }

	if s.Duplicate("evt_a") {
		t.Fatal("ilk görülme yineleme olmamalı")
	}
	if !s.Duplicate("evt_a") {
		t.Fatal("pencere içinde tekrar yineleme olmalı")
	}
	if s.Duplicate("evt_b") {
		t.Fatal("farklı id yineleme olmamalı")
	}
	// Pencere geçince yeniden kabul.
	cur = base.Add(6 * time.Minute)
	if s.Duplicate("evt_a") {
		t.Fatal("pencere geçtikten sonra yeniden kabul edilmeli (yineleme değil)")
	}
}

func TestEmptyAndDisabled(t *testing.T) {
	s := New(time.Minute, 10)
	if s.Duplicate("") {
		t.Error("boş id asla yineleme olmamalı")
	}
	off := New(0, 10)
	if off.Duplicate("x") || off.Duplicate("x") {
		t.Error("window<=0 devre dışı olmalı (her zaman false)")
	}
}

func TestMaxEviction(t *testing.T) {
	s := New(time.Hour, 2) // en çok 2 girdi
	s.Duplicate("a")
	s.Duplicate("b")
	s.Duplicate("c") // "a" tahliye edilmeli (FIFO)
	if s.Len() != 2 {
		t.Fatalf("azami boyut 2 olmalı, %d", s.Len())
	}
	if s.Duplicate("a") {
		t.Error("tahliye edilen 'a' yeniden ilk-görülme olmalı (yineleme değil)")
	}
}

func TestNilSafe(t *testing.T) {
	var s *Seen
	if s.Duplicate("x") || s.Len() != 0 {
		t.Error("nil Seen güvenli olmalı")
	}
}
