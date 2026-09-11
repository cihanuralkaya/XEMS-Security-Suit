package dlq

import (
	"errors"
	"testing"
	"time"
)

func TestEnqueueRetrySuccess(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	q := New(10, time.Second, time.Minute, func() time.Time { return cur })
	q.Enqueue("d1", []int{1, 2, 3})
	if q.Len() != 1 {
		t.Fatalf("kuyrukta 1 olmalı, %d", q.Len())
	}
	// başarılı retry → kuyruktan çıkar
	n := q.Retry(func(*Item) error { return nil })
	if n != 1 || q.Len() != 0 {
		t.Fatalf("başarılı retry girdiyi çıkarmalı: n=%d len=%d", n, q.Len())
	}
}

func TestRetryBackoffAndPersistence(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	cur := base
	q := New(10, time.Second, time.Minute, func() time.Time { return cur })
	q.Enqueue("d1", "x")
	fail := func(*Item) error { return errors.New("db down") }

	// ilk retry başarısız → kuyrukta kalır, NextRetry ileri (backoff)
	if n := q.Retry(fail); n != 0 || q.Len() != 1 {
		t.Fatalf("başarısız retry kuyrukta tutmalı: n=%d len=%d", n, q.Len())
	}
	// süresi gelmeden ikinci retry: due değil → işlenmez
	if n := q.Retry(fail); n != 0 {
		t.Fatalf("backoff süresi gelmeden işlenmemeli: %d", n)
	}
	// zamanı ilerlet → due olur, sonra başarı ile çıkar
	cur = base.Add(5 * time.Second)
	if n := q.Retry(func(*Item) error { return nil }); n != 1 || q.Len() != 0 {
		t.Fatalf("süre gelince başarı ile çıkmalı: n=%d len=%d", n, q.Len())
	}
}

func TestCapacityDropsOldest(t *testing.T) {
	q := New(2, time.Second, time.Minute, nil)
	q.Enqueue("a", 1)
	q.Enqueue("b", 2)
	q.Enqueue("c", 3) // "a" düşer
	if q.Len() != 2 || q.Dropped() != 1 {
		t.Fatalf("kapasite: len=%d dropped=%d (beklenen 2/1)", q.Len(), q.Dropped())
	}
}

func TestBackoffCap(t *testing.T) {
	q := New(1, time.Second, 4*time.Second, nil)
	// attempts arttıkça backoff maxWait'i aşmamalı
	if got := q.backoff(1); got != 2*time.Second {
		t.Errorf("backoff(1)=%v, beklenen 2s", got)
	}
	if got := q.backoff(10); got != 4*time.Second {
		t.Errorf("backoff(10) maxWait=4s ile sınırlı olmalı, %v", got)
	}
}
