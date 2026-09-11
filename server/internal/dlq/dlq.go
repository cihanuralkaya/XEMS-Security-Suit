// Package dlq, olay boru-hattı için ÖLÜ-MEKTUP KUYRUĞU (dead-letter queue) sağlar
// (§6). Kalıcılaştırılamayan (ör. DB geçici erişilemez) olay grupları sessizce
// kaybolmak yerine sınırlı-bellekli bir kuyruğa alınır ve üstel geri-çekilmeyle
// yeniden denenir. Kuyruk dolarsa EN ESKİ girdi düşürülür (sayaçla görünür), böylece
// bellek sınırlı kalır. Saf-Go, eşzamanlı-güvenli; zaman enjekte edilebilir.
package dlq

import (
	"sync"
	"time"
)

// Item, yeniden denenecek tek bir ölü-mektup girdisidir (jenerik yük).
type Item struct {
	Key       string    // gruplama/teşhis anahtarı (ör. device_id)
	Payload   any       // yeniden işlenecek yük (ör. []model.Event)
	Attempts  int       // şimdiye dek deneme sayısı
	FirstSeen time.Time // ilk kuyruğa alınma
	NextRetry time.Time // sonraki deneme zamanı (backoff)
}

// Queue, sınırlı-bellekli bir ölü-mektup kuyruğudur.
type Queue struct {
	mu       sync.Mutex
	items    []*Item
	max      int
	baseWait time.Duration
	maxWait  time.Duration
	now      func() time.Time
	dropped  int // kapasite aşımından düşürülen girdi sayısı
}

// New, en çok max girdilik bir kuyruk kurar. baseWait ilk backoff, maxWait tavan.
// now nil → time.Now. max<1 → 1.
func New(max int, baseWait, maxWait time.Duration, now func() time.Time) *Queue {
	if max < 1 {
		max = 1
	}
	if now == nil {
		now = time.Now
	}
	if baseWait <= 0 {
		baseWait = time.Second
	}
	if maxWait < baseWait {
		maxWait = baseWait
	}
	return &Queue{max: max, baseWait: baseWait, maxWait: maxWait, now: now}
}

// Enqueue, bir yükü kuyruğa alır (ilk deneme). Kuyruk doluysa en eski düşürülür.
func (q *Queue) Enqueue(key string, payload any) {
	q.mu.Lock()
	defer q.mu.Unlock()
	now := q.now()
	it := &Item{Key: key, Payload: payload, Attempts: 0, FirstSeen: now, NextRetry: now}
	q.items = append(q.items, it)
	for len(q.items) > q.max {
		q.items = q.items[1:] // en eskiyi düşür
		q.dropped++
	}
}

// backoff, deneme sayısına göre üstel bekleme döner (baseWait*2^attempts, maxWait tavanlı).
func (q *Queue) backoff(attempts int) time.Duration {
	d := q.baseWait
	for i := 0; i < attempts && d < q.maxWait; i++ {
		d *= 2
	}
	if d > q.maxWait {
		d = q.maxWait
	}
	return d
}

// Retry, süresi gelen (NextRetry <= now) girdileri fn ile yeniden işler. fn nil hata
// dönerse girdi kuyruktan çıkar (başarı); hata dönerse deneme sayısı artar ve backoff
// ile yeniden zamanlanır. İşlenen (başarılı) girdi sayısını döner. fn kuyruk kilidi
// TUTULMADAN çağrılır (uzun/bloklayan iş güvenli).
func (q *Queue) Retry(fn func(*Item) error) (succeeded int) {
	now := q.now()
	q.mu.Lock()
	due := make([]*Item, 0)
	rest := make([]*Item, 0, len(q.items))
	for _, it := range q.items {
		if !it.NextRetry.After(now) {
			due = append(due, it)
		} else {
			rest = append(rest, it)
		}
	}
	q.items = rest // süresi gelmeyenler kalır; gelenler işlenip gerekirse geri eklenir
	q.mu.Unlock()

	var requeue []*Item
	for _, it := range due {
		if err := fn(it); err == nil {
			succeeded++
			continue
		}
		it.Attempts++
		it.NextRetry = now.Add(q.backoff(it.Attempts))
		requeue = append(requeue, it)
	}

	if len(requeue) > 0 {
		q.mu.Lock()
		q.items = append(q.items, requeue...)
		for len(q.items) > q.max {
			q.items = q.items[1:]
			q.dropped++
		}
		q.mu.Unlock()
	}
	return succeeded
}

// Len, kuyruktaki girdi sayısını döner (queue-depth gözlemi).
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// Dropped, kapasite aşımından şimdiye dek düşürülen girdi sayısını döner.
func (q *Queue) Dropped() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}
