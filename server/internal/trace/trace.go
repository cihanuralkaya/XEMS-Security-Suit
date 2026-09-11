// Package trace, OpenTelemetry SDK'sına BAĞIMLI OLMADAN saf-Go dağıtık izleme
// (distributed tracing) ilkellerini sağlar (yol haritası §14 — Gözlemlenebilirlik).
//
// Amaç: Agent→C2 sınırını aşabilen hafif bir span/trace modeli kurmak ve bunu
// ileride bir OTLP toplayıcısına (collector) DIŞ BAĞIMLILIK EKLEMEDEN aktarabilmek.
// Paket yalnızca standart kütüphaneyi kullanır; gen/ veya db paketlerini içe almaz.
//
// Başlıca bileşenler:
//   - TraceID (16 bayt) ve SpanID (8 bayt): crypto/rand tabanlı üreticiler, hex String().
//   - Span: isim, kimlikler, zaman damgaları, öznitelikler ve durum taşıyan iş birimi.
//   - Tracer: context üzerinden ebeveyn/çocuk span bağını kuran ve tamamlanmış
//     span'ları bir Recorder'a veren üretici.
//   - Recorder/SliceRecorder: tamamlanan span'ları toplayan arayüz ve bellek-içi uyarlama.
//   - W3C Trace Context: traceparent başlığı üret/çözümle (Inject/Parse).
//   - ExportOTLPJSON: span'ları OTLP-uyumlu JSON şekline seri hale getiren hand-off.
package trace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// TraceID, bir izin (trace) tüm span'larını birbirine bağlayan 16 baytlık kimliktir.
// Sıfır değeri geçersizdir (bkz. IsValid).
type TraceID [16]byte

// SpanID, tek bir span'ı tanımlayan 8 baytlık kimliktir.
// Sıfır değeri geçersizdir (bkz. IsValid).
type SpanID [8]byte

// NewTraceID, crypto/rand ile rastgele, geçerli (sıfır-olmayan) bir TraceID üretir.
func NewTraceID() (TraceID, error) {
	var id TraceID
	if _, err := rand.Read(id[:]); err != nil {
		return TraceID{}, err
	}
	// Rastgeleliğin tümü sıfıra düşme olasılığı yok denecek kadar küçüktür; yine de
	// sıfır değerinin "geçersiz" anlamını korumak için son baytı garanti ederiz.
	if !id.IsValid() {
		id[15] = 1
	}
	return id, nil
}

// NewSpanID, crypto/rand ile rastgele, geçerli (sıfır-olmayan) bir SpanID üretir.
func NewSpanID() (SpanID, error) {
	var id SpanID
	if _, err := rand.Read(id[:]); err != nil {
		return SpanID{}, err
	}
	if !id.IsValid() {
		id[7] = 1
	}
	return id, nil
}

// IsValid, TraceID sıfırdan farklıysa true döner.
func (t TraceID) IsValid() bool {
	return t != TraceID{}
}

// String, TraceID'yi 32 karakterlik küçük-harf hex olarak döndürür.
func (t TraceID) String() string {
	return hex.EncodeToString(t[:])
}

// IsValid, SpanID sıfırdan farklıysa true döner.
func (s SpanID) IsValid() bool {
	return s != SpanID{}
}

// String, SpanID'yi 16 karakterlik küçük-harf hex olarak döndürür.
func (s SpanID) String() string {
	return hex.EncodeToString(s[:])
}

// StatusCode, bir span'ın sonucunu belirtir.
type StatusCode int

const (
	// StatusUnset, durumun henüz belirlenmediğini gösterir (varsayılan).
	StatusUnset StatusCode = iota
	// StatusOK, span'ın başarıyla tamamlandığını gösterir.
	StatusOK
	// StatusError, span sırasında bir hata oluştuğunu gösterir.
	StatusError
)

// String, StatusCode için okunabilir ad döndürür.
func (c StatusCode) String() string {
	switch c {
	case StatusOK:
		return "OK"
	case StatusError:
		return "Error"
	default:
		return "Unset"
	}
}

// Status, bir span'ın durum kodunu ve isteğe bağlı açıklamasını taşır.
type Status struct {
	Code    StatusCode
	Message string
}

// Span, izlenen tek bir iş birimini (işlem/çağrı) temsil eder.
// Alanlar doğrudan okunabilir; değiştirme için metotları kullanın.
type Span struct {
	Name         string
	TraceID      TraceID
	SpanID       SpanID
	ParentSpanID SpanID
	StartTime    time.Time
	EndTime      time.Time
	Attributes   map[string]string
	Status       Status

	mu       sync.Mutex
	now      func() time.Time
	recorder Recorder
	ended    bool
}

// SetAttr, span'a bir anahtar/değer özniteliği ekler (varsa üzerine yazar).
// Eşzamanlı-güvenlidir.
func (s *Span) SetAttr(k, v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Attributes == nil {
		s.Attributes = make(map[string]string)
	}
	s.Attributes[k] = v
}

// SetError, span durumunu StatusError yapar ve hata mesajını kaydeder.
// err nil ise hiçbir şey yapmaz.
func (s *Span) SetError(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status = Status{Code: StatusError, Message: err.Error()}
}

// SetStatus, span durumunu açıkça belirler.
func (s *Span) SetStatus(code StatusCode, msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status = Status{Code: code, Message: msg}
}

// End, span'ı "now" zamanında sonlandırır ve (ilk kez sonlandırılıyorsa) bağlı
// Recorder'a verir. now sıfır ise span'ın enjekte edilmiş saati kullanılır.
// Tekrarlı çağrılar etkisizdir (idempotent).
func (s *Span) End(now time.Time) {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	if now.IsZero() {
		now = s.clock()
	}
	s.EndTime = now
	if s.Status.Code == StatusUnset {
		s.Status.Code = StatusOK
	}
	s.ended = true
	rec := s.recorder
	s.mu.Unlock()

	if rec != nil {
		rec.Record(s)
	}
}

// clock, span'ın saatini döndürür; enjekte edilmemişse time.Now kullanılır.
func (s *Span) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// Recorder, tamamlanmış span'ları tüketen hedeftir (örn. bellek, dosya, dışa aktarıcı).
type Recorder interface {
	// Record, sonlandırılmış bir span'ı kaydeder. Uygulama eşzamanlı-güvenli olmalıdır.
	Record(*Span)
}

// SliceRecorder, span'ları bellekte toplayan eşzamanlı-güvenli bir Recorder'dır.
type SliceRecorder struct {
	mu    sync.Mutex
	spans []*Span
}

// NewSliceRecorder, boş bir SliceRecorder oluşturur.
func NewSliceRecorder() *SliceRecorder {
	return &SliceRecorder{}
}

// Record, span'ı dahili dilime ekler.
func (r *SliceRecorder) Record(s *Span) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spans = append(r.spans, s)
}

// Spans, kaydedilen span'ların bir KOPYASINI döndürür (dilim düzeyinde).
func (r *SliceRecorder) Spans() []*Span {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*Span, len(r.spans))
	copy(out, r.spans)
	return out
}

// spanContextKey, context'te geçerli span'ı saklamak için kullanılan özel anahtar türü.
type spanContextKey struct{}

// ContextWithSpan, verilen span'ı context'e yerleştirerek yeni bir context döndürür.
func ContextWithSpan(ctx context.Context, s *Span) context.Context {
	return context.WithValue(ctx, spanContextKey{}, s)
}

// SpanFromContext, context'teki geçerli span'ı döndürür; yoksa nil döner.
func SpanFromContext(ctx context.Context) *Span {
	if ctx == nil {
		return nil
	}
	s, _ := ctx.Value(spanContextKey{}).(*Span)
	return s
}

// Tracer, span üreten ve tamamlananları bir Recorder'a yönlendiren üreticidir.
// Alanlar isteğe bağlı enjekte edilebilir; nil ise güvenli varsayılanlar kullanılır.
type Tracer struct {
	// Recorder, tamamlanan span'ların verileceği hedef; nil ise span'lar atılır.
	Recorder Recorder
	// Now, zaman kaynağı; nil ise time.Now kullanılır (test için enjekte edilebilir).
	Now func() time.Time
	// NewTraceID/NewSpanID, kimlik üreticileri; nil ise crypto/rand tabanlı
	// varsayılanlar kullanılır (test için enjekte edilebilir).
	NewTraceID func() (TraceID, error)
	NewSpanID  func() (SpanID, error)
}

func (t *Tracer) clock() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

func (t *Tracer) newTraceID() (TraceID, error) {
	if t.NewTraceID != nil {
		return t.NewTraceID()
	}
	return NewTraceID()
}

func (t *Tracer) newSpanID() (SpanID, error) {
	if t.NewSpanID != nil {
		return t.NewSpanID()
	}
	return NewSpanID()
}

// StartSpan, "name" adlı yeni bir span başlatır ve onu taşıyan türetilmiş bir
// context döndürür. ctx içinde bir span varsa yeni span onun ÇOCUĞUDUR (aynı
// TraceID, ParentSpanID = mevcut span'ın SpanID'si); yoksa KÖK span üretilir
// (yeni TraceID). Kimlik üretimi başarısız olursa geçersiz kimlikli bir span
// yine de döndürülür (izleme, uygulamayı durdurmamalıdır).
func (t *Tracer) StartSpan(ctx context.Context, name string) (context.Context, *Span) {
	if ctx == nil {
		ctx = context.Background()
	}
	span := &Span{
		Name:       name,
		Attributes: make(map[string]string),
		StartTime:  t.clock(),
		now:        t.Now,
		recorder:   t.Recorder,
	}

	if parent := SpanFromContext(ctx); parent != nil && parent.TraceID.IsValid() {
		span.TraceID = parent.TraceID
		span.ParentSpanID = parent.SpanID
	} else if tid, err := t.newTraceID(); err == nil {
		span.TraceID = tid
	}

	if sid, err := t.newSpanID(); err == nil {
		span.SpanID = sid
	}

	return ContextWithSpan(ctx, span), span
}
