package trace

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestIDValidityAndString(t *testing.T) {
	tests := []struct {
		name    string
		valid   bool
		traceID TraceID
		spanID  SpanID
		wantTS  string // TraceID.String() (sadece geçerli olanlar için kontrol)
		wantSS  string
	}{
		{name: "zero", valid: false},
		{
			name:    "nonzero",
			valid:   true,
			traceID: TraceID{0x01, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff},
			spanID:  SpanID{0xaa, 0, 0, 0, 0, 0, 0, 0x01},
			wantTS:  "0102000000000000000000000000000000ff"[:32],
			wantSS:  "aa00000000000001",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.traceID.IsValid(); got != tt.valid {
				t.Errorf("TraceID.IsValid()=%v, istenen %v", got, tt.valid)
			}
			if got := tt.spanID.IsValid(); got != tt.valid {
				t.Errorf("SpanID.IsValid()=%v, istenen %v", got, tt.valid)
			}
			if tt.valid {
				if got := tt.traceID.String(); len(got) != 32 {
					t.Errorf("TraceID.String() uzunluğu %d, istenen 32", len(got))
				}
				if got := tt.spanID.String(); got != tt.wantSS {
					t.Errorf("SpanID.String()=%q, istenen %q", got, tt.wantSS)
				}
			}
		})
	}
}

func TestNewIDsAreValidAndUnique(t *testing.T) {
	seenT := make(map[TraceID]bool)
	seenS := make(map[SpanID]bool)
	for i := 0; i < 1000; i++ {
		tid, err := NewTraceID()
		if err != nil {
			t.Fatalf("NewTraceID hata: %v", err)
		}
		if !tid.IsValid() {
			t.Fatal("NewTraceID geçersiz kimlik üretti")
		}
		if seenT[tid] {
			t.Fatal("NewTraceID çakışan kimlik üretti")
		}
		seenT[tid] = true

		sid, err := NewSpanID()
		if err != nil {
			t.Fatalf("NewSpanID hata: %v", err)
		}
		if !sid.IsValid() {
			t.Fatal("NewSpanID geçersiz kimlik üretti")
		}
		if seenS[sid] {
			t.Fatal("NewSpanID çakışan kimlik üretti")
		}
		seenS[sid] = true
	}
}

func TestSpanSetAttrAndError(t *testing.T) {
	s := &Span{}
	s.SetAttr("k1", "v1")
	s.SetAttr("k1", "v2") // üzerine yaz
	s.SetAttr("k2", "v3")
	if s.Attributes["k1"] != "v2" {
		t.Errorf("k1=%q, istenen v2", s.Attributes["k1"])
	}
	if s.Attributes["k2"] != "v3" {
		t.Errorf("k2=%q, istenen v3", s.Attributes["k2"])
	}

	s.SetError(nil)
	if s.Status.Code != StatusUnset {
		t.Errorf("nil hata durumu değiştirmemeli, kod=%v", s.Status.Code)
	}
	s.SetError(errors.New("boom"))
	if s.Status.Code != StatusError || s.Status.Message != "boom" {
		t.Errorf("SetError durumu=%+v", s.Status)
	}
}

func TestSpanEndIdempotentAndStatusDefault(t *testing.T) {
	rec := NewSliceRecorder()
	base := time.Unix(1_700_000_000, 0).UTC()
	s := &Span{Name: "x", recorder: rec, now: func() time.Time { return base }}

	// now=zero -> enjekte edilmiş saat kullanılır, durum OK olur.
	s.End(time.Time{})
	if !s.EndTime.Equal(base) {
		t.Errorf("EndTime=%v, istenen %v", s.EndTime, base)
	}
	if s.Status.Code != StatusOK {
		t.Errorf("varsayılan durum kodu=%v, istenen OK", s.Status.Code)
	}

	// İkinci çağrı etkisiz olmalı (kayıt bir kez).
	s.End(base.Add(time.Hour))
	if got := len(rec.Spans()); got != 1 {
		t.Fatalf("kayıt sayısı=%d, istenen 1", got)
	}
	if !s.EndTime.Equal(base) {
		t.Errorf("ikinci End EndTime'ı değiştirdi: %v", s.EndTime)
	}
}

func TestStatusCodeString(t *testing.T) {
	tests := []struct {
		code StatusCode
		want string
	}{
		{StatusUnset, "Unset"},
		{StatusOK, "OK"},
		{StatusError, "Error"},
		{StatusCode(99), "Unset"},
	}
	for _, tt := range tests {
		if got := tt.code.String(); got != tt.want {
			t.Errorf("StatusCode(%d).String()=%q, istenen %q", tt.code, got, tt.want)
		}
	}
}

func TestTracerRootSpan(t *testing.T) {
	rec := NewSliceRecorder()
	base := time.Unix(1_700_000_000, 0).UTC()
	tr := &Tracer{Recorder: rec, Now: func() time.Time { return base }}

	ctx, span := tr.StartSpan(context.Background(), "root")
	if !span.TraceID.IsValid() {
		t.Fatal("kök span geçerli TraceID almalı")
	}
	if span.ParentSpanID.IsValid() {
		t.Error("kök span'ın ebeveyni olmamalı")
	}
	if !span.StartTime.Equal(base) {
		t.Errorf("StartTime=%v, istenen %v", span.StartTime, base)
	}
	if SpanFromContext(ctx) != span {
		t.Error("context geçerli span'ı taşımalı")
	}
	span.End(time.Time{})
	if len(rec.Spans()) != 1 {
		t.Errorf("kayıt sayısı=%d, istenen 1", len(rec.Spans()))
	}
}

func TestTracerChildLinkage(t *testing.T) {
	rec := NewSliceRecorder()
	tr := &Tracer{Recorder: rec}

	ctx, parent := tr.StartSpan(context.Background(), "parent")
	_, child := tr.StartSpan(ctx, "child")

	if child.TraceID != parent.TraceID {
		t.Error("çocuk, ebeveynle aynı TraceID'yi taşımalı")
	}
	if child.ParentSpanID != parent.SpanID {
		t.Error("çocuğun ParentSpanID'si ebeveyn SpanID olmalı")
	}
	if child.SpanID == parent.SpanID {
		t.Error("çocuğun SpanID'si ebeveyninkinden farklı olmalı")
	}
}

func TestTracerNilContextAndNoRecorder(t *testing.T) {
	tr := &Tracer{} // recorder yok, saat yok
	//nolint
	ctx, span := tr.StartSpan(nil, "orphan")
	if ctx == nil || span == nil {
		t.Fatal("nil context güvenle ele alınmalı")
	}
	if !span.TraceID.IsValid() {
		t.Error("kök span geçerli TraceID almalı")
	}
	// Recorder yokken End panik atmamalı.
	span.End(time.Now())
}

func TestSliceRecorderConcurrentAndCopy(t *testing.T) {
	rec := NewSliceRecorder()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec.Record(&Span{Name: "s"})
		}()
	}
	wg.Wait()
	got := rec.Spans()
	if len(got) != 50 {
		t.Fatalf("kayıt sayısı=%d, istenen 50", len(got))
	}
	// Spans() kopya döndürmeli: döneni değiştirmek dahili durumu etkilememeli.
	got[0] = nil
	if rec.Spans()[0] == nil {
		t.Error("Spans() kopya döndürmeli, dahili dilim korunmalı")
	}
}

func TestContextWithSpanRoundTrip(t *testing.T) {
	if SpanFromContext(context.Background()) != nil {
		t.Error("boş context'te span olmamalı")
	}
	//nolint
	if SpanFromContext(nil) != nil {
		t.Error("nil context nil span döndürmeli")
	}
	s := &Span{Name: "x"}
	ctx := ContextWithSpan(context.Background(), s)
	if SpanFromContext(ctx) != s {
		t.Error("span round-trip başarısız")
	}
}

func TestTraceparentRoundTrip(t *testing.T) {
	tr := &Tracer{}
	_, span := tr.StartSpan(context.Background(), "x")

	header := InjectTraceparent(span)
	if header == "" {
		t.Fatal("geçerli span boş olmayan traceparent üretmeli")
	}
	tid, sid, ok := ParseTraceparent(header)
	if !ok {
		t.Fatalf("round-trip çözümlemesi başarısız: %q", header)
	}
	if tid != span.TraceID {
		t.Error("çözümlenen TraceID eşleşmiyor")
	}
	if sid != span.SpanID {
		t.Error("çözümlenen SpanID eşleşmiyor")
	}
}

func TestInjectTraceparentInvalidSpan(t *testing.T) {
	if got := InjectTraceparent(nil); got != "" {
		t.Errorf("nil span için boş beklenir, %q", got)
	}
	if got := InjectTraceparent(&Span{}); got != "" {
		t.Errorf("geçersiz kimlikli span için boş beklenir, %q", got)
	}
}

func TestParseTraceparentMalformed(t *testing.T) {
	valid := "00-0102030405060708090a0b0c0d0e0f10-0102030405060708-01"
	tests := []struct {
		name   string
		header string
	}{
		{"empty", ""},
		{"too few parts", "00-abc-def"},
		{"too many parts", valid + "-extra"},
		{"bad version", "01-0102030405060708090a0b0c0d0e0f10-0102030405060708-01"},
		{"short trace", "00-0102-0102030405060708-01"},
		{"short span", "00-0102030405060708090a0b0c0d0e0f10-0102-01"},
		{"bad flag len", "00-0102030405060708090a0b0c0d0e0f10-0102030405060708-1"},
		{"non-hex trace", "00-zz02030405060708090a0b0c0d0e0f10-0102030405060708-01"},
		{"non-hex span", "00-0102030405060708090a0b0c0d0e0f10-zz02030405060708-01"},
		{"non-hex flag", "00-0102030405060708090a0b0c0d0e0f10-0102030405060708-zz"},
		{"zero trace", "00-00000000000000000000000000000000-0102030405060708-01"},
		{"zero span", "00-0102030405060708090a0b0c0d0e0f10-0000000000000000-01"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, ok := ParseTraceparent(tt.header); ok {
				t.Errorf("hatalı girdi ok=true döndürdü: %q", tt.header)
			}
		})
	}

	// Geçerli girdi (baştaki/sondaki boşlukla) ok=true dönmeli.
	if _, _, ok := ParseTraceparent("  " + valid + "  "); !ok {
		t.Error("geçerli traceparent (boşluklu) ok=true dönmeli")
	}
}

func TestExportOTLPJSONShape(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	tr := &Tracer{
		Now: func() time.Time { return base },
		NewTraceID: func() (TraceID, error) {
			return TraceID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}, nil
		},
		NewSpanID: func() (SpanID, error) {
			return SpanID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, nil
		},
	}
	_, span := tr.StartSpan(context.Background(), "op")
	span.SetAttr("b", "2")
	span.SetAttr("a", "1")
	span.SetError(errors.New("kaboom"))
	span.End(base.Add(5 * time.Second))

	raw, err := ExportOTLPJSON([]*Span{span, nil})
	if err != nil {
		t.Fatalf("ExportOTLPJSON hata: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("çıktı geçerli JSON değil: %v\n%s", err, raw)
	}

	rs, ok := doc["resourceSpans"].([]any)
	if !ok || len(rs) != 1 {
		t.Fatalf("resourceSpans şekli beklenmedik: %v", doc)
	}
	ss := rs[0].(map[string]any)["scopeSpans"].([]any)
	scope := ss[0].(map[string]any)
	spans := scope["spans"].([]any)
	if len(spans) != 1 {
		t.Fatalf("span sayısı=%d, istenen 1 (nil atlanmalı)", len(spans))
	}
	sp := spans[0].(map[string]any)

	if sp["traceId"] != "0102030405060708090a0b0c0d0e0f10" {
		t.Errorf("traceId=%v", sp["traceId"])
	}
	if sp["spanId"] != "0102030405060708" {
		t.Errorf("spanId=%v", sp["spanId"])
	}
	if sp["name"] != "op" {
		t.Errorf("name=%v", sp["name"])
	}
	if sp["startTimeUnixNano"] != "1700000000000000000" {
		t.Errorf("startTimeUnixNano=%v", sp["startTimeUnixNano"])
	}
	if sp["endTimeUnixNano"] != "1700000005000000000" {
		t.Errorf("endTimeUnixNano=%v", sp["endTimeUnixNano"])
	}

	status := sp["status"].(map[string]any)
	if status["code"].(float64) != 2 {
		t.Errorf("status.code=%v, istenen 2 (ERROR)", status["code"])
	}
	if status["message"] != "kaboom" {
		t.Errorf("status.message=%v", status["message"])
	}

	// Öznitelikler sıralı olmalı (a, b).
	attrs := sp["attributes"].([]any)
	if len(attrs) != 2 {
		t.Fatalf("öznitelik sayısı=%d, istenen 2", len(attrs))
	}
	if attrs[0].(map[string]any)["key"] != "a" || attrs[1].(map[string]any)["key"] != "b" {
		t.Errorf("öznitelikler sıralı değil: %v", attrs)
	}
	firstVal := attrs[0].(map[string]any)["value"].(map[string]any)
	if firstVal["stringValue"] != "1" {
		t.Errorf("ilk öznitelik değeri=%v", firstVal)
	}
}

func TestExportOTLPJSONEmpty(t *testing.T) {
	raw, err := ExportOTLPJSON(nil)
	if err != nil {
		t.Fatalf("ExportOTLPJSON(nil) hata: %v", err)
	}
	var doc otlpExport
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("boş belge geçerli JSON değil: %v", err)
	}
	if len(doc.ResourceSpans) != 1 {
		t.Fatalf("resourceSpans sayısı=%d, istenen 1", len(doc.ResourceSpans))
	}
	spans := doc.ResourceSpans[0].ScopeSpans[0].Spans
	if len(spans) != 0 {
		t.Errorf("boş girişte span olmamalı, got %d", len(spans))
	}
}

func TestExportRootSpanNoParent(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	tr := &Tracer{Now: func() time.Time { return base }}
	_, span := tr.StartSpan(context.Background(), "root")
	span.End(base)

	raw, err := ExportOTLPJSON([]*Span{span})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	sp := doc["resourceSpans"].([]any)[0].(map[string]any)["scopeSpans"].([]any)[0].(map[string]any)["spans"].([]any)[0].(map[string]any)
	if _, present := sp["parentSpanId"]; present {
		t.Error("kök span parentSpanId alanını atlamalı (omitempty)")
	}
}
