// propagation.go, W3C Trace Context taşıması (traceparent başlığı) ve OTLP-uyumlu
// JSON dışa aktarımı sağlar. Böylece izler Agent→C2 sınırını HTTP başlıkları
// üzerinden aşabilir ve ileride bir OTLP toplayıcısına aktarılabilir.

package trace

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// traceparentVersion, desteklenen W3C Trace Context sürümüdür ("00").
const traceparentVersion = "00"

// flagSampled, "örneklendi" (sampled) bayrağının hex gösterimidir.
const flagSampled = "01"

// InjectTraceparent, bir span'dan W3C "traceparent" başlık değeri üretir:
//
//	00-<trace 32 hex>-<span 16 hex>-01
//
// Span'ın TraceID veya SpanID'si geçersizse boş dize döner (enjekte edilecek
// geçerli bağlam yoktur).
func InjectTraceparent(span *Span) string {
	if span == nil || !span.TraceID.IsValid() || !span.SpanID.IsValid() {
		return ""
	}
	var b strings.Builder
	b.WriteString(traceparentVersion)
	b.WriteByte('-')
	b.WriteString(span.TraceID.String())
	b.WriteByte('-')
	b.WriteString(span.SpanID.String())
	b.WriteByte('-')
	b.WriteString(flagSampled)
	return b.String()
}

// ParseTraceparent, bir "traceparent" başlık değerini çözümleyip TraceID, SpanID
// ve başarı bayrağı döndürür. Biçim hatalı, sürüm desteklenmiyor ya da kimlikler
// geçersiz (sıfır/hatalı hex) ise ok=false döner.
func ParseTraceparent(header string) (TraceID, SpanID, bool) {
	parts := strings.Split(strings.TrimSpace(header), "-")
	if len(parts) != 4 {
		return TraceID{}, SpanID{}, false
	}
	version, traceHex, spanHex, flags := parts[0], parts[1], parts[2], parts[3]

	// Yalnızca "00" sürümü desteklenir; alanların uzunlukları sabittir.
	if version != traceparentVersion {
		return TraceID{}, SpanID{}, false
	}
	if len(traceHex) != 32 || len(spanHex) != 16 || len(flags) != 2 {
		return TraceID{}, SpanID{}, false
	}

	var tid TraceID
	if _, err := hex.Decode(tid[:], []byte(traceHex)); err != nil {
		return TraceID{}, SpanID{}, false
	}
	var sid SpanID
	if _, err := hex.Decode(sid[:], []byte(spanHex)); err != nil {
		return TraceID{}, SpanID{}, false
	}
	// Sıfır kimlikler geçersizdir (bkz. IsValid).
	if !tid.IsValid() || !sid.IsValid() {
		return TraceID{}, SpanID{}, false
	}
	// Bayrakların geçerli hex olduğunu doğrula (değeri önemsemeyiz).
	if _, err := hex.DecodeString(flags); err != nil {
		return TraceID{}, SpanID{}, false
	}
	return tid, sid, true
}

// --- OTLP JSON dışa aktarımı ---
//
// Aşağıdaki türler, OTLP/JSON "TracesData" şeklinin sadeleştirilmiş bir alt
// kümesini yansıtır: resourceSpans -> scopeSpans -> spans. Zaman damgaları,
// OTLP kuralına uygun olarak unix-nano değerlerinin DİZE gösterimidir.

type otlpExport struct {
	ResourceSpans []otlpResourceSpans `json:"resourceSpans"`
}

type otlpResourceSpans struct {
	ScopeSpans []otlpScopeSpans `json:"scopeSpans"`
}

type otlpScopeSpans struct {
	Scope otlpScope  `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpScope struct {
	Name string `json:"name"`
}

type otlpSpan struct {
	TraceID           string         `json:"traceId"`
	SpanID            string         `json:"spanId"`
	ParentSpanID      string         `json:"parentSpanId,omitempty"`
	Name              string         `json:"name"`
	StartTimeUnixNano string         `json:"startTimeUnixNano"`
	EndTimeUnixNano   string         `json:"endTimeUnixNano"`
	Attributes        []otlpKeyValue `json:"attributes,omitempty"`
	Status            otlpStatus     `json:"status"`
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

type otlpAnyValue struct {
	StringValue string `json:"stringValue"`
}

type otlpStatus struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

// scopeName, dışa aktarılan span'ların izleme kapsamı (instrumentation scope) adıdır.
const scopeName = "xems.corp/suite/server/internal/trace"

// otlpStatusCode, iç StatusCode'u OTLP durum kodu sayısına çevirir
// (0=UNSET, 1=OK, 2=ERROR — OTLP StatusCode numaralandırması).
func otlpStatusCode(c StatusCode) int {
	switch c {
	case StatusOK:
		return 1
	case StatusError:
		return 2
	default:
		return 0
	}
}

// ExportOTLPJSON, verilen span'ları OTLP-uyumlu bir JSON belgesine seri hale
// getirir (resourceSpans/scopeSpans/spans). Kimlikler hex, zamanlar unix-nano
// dizesidir. Ağ erişimi yoktur; yalnızca baytlar döndürülür — bu, ileriki OTLP
// toplayıcı hand-off'unun girdisidir. nil/boş span girişi geçerli boş belge üretir.
func ExportOTLPJSON(spans []*Span) ([]byte, error) {
	exported := make([]otlpSpan, 0, len(spans))
	for _, s := range spans {
		if s == nil {
			continue
		}
		s.mu.Lock()
		es := otlpSpan{
			TraceID:           s.TraceID.String(),
			SpanID:            s.SpanID.String(),
			Name:              s.Name,
			StartTimeUnixNano: unixNano(s.StartTime),
			EndTimeUnixNano:   unixNano(s.EndTime),
			Status: otlpStatus{
				Code:    otlpStatusCode(s.Status.Code),
				Message: s.Status.Message,
			},
		}
		if s.ParentSpanID.IsValid() {
			es.ParentSpanID = s.ParentSpanID.String()
		}
		if len(s.Attributes) > 0 {
			es.Attributes = make([]otlpKeyValue, 0, len(s.Attributes))
			// Belirlenimci (deterministik) çıktı için anahtarları sıralarız.
			keys := make([]string, 0, len(s.Attributes))
			for k := range s.Attributes {
				keys = append(keys, k)
			}
			sortStrings(keys)
			for _, k := range keys {
				es.Attributes = append(es.Attributes, otlpKeyValue{
					Key:   k,
					Value: otlpAnyValue{StringValue: s.Attributes[k]},
				})
			}
		}
		s.mu.Unlock()
		exported = append(exported, es)
	}

	doc := otlpExport{
		ResourceSpans: []otlpResourceSpans{
			{
				ScopeSpans: []otlpScopeSpans{
					{
						Scope: otlpScope{Name: scopeName},
						Spans: exported,
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// unixNano, zamanı OTLP'nin beklediği unix-nano DİZE gösterimine çevirir.
// Sıfır zaman "0" olarak verilir.
func unixNano(t time.Time) string {
	if t.IsZero() {
		return "0"
	}
	return strconv.FormatInt(t.UnixNano(), 10)
}

// sortStrings, küçük bir yerinde ekleme sıralamasıdır (sort paketini içe almadan
// belirlenimci öznitelik sırası üretmek için yeterlidir; öznitelik sayısı küçüktür).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
