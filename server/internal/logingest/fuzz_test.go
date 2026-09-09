package logingest

import (
	"testing"
	"time"
)

var fuzzNow = time.Unix(1_700_000_000, 0)

func FuzzNormalizeJSON(f *testing.F) {
	f.Add([]byte(`[{"source":"s","message":"m"}]`))
	f.Add([]byte(`{"source":"x","category":"SECURITY","severity":"high","message":"y","details":{"a":1}}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = NormalizeJSON(data, fuzzNow) // panik olmamalı
	})
}

func FuzzNormalizeCEF(f *testing.F) {
	f.Add(`CEF:0|Vendor|Product|1.0|sig|Name|9|src=1.2.3.4`)
	f.Add(`düz metin`)
	f.Add(`CEF:0|a|b|c`)
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = NormalizeCEF(s, fuzzNow)
	})
}
