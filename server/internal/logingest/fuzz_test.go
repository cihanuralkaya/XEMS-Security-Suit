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

func FuzzNormalizeLEEF(f *testing.F) {
	f.Add("LEEF:1.0|V|P|1|evt|sev=8\tmsg=x")
	f.Add("LEEF:2.0|V|P|1|evt|x09|sev=2\tmsg=y")
	f.Add("düz metin")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = NormalizeLEEF(s, fuzzNow)
	})
}

func FuzzNormalizeSyslog(f *testing.F) {
	f.Add("<134>1 2026-09-10T12:00:00Z fw01 kernel 1234 ID47 - port scan")
	f.Add("<131>Sep 10 12:00:00 gw sshd: auth failure")
	f.Add("<9999>x")
	f.Add("no pri")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = NormalizeSyslog(s, fuzzNow) // panik olmamalı (özellikle <PRI> sınır kontrolü)
	})
}

func FuzzNormalizeWinEvent(f *testing.F) {
	f.Add([]byte(`{"winlog":{"event_id":4625,"channel":"Security","computer_name":"h"},"message":"m"}`))
	f.Add([]byte(`[{"EventID":7045,"Channel":"System","Hostname":"h"}]`))
	f.Add([]byte(`{"Event":{"System":{"EventID":{"#text":"1102"},"Channel":"Security"}}}`))
	f.Add([]byte(`{"event_data":{"Data":[{"@Name":"IpAddress","#text":"1.2.3.4"}]}}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = NormalizeWinEvent(data, fuzzNow) // panik olmamalı (özyinelemeli winFlatten)
	})
}
