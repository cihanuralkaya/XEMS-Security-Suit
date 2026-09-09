package contentscan

import "testing"

func FuzzParseRules(f *testing.F) {
	f.Add([]byte(`{"rules":[{"name":"n","strings":["x"]}]}`))
	f.Add([]byte(`{"rules":[{"name":"h","hex":["dead"]}]}`))
	f.Add([]byte(`garbage`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if rs, err := ParseRules(data); err == nil {
			rs.Scan([]byte("some content to scan")) // panik olmamalı
		}
	})
}
