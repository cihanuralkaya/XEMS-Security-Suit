package dlp

import "testing"

func FuzzScan(f *testing.F) {
	f.Add("kart 4111111111111111 iban TR330006100519786457841326 mail a@b.com tckn 10000000078")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_ = Scan(s) // panik olmamalı
	})
}
