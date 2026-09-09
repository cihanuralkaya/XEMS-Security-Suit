package offboard

import "testing"

func FuzzDecode(f *testing.F) {
	f.Add("ZGV2LTE.1700000000.c2ln")
	f.Add("a.b.c")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_, _, _ = Decode(s) // panik olmamalı
	})
}
