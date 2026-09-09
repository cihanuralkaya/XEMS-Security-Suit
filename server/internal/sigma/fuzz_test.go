package sigma

import "testing"

func FuzzConvertMulti(f *testing.F) {
	f.Add([]byte("title: X\ndetection:\n  sel:\n    A: b\n  condition: sel\n"))
	f.Add([]byte("not: valid: yaml: ["))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = ConvertMulti(data) // panik olmamalı
	})
}
