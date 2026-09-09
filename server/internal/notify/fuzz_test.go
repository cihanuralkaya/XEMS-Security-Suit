package notify

import "testing"

func FuzzParseWindows(f *testing.F) {
	f.Add([]byte(`[{"start":"2026-03-10T00:00:00Z","end":"2026-03-10T04:00:00Z"}]`))
	f.Add([]byte(`bad`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseWindows(data) // panik olmamalı
	})
}
