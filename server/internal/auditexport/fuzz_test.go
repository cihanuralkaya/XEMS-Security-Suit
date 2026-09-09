package auditexport

import "testing"

func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{"seq":0,"admin":"a","action":"X","target_type":"t","target_id":"i","created_at_unixnano":1,"prev_hash":"","hash":"deadbeef"}`))
	f.Add([]byte("not json"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_ = Verify(data, nil) // panik olmamalı
	})
}
