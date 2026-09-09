package detect

import (
	"strings"
	"testing"
)

func FuzzLoadRules(f *testing.F) {
	f.Add(`[{"id":"a","name":"n","severity":"HIGH","contains":["x"]}]`)
	f.Add(`[{"id":"b","name":"m","severity":"LOW","message_regex":"("}]`)
	f.Add(`garbage`)
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = LoadRules(strings.NewReader(s)) // panik olmamalı
	})
}
