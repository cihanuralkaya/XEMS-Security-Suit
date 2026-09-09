package dnsmon

import "testing"

func FuzzScoreDomain(f *testing.F) {
	f.Add("google.com")
	f.Add("xjdk3l2m9fqp.com")
	f.Add("")
	f.Add("...")
	f.Fuzz(func(t *testing.T, s string) {
		_ = ScoreDomain(s) // panik olmamalı
	})
}
