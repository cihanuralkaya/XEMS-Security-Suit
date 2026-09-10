package main

import (
	"testing"
	"time"
)

func TestIsWinlog(t *testing.T) {
	cases := map[string]bool{
		`{"winlog":{"event_id":1}}`:           true,
		`{"EventID":7045,"Channel":"System"}`: true,
		`{"Event":{"System":{"EventID":1}}}`:  true,
		`[{"source":"s","message":"m"}]`:      false,
		`{"source":"x","message":"y"}`:        false,
	}
	for in, want := range cases {
		if got := isWinlog(in); got != want {
			t.Errorf("isWinlog(%q)=%v beklenen %v", in, got, want)
		}
	}
}

func TestNormalizeLines(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	body := "CEF:0|V|P|1|s|Name|9|src=1.2.3.4\n" +
		"LEEF:1.0|V|P|1|evt|sev=8\tmsg=x\n" +
		"<131>Sep 10 12:00:00 gw sshd: auth failure\n" +
		"\n" + // boş satır atlanır
		"düz metin satırı" // CEF varsayılır → reddedilir, atlanır
	recs := normalizeLines(body, now)
	if len(recs) != 3 {
		t.Fatalf("3 kayıt beklenirdi (boş + geçersiz atlanır), %d", len(recs))
	}
	if recs[0].Event.Severity != "CRITICAL" || recs[1].Event.Severity != "HIGH" || recs[2].Event.Severity != "HIGH" {
		t.Fatalf("önem eşlemesi yanlış: %q %q %q",
			recs[0].Event.Severity, recs[1].Event.Severity, recs[2].Event.Severity)
	}
}
