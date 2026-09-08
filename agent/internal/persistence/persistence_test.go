package persistence

import "testing"

func TestParseRunKeys(t *testing.T) {
	out := "\r\nHKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\r\n" +
		"    OneDrive    REG_SZ    C:\\Users\\x\\OneDrive.exe /background\r\n" +
		"    Evil    REG_EXPAND_SZ    C:\\Temp\\evil.exe\r\n"
	es := parseRunKeys(out)
	if len(es) != 2 {
		t.Fatalf("2 run-key girdisi beklendi: %+v", es)
	}
	if es[0].Name != "OneDrive" || es[0].Kind != RunKey || es[0].Value != "C:\\Users\\x\\OneDrive.exe /background" {
		t.Fatalf("run-key ayrıştırma hatalı: %+v", es[0])
	}
	if es[1].Name != "Evil" || es[1].Value != "C:\\Temp\\evil.exe" {
		t.Fatalf("REG_EXPAND_SZ ayrıştırma hatalı: %+v", es[1])
	}
}

func TestParseSchtasksSkipsMicrosoft(t *testing.T) {
	out := "\"\\MyBackdoor\",\"Ready\",\"...\"\r\n\"\\Microsoft\\Windows\\Foo\",\"Ready\",\"...\"\r\n"
	es := parseSchtasks(out)
	if len(es) != 1 || es[0].Name != "\\MyBackdoor" || es[0].Kind != ScheduledTask {
		t.Fatalf("yalnız Microsoft-olmayan görev alınmalı: %+v", es)
	}
}

func TestParseCronSkipsComments(t *testing.T) {
	out := "# yorum\n\n*/5 * * * * root /usr/bin/beacon\n"
	es := parseCron(out)
	if len(es) != 1 || es[0].Kind != Cron {
		t.Fatalf("1 cron girdisi beklendi: %+v", es)
	}
}

// Diff: ilk çağrı taban çizgisi; sonra YALNIZ yeni eklenen girdi raporlanmalı.
func TestTrackerDiffNewOnly(t *testing.T) {
	tr := &Tracker{}
	base := []Entry{{Kind: RunKey, Name: "A", Value: "a.exe"}}
	if ch := tr.Diff(base); ch != nil {
		t.Fatalf("ilk çağrı taban çizgisi olmalı: %+v", ch)
	}
	// A korunur, B eklenir → yalnız B.
	next := []Entry{{Kind: RunKey, Name: "A", Value: "a.exe"}, {Kind: ScheduledTask, Name: "B"}}
	ch := tr.Diff(next)
	if len(ch) != 1 || ch[0].Name != "B" {
		t.Fatalf("yalnız yeni girdi (B) raporlanmalı: %+v", ch)
	}
	// Aynı küme tekrar → yeni yok.
	if ch2 := tr.Diff(next); len(ch2) != 0 {
		t.Fatalf("değişmeyen tarama yeni girdi üretmemeli: %+v", ch2)
	}
}
