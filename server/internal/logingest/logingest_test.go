package logingest

import (
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)

func TestSourceUUIDStableAndFormat(t *testing.T) {
	a := SourceUUID("firewall-1")
	b := SourceUUID("firewall-1")
	if a != b {
		t.Fatal("aynı kaynak aynı UUID vermeli")
	}
	if SourceUUID("firewall-2") == a {
		t.Fatal("farklı kaynak farklı UUID vermeli")
	}
	// UUID biçimi: 8-4-4-4-12, sürüm 5.
	if len(a) != 36 || a[14] != '5' {
		t.Fatalf("UUIDv5 biçimi bekleniyordu, %q", a)
	}
}

func TestNormalizeJSONArray(t *testing.T) {
	data := []byte(`[
	  {"source":"fw1","category":"NETWORK_CONN","severity":"high","message":"engellendi","details":{"src":"1.2.3.4"}},
	  {"source":"idp","message":"başarısız giriş"}
	]`)
	recs, err := NormalizeJSON(data, now)
	if err != nil {
		t.Fatalf("NormalizeJSON: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("2 kayıt beklenirdi, %d", len(recs))
	}
	if recs[0].Event.Category != "NETWORK_CONN" || recs[0].Event.Severity != "HIGH" {
		t.Fatalf("normalize yanlış: %+v", recs[0].Event)
	}
	if recs[0].Event.Details == "" {
		t.Fatal("details korunmalı")
	}
	// İkinci kayıt: geçersiz/eksik kategori+önem → SYSTEM/INFO.
	if recs[1].Event.Category != "SYSTEM" || recs[1].Event.Severity != "INFO" {
		t.Fatalf("varsayılan normalize yanlış: %+v", recs[1].Event)
	}
	if recs[0].DeviceID != SourceUUID("fw1") {
		t.Fatal("device_id kaynak UUID'siyle eşleşmeli")
	}
}

func TestNormalizeJSONSingleObject(t *testing.T) {
	recs, err := NormalizeJSON([]byte(`{"source":"s","message":"m"}`), now)
	if err != nil || len(recs) != 1 {
		t.Fatalf("tek nesne 1 kayıt vermeli, %v %d", err, len(recs))
	}
}

func TestNormalizeJSONRejectsMissing(t *testing.T) {
	for _, bad := range []string{
		`[{"category":"SYSTEM","message":"m"}]`, // source yok
		`[{"source":"s"}]`,                      // message yok
		`not json`,
	} {
		if _, err := NormalizeJSON([]byte(bad), now); err == nil {
			t.Fatalf("hata beklenirdi: %s", bad)
		}
	}
}

func TestNormalizeCEF(t *testing.T) {
	line := `CEF:0|Palo Alto|PAN-OS|10.0|threat|Malware Blocked|9|src=10.0.0.5 dst=8.8.8.8`
	rec, err := NormalizeCEF(line, now)
	if err != nil {
		t.Fatalf("NormalizeCEF: %v", err)
	}
	if rec.Event.Severity != "CRITICAL" { // 9 → CRITICAL
		t.Fatalf("CEF önem eşlemesi yanlış: %q", rec.Event.Severity)
	}
	if rec.DeviceID != SourceUUID("Palo Alto/PAN-OS") {
		t.Fatal("CEF kaynak UUID yanlış")
	}
	if rec.Event.Details == "" {
		t.Fatal("CEF uzantısı Details'e sarılmalı")
	}
}

func TestNormalizeCEFRejectsBad(t *testing.T) {
	if _, err := NormalizeCEF("düz metin log satırı", now); err == nil {
		t.Fatal("CEF öneki olmayan satır reddedilmeli")
	}
	if _, err := NormalizeCEF("CEF:0|only|three|fields", now); err == nil {
		t.Fatal("eksik CEF alanları reddedilmeli")
	}
}

func TestCEFSeverityScale(t *testing.T) {
	cases := map[string]string{"10": "CRITICAL", "8": "HIGH", "5": "MEDIUM", "2": "LOW", "0": "INFO", "High": "HIGH"}
	for in, want := range cases {
		if got := cefSeverity(in); got != want {
			t.Errorf("cefSeverity(%q)=%q beklenen %q", in, got, want)
		}
	}
}

func TestNormalizeLEEF(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	// LEEF 1.0, tab-delimited attrs.
	line := "LEEF:1.0|Palo Alto|PAN-OS|10.2|threat|sev=8\tsrc=1.2.3.4\tmsg=malware blocked\tcat=THREAT"
	rec, err := NormalizeLEEF(line, now)
	if err != nil {
		t.Fatalf("NormalizeLEEF: %v", err)
	}
	if rec.Event.Severity != "HIGH" { // sev=8 → HIGH
		t.Fatalf("severity HIGH beklenirdi, %q", rec.Event.Severity)
	}
	if !strings.Contains(rec.Event.Message, "malware blocked") {
		t.Fatalf("mesaj msg alanını taşımalı, %q", rec.Event.Message)
	}
	if rec.DeviceID == "" {
		t.Fatal("kaynaktan device id türetilmeli")
	}
	if !strings.Contains(rec.Event.Details, "src") {
		t.Fatalf("kalan öznitelikler Details'e yazılmalı, %q", rec.Event.Details)
	}
}

func TestNormalizeLEEF20Delimiter(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	// LEEF 2.0 açık ayraç alanı (x09 = tab).
	line := "LEEF:2.0|V|P|1|evt|x09|sev=2\tmsg=info"
	rec, err := NormalizeLEEF(line, now)
	if err != nil {
		t.Fatalf("NormalizeLEEF 2.0: %v", err)
	}
	if rec.Event.Severity != "LOW" { // sev=2 → LOW
		t.Fatalf("severity LOW beklenirdi, %q", rec.Event.Severity)
	}
}

func TestNormalizeLEEFBad(t *testing.T) {
	if _, err := NormalizeLEEF("düz metin", time.Now()); err == nil {
		t.Fatal("LEEF öneki yoksa hata döndürmeli")
	}
	if _, err := NormalizeLEEF("LEEF:1.0|V|P", time.Now()); err == nil {
		t.Fatal("eksik alanlarda hata döndürmeli")
	}
}

func TestNormalizeSyslog5424(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	// <134> = facility 16 (local0), severity 6 (info); version 1.
	rec, err := NormalizeSyslog("<134>1 2026-09-10T12:00:00Z fw01 kernel 1234 ID47 - port scan detected", now)
	if err != nil {
		t.Fatalf("NormalizeSyslog: %v", err)
	}
	if rec.Event.Severity != "INFO" {
		t.Fatalf("sev INFO beklenirdi, %q", rec.Event.Severity)
	}
	if !strings.Contains(rec.Event.Message, "fw01") || !strings.Contains(rec.Event.Message, "port scan detected") {
		t.Fatalf("host + mesaj taşımalı, %q", rec.Event.Message)
	}
}

func TestNormalizeSyslog3164Severity(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	// <131> = severity 3 (err) → HIGH.
	rec, err := NormalizeSyslog("<131>Sep 10 12:00:00 gw sshd: auth failure", now)
	if err != nil {
		t.Fatalf("NormalizeSyslog: %v", err)
	}
	if rec.Event.Severity != "HIGH" {
		t.Fatalf("sev HIGH beklenirdi, %q", rec.Event.Severity)
	}
}

func TestNormalizeSyslogBad(t *testing.T) {
	for _, s := range []string{"no pri", "<abc>x", "<9999>x", ""} {
		if _, err := NormalizeSyslog(s, time.Now()); err == nil {
			t.Errorf("NormalizeSyslog(%q) hata döndürmeliydi", s)
		}
	}
}
