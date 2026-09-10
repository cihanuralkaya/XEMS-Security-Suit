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

func TestCEFEventTimeRT(t *testing.T) {
	// CEF rt = epoch millis → OccurredAt.
	line := `CEF:0|V|P|1|sig|Name|5|src=1.2.3.4 rt=1767322845000`
	rec, err := NormalizeCEF(line, now)
	if err != nil {
		t.Fatalf("NormalizeCEF: %v", err)
	}
	want := time.UnixMilli(1767322845000).UTC()
	if !rec.Event.OccurredAt.Equal(want) {
		t.Fatalf("OccurredAt rt'den gelmeli, %v beklenen %v", rec.Event.OccurredAt, want)
	}
	// rt yoksa alım zamanına düşer.
	rec, _ = NormalizeCEF(`CEF:0|V|P|1|sig|Name|5|src=1.2.3.4`, now)
	if !rec.Event.OccurredAt.Equal(now) {
		t.Fatalf("rt yoksa now olmalı, %v", rec.Event.OccurredAt)
	}
}

func TestLEEFEventTimeDevTime(t *testing.T) {
	// LEEF devTime = RFC3339 → OccurredAt.
	line := "LEEF:1.0|V|P|1|evt|sev=5\tmsg=x\tdevTime=2026-01-02T03:04:05Z"
	rec, err := NormalizeLEEF(line, now)
	if err != nil {
		t.Fatalf("NormalizeLEEF: %v", err)
	}
	want := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if !rec.Event.OccurredAt.Equal(want) {
		t.Fatalf("OccurredAt devTime'dan gelmeli, %v beklenen %v", rec.Event.OccurredAt, want)
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
	// RFC5424 TIMESTAMP → OccurredAt (alım zamanı değil).
	wantT := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	if !rec.Event.OccurredAt.Equal(wantT) {
		t.Fatalf("OccurredAt syslog TIMESTAMP'tan gelmeli, %v beklenen %v", rec.Event.OccurredAt, wantT)
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

func TestWinEventClass(t *testing.T) {
	cases := []struct {
		id       int
		ch       string
		cat, sev string
		known    bool
	}{
		{4625, "Security", "SECURITY", "MEDIUM", true},                        // failed logon
		{1102, "Security", "SECURITY", "CRITICAL", true},                      // audit log cleared
		{4720, "Security", "SECURITY", "HIGH", true},                          // account created
		{7045, "System", "SECURITY", "HIGH", true},                            // service installed
		{4688, "Security", "PROCESS", "INFO", true},                           // process creation
		{1, "Microsoft-Windows-Sysmon/Operational", "PROCESS", "INFO", true},  // Sysmon proc create
		{8, "Microsoft-Windows-Sysmon/Operational", "SECURITY", "HIGH", true}, // CreateRemoteThread
		{4104, "Microsoft-Windows-PowerShell/Operational", "PROCESS", "MEDIUM", true},
		{1, "Security", "SECURITY", "INFO", false}, // ID 1 Security kanalında → bilinmeyen (Sysmon değil)
		{99999, "Security", "SECURITY", "INFO", false},
		{99999, "System", "SYSTEM", "INFO", false},
	}
	for _, c := range cases {
		cat, sev, _, known := WinEventClass(c.id, c.ch)
		if cat != c.cat || sev != c.sev || known != c.known {
			t.Errorf("WinEventClass(%d,%q)=(%q,%q,%v) beklenen (%q,%q,%v)",
				c.id, c.ch, cat, sev, known, c.cat, c.sev, c.known)
		}
	}
}

func TestNormalizeWinEventWinlogbeat(t *testing.T) {
	// winlogbeat iç içe "winlog" şekli.
	data := []byte(`{"winlog":{"event_id":4625,"channel":"Security","computer_name":"WS-01","provider_name":"Microsoft-Windows-Security-Auditing"},"message":"An account failed to log on.\nSubject: ..."}`)
	recs, err := NormalizeWinEvent(data, now)
	if err != nil || len(recs) != 1 {
		t.Fatalf("winlogbeat normalize: %v %d", err, len(recs))
	}
	if recs[0].Event.Category != "SECURITY" || recs[0].Event.Severity != "MEDIUM" {
		t.Fatalf("4625 sınıflandırma yanlış: %+v", recs[0].Event)
	}
	if !strings.Contains(recs[0].Event.Message, "WS-01") || !strings.Contains(recs[0].Event.Message, "4625") {
		t.Fatalf("mesaj host+id taşımalı, %q", recs[0].Event.Message)
	}
	if recs[0].DeviceID != SourceUUID("WS-01") {
		t.Fatal("device id computer_name'den türetilmeli")
	}
	if !strings.Contains(recs[0].Event.Details, "Security") {
		t.Fatalf("details kanalı taşımalı, %q", recs[0].Event.Details)
	}
}

func TestNormalizeWinEventNxlogArray(t *testing.T) {
	// nxlog düz şekil, dizi; ikinci kayıt Sysmon.
	data := []byte(`[
	  {"EventID":7045,"Channel":"System","Hostname":"SRV-DC","Message":"A service was installed"},
	  {"EventID":8,"Channel":"Microsoft-Windows-Sysmon/Operational","Hostname":"SRV-DC","Message":"CreateRemoteThread detected"}
	]`)
	recs, err := NormalizeWinEvent(data, now)
	if err != nil || len(recs) != 2 {
		t.Fatalf("nxlog dizi normalize: %v %d", err, len(recs))
	}
	if recs[0].Event.Severity != "HIGH" || recs[1].Event.Severity != "HIGH" {
		t.Fatalf("7045/Sysmon8 HIGH olmalı: %q %q", recs[0].Event.Severity, recs[1].Event.Severity)
	}
	if recs[1].Event.Category != "SECURITY" {
		t.Fatalf("Sysmon 8 SECURITY olmalı, %q", recs[1].Event.Category)
	}
}

func TestNormalizeWinEventRenderedXML(t *testing.T) {
	// wevtutil/EVTX render-XML → JSON: iç içe Event.System, EventID {#text}.
	data := []byte(`{"Event":{"System":{"EventID":{"#text":"1102","Qualifiers":"0"},"Channel":"Security","Computer":"AUDIT-01"}}}`)
	recs, err := NormalizeWinEvent(data, now)
	if err != nil || len(recs) != 1 {
		t.Fatalf("render-XML normalize: %v %d", err, len(recs))
	}
	if recs[0].Event.Severity != "CRITICAL" {
		t.Fatalf("1102 CRITICAL olmalı, %q", recs[0].Event.Severity)
	}
	if recs[0].DeviceID != SourceUUID("AUDIT-01") {
		t.Fatal("device id Computer'dan türetilmeli")
	}
}

func TestNormalizeWinEventEnrichment(t *testing.T) {
	// winlogbeat event_data (iç içe map) → Details'e taşınan triyaj alanları.
	data := []byte(`{"winlog":{"event_id":4625,"channel":"Security","computer_name":"WS-01","event_data":{"TargetUserName":"admin","IpAddress":"10.0.0.9","LogonType":"3"}},"message":"failed logon"}`)
	recs, err := NormalizeWinEvent(data, now)
	if err != nil || len(recs) != 1 {
		t.Fatalf("enrichment normalize: %v %d", err, len(recs))
	}
	for _, want := range []string{`"target_user":"admin"`, `"src_ip":"10.0.0.9"`, `"logon_type":"3"`} {
		if !strings.Contains(recs[0].Event.Details, want) {
			t.Fatalf("details %s içermeli, %q", want, recs[0].Event.Details)
		}
	}
	// Render-XML EventData Data[] dizisi ({@Name,#text}) → aynı zenginleştirme.
	xml := []byte(`{"Event":{"System":{"EventID":"4625","Channel":"Security","Computer":"AUD"},"EventData":{"Data":[{"@Name":"TargetUserName","#text":"root"},{"@Name":"IpAddress","#text":"1.2.3.4"}]}}}`)
	recs, err = NormalizeWinEvent(xml, now)
	if err != nil || len(recs) != 1 {
		t.Fatalf("render-XML EventData normalize: %v %d", err, len(recs))
	}
	if !strings.Contains(recs[0].Event.Details, `"target_user":"root"`) ||
		!strings.Contains(recs[0].Event.Details, `"src_ip":"1.2.3.4"`) {
		t.Fatalf("Data[] zenginleştirme eksik, %q", recs[0].Event.Details)
	}
}

func TestNormalizeWinEventEventTime(t *testing.T) {
	// winlogbeat @timestamp → OccurredAt gerçek olay zamanı olmalı (alım zamanı değil).
	data := []byte(`{"@timestamp":"2026-01-02T03:04:05Z","winlog":{"event_id":4625,"channel":"Security","computer_name":"h"},"message":"m"}`)
	recs, err := NormalizeWinEvent(data, now)
	if err != nil || len(recs) != 1 {
		t.Fatalf("event-time normalize: %v %d", err, len(recs))
	}
	want := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if !recs[0].Event.OccurredAt.Equal(want) {
		t.Fatalf("OccurredAt @timestamp'tan gelmeli, %v beklenen %v", recs[0].Event.OccurredAt, want)
	}
	// Render-XML TimeCreated @SystemTime.
	xml := []byte(`{"Event":{"System":{"EventID":"1102","Channel":"Security","Computer":"a","TimeCreated":{"@SystemTime":"2026-01-02T03:04:05Z"}}}}`)
	recs, _ = NormalizeWinEvent(xml, now)
	if len(recs) != 1 || !recs[0].Event.OccurredAt.Equal(want) {
		t.Fatalf("SystemTime çözülmeli, %+v", recs[0].Event.OccurredAt)
	}
	// Zaman damgası yoksa alım zamanına düşer.
	recs, _ = NormalizeWinEvent([]byte(`{"EventID":7045,"Channel":"System","Hostname":"h"}`), now)
	if len(recs) != 1 || !recs[0].Event.OccurredAt.Equal(now) {
		t.Fatalf("zaman damgası yoksa alım zamanı (now) olmalı, %v", recs[0].Event.OccurredAt)
	}
}

func TestNormalizeWinEventBad(t *testing.T) {
	if _, err := NormalizeWinEvent([]byte(`{"message":"no id"}`), now); err == nil {
		t.Fatal("event_id yoksa hata döndürmeli")
	}
	if _, err := NormalizeWinEvent([]byte(`not json`), now); err == nil {
		t.Fatal("bozuk JSON hata döndürmeli")
	}
}
