package detect

import (
	"strings"
	"testing"

	"xems.corp/suite/server/internal/model"
)

func TestEvaluateDefaultRules(t *testing.T) {
	e := NewEngine(nil) // yerleşik kurallar

	cases := []struct {
		cat, msg   string
		wantRule   string
		wantSev    string
		wantTechID string
	}{
		{"SECURITY", "watchdog kurcalama tespit edildi", "XEMS-0001", "CRITICAL", "T1562"},
		{"SECURITY", "imzasız/sahte script reddedildi: cmd-9", "XEMS-0002", "HIGH", "T1059"},
		{"SECURITY", "sahte/bozuk güncelleme reddedildi", "XEMS-0003", "HIGH", "T1195"},
		{"SECURITY", "anomali: olağandışı süreç davranışı", "XEMS-0004", "HIGH", "T1055"},
		{"POLICY_VIOLATION", "yasaklı süreç sonlandırıldı: game.exe", "XEMS-0005", "HIGH", "T1204"},
		{"NETWORK_DISCOVERY", "10 komşu bulundu", "XEMS-0006", "LOW", "T1046"},
	}
	for _, c := range cases {
		dets := e.Evaluate(model.Event{Category: c.cat, Message: c.msg})
		if len(dets) == 0 {
			t.Errorf("(%q,%q) tespit üretmeliydi", c.cat, c.msg)
			continue
		}
		d := dets[0]
		if d.RuleID != c.wantRule || d.Severity != c.wantSev || d.Technique.ID != c.wantTechID {
			t.Errorf("(%q,%q) → %s/%s/%s beklenen %s/%s/%s",
				c.cat, c.msg, d.RuleID, d.Severity, d.Technique.ID, c.wantRule, c.wantSev, c.wantTechID)
		}
	}
}

func TestEvaluateNoMatch(t *testing.T) {
	e := NewEngine(nil)
	if d := e.Evaluate(model.Event{Category: "SYSTEM", Message: "ajan başladı"}); len(d) != 0 {
		t.Fatalf("SYSTEM olayı tespit üretmemeliydi: %v", d)
	}
	// Doğru kategori ama örüntü uymuyor → eşleşmez.
	if d := e.Evaluate(model.Event{Category: "SECURITY", Message: "alakasız mesaj"}); len(d) != 0 {
		t.Fatalf("örüntü uymayan SECURITY olayı eşleşmemeliydi: %v", d)
	}
}

func TestContainsIsAND(t *testing.T) {
	e := NewEngine([]Rule{{ID: "R1", Name: "iki-parça", Contains: []string{"foo", "bar"}, Severity: "HIGH"}})
	if d := e.Evaluate(model.Event{Message: "sadece foo"}); len(d) != 0 {
		t.Fatal("tek parça eşleşmemeliydi (AND)")
	}
	if d := e.Evaluate(model.Event{Message: "foo ve bar birlikte"}); len(d) != 1 {
		t.Fatal("iki parça da geçince eşleşmeliydi")
	}
}

func TestLoadRulesAndEvaluate(t *testing.T) {
	js := `[
	  {"id":"ORG-1","name":"Kripto madenci","category":"POLICY_VIOLATION","contains":["xmrig"],
	   "severity":"CRITICAL","technique":{"id":"T1496","name":"Resource Hijacking","tactic":"Impact"}}
	]`
	custom, err := LoadRules(strings.NewReader(js))
	if err != nil {
		t.Fatal(err)
	}
	if len(custom) != 1 || custom[0].ID != "ORG-1" {
		t.Fatalf("özel kural ayrıştırılamadı: %+v", custom)
	}
	// Yerleşik + özel kurallarla motor: özel kural eşleşir.
	e := NewEngine(WithDefaults(custom))
	dets := e.Evaluate(model.Event{Category: "POLICY_VIOLATION", Message: "yasaklı süreç sonlandırıldı: xmrig.exe"})
	var hasOrg bool
	for _, d := range dets {
		if d.RuleID == "ORG-1" && d.Severity == "CRITICAL" && d.Technique.ID == "T1496" {
			hasOrg = true
		}
	}
	if !hasOrg {
		t.Fatalf("özel kural eşleşmeliydi: %+v", dets)
	}
	// Katalogda hem yerleşik hem özel görünür.
	if len(e.Rules()) != len(DefaultRules())+1 {
		t.Fatalf("katalog yerleşik+özel içermeliydi: %d", len(e.Rules()))
	}
}

func TestLoadRulesRejectsInvalid(t *testing.T) {
	if _, err := LoadRules(strings.NewReader(`[{"id":"x"}]`)); err == nil {
		t.Fatal("eksik alanlı kural reddedilmeliydi")
	}
	if _, err := LoadRules(strings.NewReader(`bozuk json`)); err == nil {
		t.Fatal("bozuk JSON reddedilmeliydi")
	}
}

func TestRulesCatalogCopy(t *testing.T) {
	e := NewEngine(nil)
	r := e.Rules()
	if len(r) == 0 {
		t.Fatal("katalog boş")
	}
	r[0].ID = "DEĞİŞTİRİLDİ" // dönen kopya iç durumu bozmamalı
	if e.Rules()[0].ID == "DEĞİŞTİRİLDİ" {
		t.Fatal("Rules() iç kurallara referans sızdırdı")
	}
}

// v2: MessageRegex koşulu — regex'e uyan mesaj eşleşir, uymayan eşleşmez.
func TestRuleMessageRegex(t *testing.T) {
	e := NewEngine([]Rule{{ID: "R1", Name: "regex", Category: "PROCESS",
		MessageRegex: `mimikatz|\bnc\.exe`, Severity: "HIGH"}})
	if d := e.Evaluate(model.Event{Category: "PROCESS", Message: "süreç başlatıldı: mimikatz.exe (pid=5)"}); len(d) != 1 {
		t.Fatalf("mimikatz eşleşmeliydi, %d", len(d))
	}
	if d := e.Evaluate(model.Event{Category: "PROCESS", Message: "süreç başlatıldı: NC.EXE (pid=5)"}); len(d) != 1 {
		t.Fatalf("nc.exe (büyük harf) eşleşmeliydi (küçük/büyük duyarsız), %d", len(d))
	}
	if d := e.Evaluate(model.Event{Category: "PROCESS", Message: "süreç başlatıldı: notepad.exe"}); len(d) != 0 {
		t.Fatalf("notepad eşleşmemeliydi, %d", len(d))
	}
}

// v2: Fields koşulu — olay Details'indeki alan(lar) belirtilen değeri içermeli.
func TestRuleFields(t *testing.T) {
	e := NewEngine([]Rule{{ID: "R2", Name: "fields", Category: "SYSTEM",
		Fields: map[string]string{"disk_encryption": "off"}, Severity: "MEDIUM"}})
	on := model.Event{Category: "SYSTEM", Message: "uyum", Details: `{"disk_encryption":"off","firewall":"on"}`}
	if d := e.Evaluate(on); len(d) != 1 {
		t.Fatalf("disk_encryption=off eşleşmeliydi, %d", len(d))
	}
	off := model.Event{Category: "SYSTEM", Message: "uyum", Details: `{"disk_encryption":"on"}`}
	if d := e.Evaluate(off); len(d) != 0 {
		t.Fatalf("disk_encryption=on eşleşmemeliydi, %d", len(d))
	}
	// Details yoksa / alan yoksa eşleşmez.
	if d := e.Evaluate(model.Event{Category: "SYSTEM", Message: "uyum"}); len(d) != 0 {
		t.Fatalf("Details olmadan eşleşmemeliydi, %d", len(d))
	}
}

// v2: MinSeverity koşulu — olay önem düzeyi eşiğin altındaysa eşleşmez.
func TestRuleMinSeverity(t *testing.T) {
	e := NewEngine([]Rule{{ID: "R3", Name: "sev", Category: "SECURITY",
		Contains: []string{"olay"}, MinSeverity: "HIGH", Severity: "HIGH"}})
	if d := e.Evaluate(model.Event{Category: "SECURITY", Severity: "CRITICAL", Message: "kritik olay"}); len(d) != 1 {
		t.Fatalf("CRITICAL >= HIGH eşleşmeliydi, %d", len(d))
	}
	if d := e.Evaluate(model.Event{Category: "SECURITY", Severity: "LOW", Message: "düşük olay"}); len(d) != 0 {
		t.Fatalf("LOW < HIGH eşleşmemeliydi, %d", len(d))
	}
}

// v2: geçersiz regex/min_severity LoadRules'ta reddedilir.
func TestLoadRulesRejectsInvalidV2(t *testing.T) {
	bad := `[{"id":"X","name":"n","severity":"HIGH","message_regex":"("}]`
	if _, err := LoadRules(strings.NewReader(bad)); err == nil {
		t.Fatal("geçersiz regex reddedilmeliydi")
	}
	badSev := `[{"id":"X","name":"n","severity":"HIGH","min_severity":"BOGUS"}]`
	if _, err := LoadRules(strings.NewReader(badSev)); err == nil {
		t.Fatal("geçersiz min_severity reddedilmeliydi")
	}
}

// XEMS-0007 varsayılan kuralı: şüpheli PROCESS regex'i.
func TestDefaultSuspiciousProcessRule(t *testing.T) {
	e := NewEngine(nil)
	d := e.Evaluate(model.Event{Category: "PROCESS", Message: "süreç başlatıldı: powershell.exe -EncodedCommand ZQBjAGgAbw=="})
	if len(d) == 0 || d[0].RuleID != "XEMS-0007" {
		t.Fatalf("XEMS-0007 powershell -EncodedCommand eşleşmeliydi: %+v", d)
	}
}
