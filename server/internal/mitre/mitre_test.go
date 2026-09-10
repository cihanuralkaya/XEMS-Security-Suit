package mitre

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		cat, msg string
		wantID   string
		wantOK   bool
	}{
		{"NETWORK_DISCOVERY", "12 komşu bulundu", "T1046", true},
		{"POLICY_VIOLATION", "yasaklı süreç sonlandırıldı: game.exe", "T1204", true},
		{"SECURITY", "sahte/bozuk güncelleme reddedildi: 2.0.0", "T1195", true},
		{"SECURITY", "imzasız/sahte script reddedildi: cmd-9", "T1059", true},
		{"SECURITY", "anomali: olağandışı süreç davranışı: x.exe", "T1055", true},
		{"SECURITY", "watchdog kurcalama tespit edildi", "T1562", true},
		{"SECURITY", "tanımsız güvenlik olayı", "T1562", true}, // default
		// Genişletilmiş kapsam:
		{"POLICY_VIOLATION", "yeni kalıcılık girdisi: Run key", "T1547", true},
		{"NETWORK_CONN", "giden bağlantı: 1.2.3.4:443", "T1071", true},
		{"SECURITY", "DGA-şüpheli DNS sorgusu: xjq.com", "T1071", true},
		{"SECURITY", "IoC eşleşmesi [bad] 1.2.3.4", "T1071", true},
		{"SECURITY", "DLP: hassas veri tespit edildi", "T1048", true},
		{"SECURITY", "içerik-tarama eşleşmesi (R1): /tmp/x", "T1105", true},
		{"SECURITY", "dosya bütünlüğü değişikliği (deleted): /etc/passwd", "T1070", true},
		{"SECURITY", "olası yanal hareket: 5dk içinde 9 farklı iç hedefe bağlantı", "T1046", true},
		{"SECURITY", "olası DNS tünelleme: evil.com altında 5dk içinde 25 farklı alt alan", "T1071", true},
		{"SECURITY", "ajan öz-tasdik ihlali", "T1562", true},
		{"SYSTEM", "ajan başladı", "", false},
		{"AGENT_UPDATE", "güncellendi", "", false},
	}
	for _, c := range cases {
		got, ok := Classify(c.cat, c.msg)
		if ok != c.wantOK {
			t.Errorf("Classify(%q,%q) ok=%v beklenen=%v", c.cat, c.msg, ok, c.wantOK)
			continue
		}
		if ok && got.ID != c.wantID {
			t.Errorf("Classify(%q,%q) id=%s beklenen=%s", c.cat, c.msg, got.ID, c.wantID)
		}
	}
}

func TestCatalogUnique(t *testing.T) {
	seen := map[string]bool{}
	cat := Catalog()
	if len(cat) == 0 {
		t.Fatal("katalog boş")
	}
	for _, tq := range cat {
		if tq.ID == "" || tq.Name == "" || tq.Tactic == "" {
			t.Errorf("eksik alan: %+v", tq)
		}
		if seen[tq.ID] {
			t.Errorf("yinelenen teknik: %s", tq.ID)
		}
		seen[tq.ID] = true
	}
}
