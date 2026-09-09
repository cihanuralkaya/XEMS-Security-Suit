package contentscan

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// Tüm test desenleri BENIGN sentetik string'lerdir (zararlı-yazılım imzası yok);
// motor mantığını doğrular, AV sezgisel tetiklemez.

func TestScanAny(t *testing.T) {
	rs := RuleSet{Rules: []Rule{
		{Name: "R1", Severity: "HIGH", Condition: "any",
			Patterns: [][]byte{[]byte("ALPHA"), []byte("BRAVO")}},
	}}
	m := rs.Scan([]byte("... contains BRAVO here ..."))
	if len(m) != 1 || m[0].Rule != "R1" || m[0].Hits != 1 {
		t.Fatalf("any: beklenen 1 eşleşme 1 hit, gelen %+v", m)
	}
	if none := rs.Scan([]byte("nothing relevant")); len(none) != 0 {
		t.Fatalf("any: eşleşme olmamalı, gelen %+v", none)
	}
}

func TestScanAll(t *testing.T) {
	rs := RuleSet{Rules: []Rule{
		{Name: "R2", Condition: "all",
			Patterns: [][]byte{[]byte("FOO"), []byte("BAR")}},
	}}
	if m := rs.Scan([]byte("FOO only")); len(m) != 0 {
		t.Fatalf("all: kısmi eşleşme tetiklememeli, gelen %+v", m)
	}
	m := rs.Scan([]byte("FOO and BAR both"))
	if len(m) != 1 || m[0].Hits != 2 {
		t.Fatalf("all: iki desen eşleşmeli, gelen %+v", m)
	}
	if m[0].Severity != "MEDIUM" {
		t.Fatalf("all: boş severity MEDIUM'a düşmeli, gelen %q", m[0].Severity)
	}
}

func TestScanNOf(t *testing.T) {
	rs := RuleSet{Rules: []Rule{
		{Name: "R3", Condition: "2",
			Patterns: [][]byte{[]byte("A1"), []byte("B2"), []byte("C3")}},
	}}
	if m := rs.Scan([]byte("only A1")); len(m) != 0 {
		t.Fatalf("2-of: tek eşleşme yetmemeli, gelen %+v", m)
	}
	if m := rs.Scan([]byte("A1 and C3")); len(m) != 1 {
		t.Fatalf("2-of: iki eşleşme tetiklemeli, gelen %+v", m)
	}
}

func TestScanInvalidConditionDisabled(t *testing.T) {
	rs := RuleSet{Rules: []Rule{
		{Name: "R4", Condition: "banana", Patterns: [][]byte{[]byte("X")}},
	}}
	if m := rs.Scan([]byte("X X X")); len(m) != 0 {
		t.Fatalf("tanınmayan koşul fail-closed olmalı (eşleşme yok), gelen %+v", m)
	}
}

func TestScanEmptyPatternsSkipped(t *testing.T) {
	rs := RuleSet{Rules: []Rule{{Name: "R5", Condition: "any", Patterns: nil}}}
	if m := rs.Scan([]byte("anything")); len(m) != 0 {
		t.Fatalf("desensiz kural eşleşmemeli, gelen %+v", m)
	}
}

func TestParseRulesLiteralAndHex(t *testing.T) {
	data := []byte(`{"rules":[
	  {"name":"lit","severity":"high","condition":"any","strings":["HELLO"]},
	  {"name":"hx","condition":"all","hex":["de ad be ef","cafe"]}
	]}`)
	rs, err := ParseRules(data)
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	if len(rs.Rules) != 2 {
		t.Fatalf("2 kural beklenirdi, %d", len(rs.Rules))
	}
	if rs.Rules[0].Severity != "HIGH" {
		t.Fatalf("severity büyük harfe normalize edilmeli, %q", rs.Rules[0].Severity)
	}
	// hex kuralı gerçek baytlarla eşleşmeli; literal "HELLO" bu blob'da yok.
	blob := append([]byte("xx"), 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe)
	m := rs.Scan(blob)
	if len(m) != 1 || m[0].Rule != "hx" || m[0].Hits != 2 {
		t.Fatalf("beklenen: yalnız hx (2 hit) eşleşir; gelen %+v", m)
	}
}

func TestParseRulesRejectsBad(t *testing.T) {
	for _, bad := range []string{
		`{"rules":[]}`, // boş
		`{"rules":[{"name":"","strings":["x"]}]}`, // adsız
		`{"rules":[{"name":"n"}]}`,                // desensiz
		`{"rules":[{"name":"n","hex":["zz"]}]}`,   // geçersiz hex
		`not json`,                                // bozuk JSON
	} {
		if _, err := ParseRules([]byte(bad)); err == nil {
			t.Fatalf("ParseRules(%q) hata döndürmeliydi", bad)
		}
	}
}

func TestLoadSignedVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := []byte(`{"rules":[{"name":"n","condition":"any","strings":["ZZZ"]}]}`)
	dir := t.TempDir()
	rp := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, data)
	if err := os.WriteFile(rp+".sig", []byte(base64.StdEncoding.EncodeToString(sig)), 0o600); err != nil {
		t.Fatal(err)
	}

	rs, err := LoadSigned(rp, pub)
	if err != nil {
		t.Fatalf("geçerli imza yüklenmeli: %v", err)
	}
	if len(rs.Rules) != 1 {
		t.Fatalf("1 kural beklenirdi, %d", len(rs.Rules))
	}

	// Kurcalanmış kural (aynı imza) reddedilmeli.
	if err := os.WriteFile(rp, append(data, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigned(rp, pub); err == nil {
		t.Fatal("kurcalanmış kural kabul edilmemeli")
	}

	// Yanlış anahtar reddedilmeli.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := os.WriteFile(rp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigned(rp, otherPub); err == nil {
		t.Fatal("yanlış anahtar kabul edilmemeli")
	}
}
