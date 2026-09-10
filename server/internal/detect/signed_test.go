package detect

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRulesFileSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := []byte(`[{"id":"a","name":"n","severity":"HIGH","contains":["x"]}]`)
	dir := t.TempDir()
	rp := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, data)
	if err := os.WriteFile(rp+".sig", []byte(b64(sig)), 0o600); err != nil {
		t.Fatal(err)
	}

	rules, err := LoadRulesFileSigned(rp, pub)
	if err != nil {
		t.Fatalf("geçerli imza yüklenmeli: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("1 kural beklenirdi, %d", len(rules))
	}

	// Kurcalanmış kural (aynı imza) reddedilmeli.
	if err := os.WriteFile(rp, append(data, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRulesFileSigned(rp, pub); err != ErrBadSignature {
		t.Fatalf("kurcalanmış kural ErrBadSignature vermeli, %v", err)
	}
	// Yanlış anahtar reddedilmeli.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := os.WriteFile(rp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRulesFileSigned(rp, otherPub); err != ErrBadSignature {
		t.Fatalf("yanlış anahtar ErrBadSignature vermeli, %v", err)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
