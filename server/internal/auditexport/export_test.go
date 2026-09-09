package auditexport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func sampleEntries() []Entry {
	base := time.Unix(1_700_000_000, 0)
	return []Entry{
		{Admin: "a@corp", Action: "LOGIN", TargetType: "session", TargetID: "s1", CreatedAt: base},
		{Admin: "a@corp", Action: "QUARANTINE", TargetType: "device", TargetID: "d1", CreatedAt: base.Add(time.Minute)},
		{Admin: "b@corp", Action: "WIPE", TargetType: "device", TargetID: "d2", CreatedAt: base.Add(2 * time.Minute)},
	}
}

func TestBuildChainLinks(t *testing.T) {
	recs := BuildChain(sampleEntries())
	if len(recs) != 3 {
		t.Fatalf("3 kayıt beklenirdi, %d", len(recs))
	}
	// İlk kaydın prev_hash'i boş; sonrakiler öncekinin hash'ine bağlı.
	if recs[0].PrevHash != "" {
		t.Fatalf("ilk prev_hash boş olmalı, %q", recs[0].PrevHash)
	}
	if recs[1].PrevHash != recs[0].Hash || recs[2].PrevHash != recs[1].Hash {
		t.Fatal("zincir bağlantısı kopuk")
	}
}

func TestVerifyRoundTripUnsigned(t *testing.T) {
	data, err := MarshalJSONL(BuildChain(sampleEntries()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(data, nil); err != nil {
		t.Fatalf("imzasız dışa aktarım doğrulanmalı: %v", err)
	}
}

func TestVerifyRoundTripSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data, err := MarshalJSONL(BuildChain(sampleEntries()), priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(data, pub); err != nil {
		t.Fatalf("imzalı dışa aktarım doğrulanmalı: %v", err)
	}
	// Yanlış anahtarla imza reddedilmeli.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := Verify(data, otherPub); err != ErrSignature {
		t.Fatalf("yanlış anahtar ErrSignature vermeli, %v", err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	data, _ := MarshalJSONL(BuildChain(sampleEntries()), nil)
	// Bir kaydın action'ını değiştir → zincir kırılmalı.
	tampered := bytes.Replace(data, []byte("QUARANTINE"), []byte("NOOPXXXXXX"), 1)
	if err := Verify(tampered, nil); err != ErrChain {
		t.Fatalf("kurcalama ErrChain vermeli, %v", err)
	}
}

func TestVerifyDetectsHeadMismatch(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data, _ := MarshalJSONL(BuildChain(sampleEntries()), priv)
	// Manifest'i bozarak head_hash'i değiştir (imza da bozulur ama önce head kontrolü).
	tampered := bytes.Replace(data, []byte(`"count":3`), []byte(`"count":2`), 1)
	if err := Verify(tampered, pub); err != ErrHeadMatch {
		t.Fatalf("head/count uyuşmazlığı ErrHeadMatch vermeli, %v", err)
	}
}

func TestVerifyEmpty(t *testing.T) {
	if err := Verify([]byte("\n  \n"), nil); err != ErrEmpty {
		t.Fatalf("boş dışa aktarım ErrEmpty vermeli, %v", err)
	}
}
