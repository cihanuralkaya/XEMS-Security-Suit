package ota

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"xems.corp/suite/otawire"
)

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(priv)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("XEMS agent v1.4.0 ikilisi")
	m := otawire.Manifest{
		TargetVersion: "1.4.0",
		SHA256Hex:     SHA256Hex(payload),
		DownloadURL:   "https://c2/updates/1.4.0/agent.exe",
		Mandatory:     false,
	}
	sig := s.Sign(m)

	// Ajanın yapacağı doğrulama: aynı kanonik baytlar + public key.
	if !ed25519.Verify(pub, otawire.CanonicalBytes(m), sig) {
		t.Fatal("imzalanan manifesto public key ile doğrulanamadı")
	}
}

func TestNewSignerRejectsBadKey(t *testing.T) {
	if _, err := NewSigner(ed25519.PrivateKey([]byte("kısa"))); err == nil {
		t.Fatal("geçersiz anahtar boyutu kabul edildi")
	}
}
