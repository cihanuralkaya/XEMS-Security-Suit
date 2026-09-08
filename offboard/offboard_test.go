package offboard

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	_, priv := mustKey(t)
	tok := Token{DeviceID: "dev-42.strange/id", ExpiresAt: 1_700_000_000}
	sig := ed25519.Sign(priv, CanonicalBytes(tok))

	enc := Encode(tok, sig)
	got, gotSig, err := Decode(enc)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.DeviceID != tok.DeviceID || got.ExpiresAt != tok.ExpiresAt {
		t.Fatalf("token mismatch: %+v != %+v", got, tok)
	}
	if string(gotSig) != string(sig) {
		t.Fatal("signature mismatch after round-trip")
	}
}

func TestDecodeMalformed(t *testing.T) {
	for _, s := range []string{"", "a.b", "a.b.c.d", "notbase64!.100.sig", "aaa.notint.bbb"} {
		if _, _, err := Decode(s); err == nil {
			t.Fatalf("Decode(%q) = nil error, want error", s)
		}
	}
}

func TestVerifyValid(t *testing.T) {
	pub, priv := mustKey(t)
	v, err := NewVerifier(pub)
	if err != nil {
		t.Fatal(err)
	}
	tok := Token{DeviceID: "dev-1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	sig := ed25519.Sign(priv, CanonicalBytes(tok))
	if err := v.Verify(tok, sig, "dev-1", time.Now().Unix()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyWrongDevice(t *testing.T) {
	pub, priv := mustKey(t)
	v, _ := NewVerifier(pub)
	tok := Token{DeviceID: "dev-1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	sig := ed25519.Sign(priv, CanonicalBytes(tok))
	if err := v.Verify(tok, sig, "dev-2", time.Now().Unix()); err != ErrWrongDevice {
		t.Fatalf("Verify = %v, want ErrWrongDevice", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	pub, priv := mustKey(t)
	v, _ := NewVerifier(pub)
	tok := Token{DeviceID: "dev-1", ExpiresAt: 1000}
	sig := ed25519.Sign(priv, CanonicalBytes(tok))
	if err := v.Verify(tok, sig, "dev-1", 2000); err != ErrExpired {
		t.Fatalf("Verify = %v, want ErrExpired", err)
	}
	// ExpiresAt=0 → süresiz (asla dolmaz).
	tok0 := Token{DeviceID: "dev-1", ExpiresAt: 0}
	sig0 := ed25519.Sign(priv, CanonicalBytes(tok0))
	if err := v.Verify(tok0, sig0, "dev-1", 9_999_999_999); err != nil {
		t.Fatalf("Verify(expiry=0) = %v, want nil", err)
	}
}

func TestVerifyTamperedRejected(t *testing.T) {
	pub, priv := mustKey(t)
	v, _ := NewVerifier(pub)
	tok := Token{DeviceID: "dev-1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	sig := ed25519.Sign(priv, CanonicalBytes(tok))
	// Aynı imza, değiştirilmiş expiry → imza CanonicalBytes'ı kapsadığından reddedilir.
	tampered := Token{DeviceID: "dev-1", ExpiresAt: tok.ExpiresAt + 10_000}
	if err := v.Verify(tampered, sig, "dev-1", time.Now().Unix()); err != ErrBadSignature {
		t.Fatalf("Verify(tampered) = %v, want ErrBadSignature", err)
	}
}

func TestVerifyWrongKeyRejected(t *testing.T) {
	pub, _ := mustKey(t)
	_, otherPriv := mustKey(t)
	v, _ := NewVerifier(pub)
	tok := Token{DeviceID: "dev-1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	sig := ed25519.Sign(otherPriv, CanonicalBytes(tok))
	if err := v.Verify(tok, sig, "dev-1", time.Now().Unix()); err != ErrBadSignature {
		t.Fatalf("Verify(wrong key) = %v, want ErrBadSignature", err)
	}
}

func TestVerifierRotation(t *testing.T) {
	oldPub, oldPriv := mustKey(t)
	newPub, _ := mustKey(t)
	// Ajan hem eski hem yeni anahtarı güvenir (örtüşme penceresi).
	v, err := NewVerifier(newPub, oldPub)
	if err != nil {
		t.Fatal(err)
	}
	tok := Token{DeviceID: "dev-1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	// Eski anahtarla imzalanmış jeton hâlâ kabul edilmeli.
	sig := ed25519.Sign(oldPriv, CanonicalBytes(tok))
	if err := v.Verify(tok, sig, "dev-1", time.Now().Unix()); err != nil {
		t.Fatalf("Verify(old key during overlap) = %v, want nil", err)
	}
}

func TestNewVerifierRejectsEmpty(t *testing.T) {
	if _, err := NewVerifier(); err == nil {
		t.Fatal("NewVerifier() with no keys = nil error, want error")
	}
	if _, err := NewVerifier([]byte{1, 2, 3}); err == nil {
		t.Fatal("NewVerifier(short key) = nil error, want error")
	}
}
