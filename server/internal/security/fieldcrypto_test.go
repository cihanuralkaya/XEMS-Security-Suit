package security

import (
	"crypto/rand"
	"testing"
)

func randKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

// Anahtar rotasyonu (keyring): eski anahtarla şifrelenmiş veri, yeni birincil +
// eski çözme anahtarı olan halkayla HÂLÂ çözülür (VERİ KAYBI YOK). Yeni veri yeni
// anahtarla şifrelenir; eski anahtar tek başına yeni veriyi çözemez.
func TestFieldCipherKeyringRotation(t *testing.T) {
	oldKey, newKey := randKey(t), randKey(t)

	oldC, _ := NewFieldCipher(oldKey)
	oldBlob, _ := oldC.EncryptString("gizli-veri")

	ring, err := NewFieldCipherRing(newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	// Eski veri halkayla çözülmeli (eski anahtar çözme için hâlâ var).
	if s, err := ring.DecryptString(oldBlob); err != nil || s != "gizli-veri" {
		t.Fatalf("rotasyon sonrası eski veri çözülmeli: %v %q", err, s)
	}
	// Yeni şifreleme BİRİNCİL (yeni) anahtarla yapılır.
	newBlob, _ := ring.EncryptString("yeni-veri")
	if s, err := ring.DecryptString(newBlob); err != nil || s != "yeni-veri" {
		t.Fatalf("yeni veri çözülmeli: %v %q", err, s)
	}
	// Yalnız-yeni cipher yeni veriyi çözer; yalnız-eski cipher ÇÖZEMEZ (birincil değişti).
	newOnly, _ := NewFieldCipher(newKey)
	if s, err := newOnly.DecryptString(newBlob); err != nil || s != "yeni-veri" {
		t.Fatalf("yeni anahtar yeni veriyi çözmeli: %v %q", err, s)
	}
	if _, err := oldC.DecryptString(newBlob); err == nil {
		t.Fatal("eski anahtar yeni veriyi çözMEMELİ (rotasyon güvenliği)")
	}
}

// Boş eski anahtarlar atlanır (yapılandırma esnekliği).
func TestFieldCipherRingSkipsEmptyOlds(t *testing.T) {
	ring, err := NewFieldCipherRing(randKey(t), nil, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := ring.EncryptString("x")
	if s, _ := ring.DecryptString(blob); s != "x" {
		t.Fatal("boş eski anahtarlarla tur başarısız")
	}
}
