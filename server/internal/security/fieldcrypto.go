package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// FieldCipher, hassas serbest-metin alanlarını (hostname, mac, os_info)
// uygulama katmanında AES-256-GCM ile şifreler. DB'de BYTEA olarak saklanır.
//
// Not: pgcrypto yerine uygulama katmanı tercih edildi — anahtar sunucu RAM'inde
// kalır, DB süreci hiçbir zaman düz metni görmez (inceleme notu). Yüksek hacimli
// event_logs bu yolla ŞİFRELENMEZ; onun gizliliği at-rest (disk/TDE) düzeyindedir.
// FieldCipher bir ANAHTAR-HALKASI (keyring) tutar: şifreleme her zaman BİRİNCİL
// anahtarla yapılır; çözme, sırayla tüm anahtarları dener ve GCM kimlik-doğrulama
// etiketi hangi anahtarın doğru olduğunu belirler. Bu, anahtar rotasyonunu VERİ
// KAYBI OLMADAN mümkün kılar: yeni anahtar birincil yapılır, eski anahtar(lar)
// çözme için halkada tutulur — eski şifreli veri okunmaya devam eder, yeni veri
// yeni anahtarla şifrelenir. Zorunlu yeniden-şifreleme gerekmez (biçim aynı:
// nonce || ct+tag; sürüm öneki yok — kimlik-doğrulama etiketi ayrımı yapar).
type FieldCipher struct {
	primary cipher.AEAD   // şifreleme + ilk çözme denemesi
	ring    []cipher.AEAD // çözme sırası: birincil + eski anahtarlar
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("security: alan şifreleme anahtarı 32 bayt olmalı, %d verildi", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewFieldCipher, 32 baytlık (AES-256) tek anahtarla cipher oluşturur (geriye uyumlu).
func NewFieldCipher(key []byte) (*FieldCipher, error) {
	return NewFieldCipherRing(key)
}

// NewFieldCipherRing, birincil (şifreleme) anahtar + isteğe bağlı ESKİ anahtarlarla
// (yalnız çözme, rotasyon örtüşmesi) bir keyring oluşturur. Boş eski anahtarlar atlanır.
func NewFieldCipherRing(primary []byte, olds ...[]byte) (*FieldCipher, error) {
	pa, err := newAEAD(primary)
	if err != nil {
		return nil, err
	}
	fc := &FieldCipher{primary: pa, ring: []cipher.AEAD{pa}}
	for _, k := range olds {
		if len(k) == 0 {
			continue
		}
		a, err := newAEAD(k)
		if err != nil {
			return nil, err
		}
		fc.ring = append(fc.ring, a)
	}
	return fc, nil
}

// Encrypt, düz metni BİRİNCİL anahtarla şifreler. Çıktı: nonce || ciphertext(+tag).
func (c *FieldCipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, c.primary.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return c.primary.Seal(nonce, nonce, plaintext, nil), nil
}

// EncryptString, string kolaylık sarmalayıcısıdır.
func (c *FieldCipher) EncryptString(s string) ([]byte, error) {
	return c.Encrypt([]byte(s))
}

// Decrypt, halkadaki anahtarları sırayla deneyerek blob'u çözer (rotasyon: eski
// veri eski anahtarla, yeni veri birincil anahtarla çözülür). GCM etiketi yalnız
// doğru anahtarda doğrulanır; hiçbiri açmazsa hata döner.
func (c *FieldCipher) Decrypt(blob []byte) ([]byte, error) {
	ns := c.primary.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("security: şifreli veri nonce boyutundan kısa")
	}
	nonce, ciphertext := blob[:ns], blob[ns:]
	var lastErr error
	for _, a := range c.ring {
		if pt, err := a.Open(nil, nonce, ciphertext, nil); err == nil {
			return pt, nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("security: çözme başarısız")
	}
	return nil, lastErr
}

// DecryptString, çözülen veriyi string olarak döner.
func (c *FieldCipher) DecryptString(blob []byte) (string, error) {
	b, err := c.Decrypt(blob)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
