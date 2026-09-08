// Package update, OTA güncellemelerinin doğrulanmasını sağlar. Ajan bir
// güncelleme uygulamadan ÖNCE:
//  1. Manifesto imzasını gömülü public key ile doğrular (kimlik + bütünlük).
//  2. İndirilen paketin SHA-256'sını manifestodaki değerle karşılaştırır.
//
// Yalnız SHA-256 eşleşmesi YETMEZ (inceleme #4): imza, paketin gerçekten
// yetkili yönetici tarafından yayımlandığını kanıtlar; hash yalnız transport
// bütünlüğüdür.
package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"

	"xems.corp/suite/otawire"
)

var (
	// ErrBadSignature, manifesto imzası public key ile doğrulanamadığında döner.
	ErrBadSignature = errors.New("update: manifesto imzası geçersiz")
	// ErrHashMismatch, indirilen paketin SHA-256'sı manifestoyla uyuşmadığında döner.
	ErrHashMismatch = errors.New("update: paket SHA-256 uyuşmuyor")
)

// Verifier, gömülü public key ile güncellemeleri doğrular.
type Verifier struct {
	pub ed25519.PublicKey
}

// NewVerifier, Ed25519 public key ile doğrulayıcı oluşturur.
func NewVerifier(pub ed25519.PublicKey) (*Verifier, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("update: geçersiz Ed25519 public key boyutu")
	}
	return &Verifier{pub: pub}, nil
}

// VerifyManifest, manifesto imzasını doğrular.
func (v *Verifier) VerifyManifest(m otawire.Manifest, signature []byte) error {
	if !ed25519.Verify(v.pub, otawire.CanonicalBytes(m), signature) {
		return ErrBadSignature
	}
	return nil
}

// VerifyPayload, indirilen paketin SHA-256'sını manifestodaki hex ile
// sabit-zamanlı karşılaştırır.
func VerifyPayload(payload []byte, sha256Hex string) error {
	sum := sha256.Sum256(payload)
	want, err := hex.DecodeString(sha256Hex)
	if err != nil {
		return ErrHashMismatch
	}
	if subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return ErrHashMismatch
	}
	return nil
}
