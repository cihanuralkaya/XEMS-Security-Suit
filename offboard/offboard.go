// Package offboard, ÇEVRİMDIŞI (offline) cihaz emekliye ayırma jetonlarının
// kanonik (imzalanacak) bayt biçimini ve doğrulamasını tanımlar.
//
// AMAÇ: Bir cihaz C2'ye artık ulaşamıyorsa (satış, iade, imha, ağdan koparılmış
// depo) tamper-koruması (watchdog karşılıklı yeniden başlatma + kalıcılık) ajanı
// canlı tutmaya devam eder. Yetkili yönetici, çevrimdışı bir "stand-down" jetonu
// İMZALAYARAK bu korumayı BİLİNÇLİ olarak devre dışı bırakabilir.
//
// GÜVENLİK: Jeton yalnız Ed25519 imzası gömülü public key ile doğrulanırsa
// geçerlidir (tek bayt değişse reddedilir) VE cihaz kimliği + son kullanma
// (expiry) kontrol edilir. Böylece jeton ele geçse bile:
//   - yalnız HEDEF cihaz için geçerlidir (DeviceID bağlı),
//   - süresi dolduğunda işe yaramaz (expiry),
//   - imzalanamadan üretilemez (yalnız özel anahtar sahibi).
//
// Kodlama scriptwire/otawire ile aynı desendir: domainTag + 4 baytlık big-endian
// uzunluk-önekli alanlar. Sunucu (imzalayan) ve ajan (doğrulayan) TAM OLARAK aynı
// baytları üretmek zorunda olduğundan bu paket internal-dışı paylaşılır.
package offboard

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

const domainTag = "xems-offboard-v1"

// Token, çevrimdışı emekliye-ayırma jetonunun imzalanan alanlarıdır.
type Token struct {
	DeviceID  string // hedef cihazın kimliği (jeton yalnız bu cihaz için geçerli)
	ExpiresAt int64  // Unix saniye; bu andan sonra jeton reddedilir
}

// CanonicalBytes, jetonun imzalanacak deterministik baytlarını üretir.
func CanonicalBytes(t Token) []byte {
	var out []byte
	out = field(out, []byte(domainTag))
	out = field(out, []byte(t.DeviceID))
	var e [8]byte
	binary.BigEndian.PutUint64(e[:], uint64(t.ExpiresAt))
	out = field(out, e[:])
	return out
}

func field(dst, f []byte) []byte {
	var lp [4]byte
	binary.BigEndian.PutUint32(lp[:], uint32(len(f)))
	dst = append(dst, lp[:]...)
	return append(dst, f...)
}

// Encode, jeton + imzayı taşınabilir tek satırlık metne çevirir:
//
//	deviceID.expiry.base64(signature)
//
// DeviceID base64url ile kodlanır (ayraç '.' çakışmasını önlemek için).
func Encode(t Token, sig []byte) string {
	id := base64.RawURLEncoding.EncodeToString([]byte(t.DeviceID))
	return id + "." + strconv.FormatInt(t.ExpiresAt, 10) + "." +
		base64.RawURLEncoding.EncodeToString(sig)
}

// ErrMalformed, jeton metni ayrıştırılamadığında döner.
var ErrMalformed = errors.New("offboard: jeton biçimi geçersiz")

// Decode, Encode'un ürettiği metni jeton + imzaya geri ayrıştırır.
func Decode(s string) (Token, []byte, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 3 {
		return Token{}, nil, ErrMalformed
	}
	idRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Token{}, nil, ErrMalformed
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return Token{}, nil, ErrMalformed
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Token{}, nil, ErrMalformed
	}
	return Token{DeviceID: string(idRaw), ExpiresAt: exp}, sig, nil
}

// Errors doğrulama başarısızlıkları için.
var (
	// ErrBadSignature, imza gömülü public key(ler)le doğrulanamadığında döner.
	ErrBadSignature = errors.New("offboard: imza geçersiz")
	// ErrWrongDevice, jeton başka bir cihaz için imzalandığında döner.
	ErrWrongDevice = errors.New("offboard: jeton bu cihaz için değil")
	// ErrExpired, jetonun son kullanma tarihi geçtiğinde döner.
	ErrExpired = errors.New("offboard: jeton süresi dolmuş")
)

// Verifier, GÜVENİLEN Ed25519 public key(ler)le jetonları doğrular. Birden çok
// anahtar imza-anahtarı ROTASYONU içindir (örtüşme penceresinde eski + yeni).
type Verifier struct {
	pubs []ed25519.PublicKey
}

// NewVerifier, birden çok GÜVENİLEN public key ile doğrulayıcı oluşturur.
// En az bir geçerli anahtar gerekir.
func NewVerifier(pubs ...ed25519.PublicKey) (*Verifier, error) {
	var valid []ed25519.PublicKey
	for _, p := range pubs {
		if len(p) == ed25519.PublicKeySize {
			valid = append(valid, p)
		}
	}
	if len(valid) == 0 {
		return nil, errors.New("offboard: geçersiz Ed25519 public key boyutu")
	}
	return &Verifier{pubs: valid}, nil
}

// Verify, jetonun imzasını GÜVENİLEN anahtarlardan HERHANGİ biriyle doğrular,
// ardından cihaz kimliği + son kullanma kontrolü yapar. now Unix saniye olmalı.
func (v *Verifier) Verify(t Token, sig []byte, deviceID string, now int64) error {
	msg := CanonicalBytes(t)
	ok := false
	for _, p := range v.pubs {
		if ed25519.Verify(p, msg, sig) {
			ok = true
			break
		}
	}
	if !ok {
		return ErrBadSignature
	}
	if t.DeviceID != deviceID {
		return ErrWrongDevice
	}
	if t.ExpiresAt != 0 && now > t.ExpiresAt {
		return ErrExpired
	}
	return nil
}
