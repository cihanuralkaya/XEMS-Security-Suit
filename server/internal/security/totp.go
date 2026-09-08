package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP (RFC 6238) — admin konsolu için ikinci faktör (2FA). Saf stdlib:
// HMAC-SHA1 tabanlı, 30 sn adım, 6 haneli. Kimlik doğrulayıcı uygulamalarla
// (Google Authenticator, Aegis, 1Password…) uyumludur.

const (
	totpDigits = 6
	totpStep   = 30 * time.Second
	// totpSkew, saat kayması için kabul edilen ±adım penceresi (her biri 30 sn).
	totpSkew = 1
)

// b32, TOTP paylaşılan sırları için dolgusuz (padding'siz) Base32. Kimlik
// doğrulayıcı uygulamalar dolgusuz büyük harf Base32 bekler.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateTOTPSecret, 160-bit (20 bayt) rastgele bir TOTP sırrı üretir ve
// dolgusuz Base32 olarak döner (RFC 4648; authenticator uygulama formatı).
func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b32.EncodeToString(buf), nil
}

// hotp, RFC 4226 HOTP değerini (verilen sayaç için) döner.
func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) |
		(uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) |
		uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, code%mod)
}

// TOTPAt, verilen sır ve zaman için TOTP kodunu döner. Sır geçersiz Base32 ise
// hata döner.
func TOTPAt(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix()) / uint64(totpStep.Seconds())
	return hotp(key, counter), nil
}

// VerifyTOTP, kullanıcının girdiği kodu now etrafında ±totpSkew pencerede
// doğrular. Karşılaştırma sabit-zamanlıdır. Sır geçersizse ya da kod boşsa
// false döner (fail-closed).
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return false
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return false
	}
	base := uint64(now.Unix()) / uint64(totpStep.Seconds())
	for d := -totpSkew; d <= totpSkew; d++ {
		c := int64(base) + int64(d)
		if c < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(c))), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// OTPAuthURI, authenticator uygulamalarının QR olarak okuduğu otpauth:// URI'sini
// üretir. issuer ve account etiketleme içindir (ör. "XEMS Konsol", admin e-postası).
func OTPAuthURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", int(totpStep.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// decodeSecret, hem dolgulu hem dolgusuz Base32'yi (büyük/küçük harf) çözer.
func decodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.TrimSpace(strings.ReplaceAll(secret, " ", "")))
	s = strings.TrimRight(s, "=")
	return b32.DecodeString(s)
}
