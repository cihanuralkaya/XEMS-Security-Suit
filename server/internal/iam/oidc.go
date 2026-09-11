package iam

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// OIDC ID-token doğrulama hataları.
var (
	// ErrMalformedToken, JWT üç nokta-ayraçlı bölümden oluşmuyorsa döner.
	ErrMalformedToken = errors.New("iam: bozuk JWT biçimi")
	// ErrUnsupportedAlg, başlık RS256 dışında bir algoritma belirtiyorsa döner.
	ErrUnsupportedAlg = errors.New("iam: desteklenmeyen imza algoritması (yalnız RS256)")
	// ErrUnknownKey, başlıktaki kid JWKS içinde bulunamazsa döner.
	ErrUnknownKey = errors.New("iam: bilinmeyen anahtar kimliği (kid)")
	// ErrBadSignature, RS256 imza doğrulaması başarısız olursa döner.
	ErrBadSignature = errors.New("iam: imza doğrulanamadı")
	// ErrIssuerMismatch, iss beklenen yayıncıyla eşleşmezse döner.
	ErrIssuerMismatch = errors.New("iam: yayıncı (iss) eşleşmiyor")
	// ErrAudienceMismatch, aud beklenen hedef kitleyi içermezse döner.
	ErrAudienceMismatch = errors.New("iam: hedef kitle (aud) eşleşmiyor")
	// ErrTokenExpired, token exp ile belirtilen süreyi geçmişse döner.
	ErrTokenExpired = errors.New("iam: token süresi dolmuş (exp)")
	// ErrTokenNotYetValid, token nbf'den önce kullanılıyorsa döner.
	ErrTokenNotYetValid = errors.New("iam: token henüz geçerli değil (nbf)")
	// ErrTokenIssuedInFuture, iat gelecekteyse (leeway dışı) döner.
	ErrTokenIssuedInFuture = errors.New("iam: token gelecekte düzenlenmiş (iat)")
	// ErrNonceMismatch, beklenen nonce token'daki ile eşleşmezse döner.
	ErrNonceMismatch = errors.New("iam: nonce eşleşmiyor")
)

// Claims, doğrulanmış bir OIDC ID-token'ının ayrıştırılmış iddialarıdır.
// Standart alanlar rahat erişim için ayrıca sunulur; Raw tüm payload'ı tutar.
type Claims struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	Name    string `json:"name"`
	Issuer  string `json:"iss"`
	// Audience, aud iddiasıdır; token tek dize veya dize dizisi taşıyabilir.
	Audience []string       `json:"aud"`
	Expiry   int64          `json:"exp"`
	Raw      map[string]any `json:"-"`
}

// Verifier, bir OIDC ID-token'ını doğrulamak için gereken yapılandırmadır.
// Keys minimal bir JWKS'tir (kid -> RSA açık anahtarı). Now enjekte edilebilir
// saat kaynağıdır (nil ise time.Now); Leeway saat sapmasını toleranslar.
type Verifier struct {
	Issuer   string
	Audience string
	Keys     map[string]*rsa.PublicKey
	Now      func() time.Time
	Leeway   time.Duration
}

// now, enjekte edilmiş saati veya time.Now'u döndürür.
func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify, bir RS256 OIDC ID-token'ını tam olarak doğrular: biçim, kid seçimi,
// imza (PKCS1v15 + SHA-256), iss/aud eşleşmesi ve exp/nbf/iat zaman
// pencereleri (leeway ile). Doğrulama başarılıysa ayrıştırılmış Claims döner.
// Bu çağrı nonce kontrolü yapmaz; nonce gerekiyorsa VerifyWithNonce kullanın.
func (v *Verifier) Verify(idToken string) (Claims, error) {
	return v.verify(idToken, "", false)
}

// VerifyWithNonce, Verify ile aynı doğrulamayı yapar ve ek olarak token'daki
// nonce iddiasının expectedNonce ile eşleştiğini doğrular (replay koruması).
func (v *Verifier) VerifyWithNonce(idToken, expectedNonce string) (Claims, error) {
	return v.verify(idToken, expectedNonce, true)
}

// verify, doğrulama mantığının çekirdeğidir.
func (v *Verifier) verify(idToken, expectedNonce string, checkNonce bool) (Claims, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return Claims{}, ErrMalformedToken
	}
	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("iam: başlık çözülemedi: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return Claims{}, fmt.Errorf("iam: başlık JSON'u ayrıştırılamadı: %w", err)
	}
	if header.Alg != "RS256" {
		return Claims{}, ErrUnsupportedAlg
	}
	key, ok := v.Keys[header.Kid]
	if !ok || key == nil {
		return Claims{}, ErrUnknownKey
	}

	// İmza, "header.payload" (ham base64url kodlu dizeler) üzerinden hesaplanır.
	signingInput := parts[0] + "." + parts[1]
	sig, err := decodeSegment(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("iam: imza çözülemedi: %w", err)
	}
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return Claims{}, ErrBadSignature
	}

	payloadBytes, err := decodeSegment(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("iam: payload çözülemedi: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payloadBytes, &raw); err != nil {
		return Claims{}, fmt.Errorf("iam: payload JSON'u ayrıştırılamadı: %w", err)
	}

	claims := Claims{
		Subject:  stringClaim(raw, "sub"),
		Email:    stringClaim(raw, "email"),
		Name:     stringClaim(raw, "name"),
		Issuer:   stringClaim(raw, "iss"),
		Audience: audienceClaim(raw),
		Expiry:   intClaim(raw, "exp"),
		Raw:      raw,
	}

	// iss eşleşmesi.
	if v.Issuer != "" && claims.Issuer != v.Issuer {
		return Claims{}, ErrIssuerMismatch
	}
	// aud, beklenen hedef kitleyi içermeli.
	if v.Audience != "" {
		found := false
		for _, a := range claims.Audience {
			if a == v.Audience {
				found = true
				break
			}
		}
		if !found {
			return Claims{}, ErrAudienceMismatch
		}
	}

	now := v.now()
	// exp: now, exp + leeway'i geçmemeli.
	if exp := claims.Expiry; exp != 0 {
		if now.After(time.Unix(exp, 0).Add(v.Leeway)) {
			return Claims{}, ErrTokenExpired
		}
	}
	// nbf: now, nbf - leeway'den önce olmamalı.
	if nbf := intClaim(raw, "nbf"); nbf != 0 {
		if now.Before(time.Unix(nbf, 0).Add(-v.Leeway)) {
			return Claims{}, ErrTokenNotYetValid
		}
	}
	// iat: gelecekte (leeway dışı) düzenlenmiş olmamalı.
	if iat := intClaim(raw, "iat"); iat != 0 {
		if time.Unix(iat, 0).Add(-v.Leeway).After(now) {
			return Claims{}, ErrTokenIssuedInFuture
		}
	}

	if checkNonce {
		if stringClaim(raw, "nonce") != expectedNonce {
			return Claims{}, ErrNonceMismatch
		}
	}

	return claims, nil
}

// decodeSegment, bir JWT bölümünü base64url (padding'siz) olarak çözer.
func decodeSegment(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// stringClaim, raw payload'dan bir dize iddiası okur; yoksa "" döner.
func stringClaim(raw map[string]any, key string) string {
	if v, ok := raw[key].(string); ok {
		return v
	}
	return ""
}

// intClaim, JSON sayısal bir iddiayı int64'e çevirir (JSON sayıları float64
// olarak çözülür); yoksa 0 döner.
func intClaim(raw map[string]any, key string) int64 {
	switch v := raw[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case json.Number:
		n, _ := v.Int64()
		return n
	default:
		return 0
	}
}

// audienceClaim, aud iddiasını normalize eder: OIDC'ye göre aud tek bir dize
// ya da dize dizisi olabilir.
func audienceClaim(raw map[string]any) []string {
	switch v := raw["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// jwksDoc, bir JWKS JSON belgesinin RSA anahtarları için ayrıştırma yapısıdır.
type jwksDoc struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

// ParseJWKS, bir JWKS JSON belgesini ayrıştırır ve RSA açık anahtarlarını
// kid -> *rsa.PublicKey eşlemesi olarak döndürür. n ve e base64url (padding'siz)
// büyük-endian tamsayılardır. RSA dışı (kty != "RSA") anahtarlar atlanır.
func ParseJWKS(data []byte) (map[string]*rsa.PublicKey, error) {
	var doc jwksDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("iam: JWKS ayrıştırılamadı: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("iam: JWKS modülü (n) çözülemedi [kid=%s]: %w", k.Kid, err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("iam: JWKS üssü (e) çözülemedi [kid=%s]: %w", k.Kid, err)
		}
		if len(nBytes) == 0 || len(eBytes) == 0 {
			return nil, fmt.Errorf("iam: JWKS anahtarı eksik n/e [kid=%s]", k.Kid)
		}
		n := new(big.Int).SetBytes(nBytes)
		e := new(big.Int).SetBytes(eBytes)
		if !e.IsInt64() || e.Int64() > int64(^uint32(0)) {
			return nil, fmt.Errorf("iam: JWKS üssü (e) çok büyük [kid=%s]", k.Kid)
		}
		keys[k.Kid] = &rsa.PublicKey{N: n, E: int(e.Int64())}
	}
	return keys, nil
}
