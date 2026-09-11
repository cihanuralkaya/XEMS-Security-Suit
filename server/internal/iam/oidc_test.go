package iam

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

// signJWT, test için bir RS256 JWT üretir: header ve claims'i kodlar, verilen
// özel anahtarla imzalar.
func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("header marshal: %v", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("claims marshal: %v", err)
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signingInput + "." + enc.EncodeToString(sig)
}

func newVerifier(t *testing.T, key *rsa.PrivateKey, kid string, now time.Time) *Verifier {
	t.Helper()
	return &Verifier{
		Issuer:   "https://idp.xems.corp",
		Audience: "xems-console",
		Keys:     map[string]*rsa.PublicKey{kid: &key.PublicKey},
		Now:      func() time.Time { return now },
		Leeway:   30 * time.Second,
	}
}

func baseClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":   "https://idp.xems.corp",
		"aud":   "xems-console",
		"sub":   "user-123",
		"email": "alice@xems.corp",
		"name":  "Alice Analyst",
		"exp":   now.Add(time.Hour).Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"iat":   now.Add(-time.Minute).Unix(),
		"nonce": "n-abc",
	}
}

func TestVerifyHappyPath(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	now := time.Unix(1_700_000_000, 0)
	v := newVerifier(t, key, "k1", now)
	tok := signJWT(t, key, "k1", baseClaims(now))

	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-123" || claims.Email != "alice@xems.corp" || claims.Name != "Alice Analyst" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "xems-console" {
		t.Fatalf("unexpected aud: %v", claims.Audience)
	}
	if claims.Raw["nonce"] != "n-abc" {
		t.Fatalf("raw claims missing nonce: %v", claims.Raw)
	}
}

func TestVerifyWithNonce(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	v := newVerifier(t, key, "k1", now)
	tok := signJWT(t, key, "k1", baseClaims(now))

	if _, err := v.VerifyWithNonce(tok, "n-abc"); err != nil {
		t.Fatalf("nonce match should verify: %v", err)
	}
	if _, err := v.VerifyWithNonce(tok, "wrong"); err != ErrNonceMismatch {
		t.Fatalf("want ErrNonceMismatch, got %v", err)
	}
}

func TestVerifyFailures(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)

	tests := []struct {
		name    string
		build   func() string
		mutate  func(v *Verifier)
		wantErr error
	}{
		{
			name: "tampered signature",
			build: func() string {
				tok := signJWT(t, key, "k1", baseClaims(now))
				return tok[:len(tok)-2] + "AA" // imzayı boz
			},
			wantErr: ErrBadSignature,
		},
		{
			name: "expired",
			build: func() string {
				c := baseClaims(now)
				c["exp"] = now.Add(-time.Hour).Unix()
				return signJWT(t, key, "k1", c)
			},
			wantErr: ErrTokenExpired,
		},
		{
			name: "not yet valid (nbf)",
			build: func() string {
				c := baseClaims(now)
				c["nbf"] = now.Add(time.Hour).Unix()
				return signJWT(t, key, "k1", c)
			},
			wantErr: ErrTokenNotYetValid,
		},
		{
			name: "issued in future (iat)",
			build: func() string {
				c := baseClaims(now)
				c["iat"] = now.Add(time.Hour).Unix()
				return signJWT(t, key, "k1", c)
			},
			wantErr: ErrTokenIssuedInFuture,
		},
		{
			name: "wrong audience",
			build: func() string {
				c := baseClaims(now)
				c["aud"] = "some-other-app"
				return signJWT(t, key, "k1", c)
			},
			wantErr: ErrAudienceMismatch,
		},
		{
			name: "wrong issuer",
			build: func() string {
				c := baseClaims(now)
				c["iss"] = "https://evil.example"
				return signJWT(t, key, "k1", c)
			},
			wantErr: ErrIssuerMismatch,
		},
		{
			name: "unknown kid",
			build: func() string {
				return signJWT(t, key, "unknown-kid", baseClaims(now))
			},
			wantErr: ErrUnknownKey,
		},
		{
			name: "malformed token",
			build: func() string {
				return "only.two"
			},
			wantErr: ErrMalformedToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newVerifier(t, key, "k1", now)
			if tt.mutate != nil {
				tt.mutate(v)
			}
			_, err := v.Verify(tt.build())
			if err != tt.wantErr {
				t.Fatalf("Verify err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyUnsupportedAlg(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	// "none" alg'li bir token elle kur.
	enc := base64.RawURLEncoding
	hb, _ := json.Marshal(map[string]any{"alg": "none", "typ": "JWT", "kid": "k1"})
	cb, _ := json.Marshal(baseClaims(now))
	tok := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb) + "."
	v := newVerifier(t, key, "k1", now)
	if _, err := v.Verify(tok); err != ErrUnsupportedAlg {
		t.Fatalf("want ErrUnsupportedAlg, got %v", err)
	}
}

func TestVerifyAudienceArray(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Unix(1_700_000_000, 0)
	v := newVerifier(t, key, "k1", now)
	c := baseClaims(now)
	c["aud"] = []any{"other-app", "xems-console"}
	tok := signJWT(t, key, "k1", c)
	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("array aud should verify: %v", err)
	}
	if len(claims.Audience) != 2 {
		t.Fatalf("want 2 audiences, got %v", claims.Audience)
	}
}

func TestParseJWKS(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &key.PublicKey
	enc := base64.RawURLEncoding
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	jwks := map[string]any{
		"keys": []any{
			map[string]any{
				"kty": "RSA",
				"kid": "k1",
				"n":   enc.EncodeToString(pub.N.Bytes()),
				"e":   enc.EncodeToString(eBytes),
			},
			map[string]any{
				"kty": "EC", // RSA dışı: atlanmalı
				"kid": "ec1",
			},
		},
	}
	data, _ := json.Marshal(jwks)
	keys, err := ParseJWKS(data)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want 1 RSA key, got %d", len(keys))
	}
	got := keys["k1"]
	if got == nil || got.N.Cmp(pub.N) != 0 || got.E != pub.E {
		t.Fatalf("parsed key mismatch: %+v vs %+v", got, pub)
	}

	// Parse edilen anahtarla gerçekten doğrulama yapılabilmeli (uçtan uca).
	now := time.Unix(1_700_000_000, 0)
	v := &Verifier{
		Issuer:   "https://idp.xems.corp",
		Audience: "xems-console",
		Keys:     keys,
		Now:      func() time.Time { return now },
		Leeway:   30 * time.Second,
	}
	tok := signJWT(t, key, "k1", baseClaims(now))
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("verify with parsed JWKS: %v", err)
	}
}

func TestParseJWKSInvalid(t *testing.T) {
	if _, err := ParseJWKS([]byte("{not json")); err == nil {
		t.Fatal("want error on invalid JSON")
	}
}
