// Package tenant, çok-kiracılı (multi-tenant) dağıtımlar için KİRACI KİMLİĞİ
// kavramını tanımlar. Tek-kiracılı dağıtımlar örtük "default" kiracıyla çalışmaya
// devam eder (geriye tam uyumlu). Bu paket, kiracı kimliğinin doğrulanması ve
// istek bağlamında (context) taşınması için temel katmandır; veri bölümleme
// (tenant_id kolonları + sorgu süzme) sonraki fazlarda buna dayanır.
package tenant

import (
	"context"
	"errors"
	"strings"
)

// ID, bir kiracının kimliğidir (DNS-etiketi benzeri: küçük harf/rakam/tire).
type ID string

// Default, kiracı belirtilmediğinde kullanılan örtük kiracıdır (tek-kiracılı mod).
const Default ID = "default"

// maxLen, kiracı kimliği azami uzunluğudur (DNS etiketi sınırı).
const maxLen = 63

// ErrInvalid, kiracı kimliği doğrulamayı geçmediğinde döner.
var ErrInvalid = errors.New("tenant: geçersiz kiracı kimliği (küçük harf/rakam/tire, 1-63)")

// Valid, bir kiracı kimliğinin biçimsel olarak geçerli olup olmadığını döner.
// Kural: 1..63 karakter; yalnız [a-z0-9-]; tire ile başlayamaz/bitemez.
func Valid(id string) bool {
	if id == "" || len(id) > maxLen {
		return false
	}
	if id[0] == '-' || id[len(id)-1] == '-' {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Normalize, bir kiracı kimliğini kırpar + küçük harfe çevirir ve doğrular. Boş
// girdi Default'a çözülür (tek-kiracılı mod). Geçersizse ErrInvalid döner.
func Normalize(id string) (ID, error) {
	s := strings.ToLower(strings.TrimSpace(id))
	if s == "" {
		return Default, nil
	}
	if !Valid(s) {
		return "", ErrInvalid
	}
	return ID(s), nil
}

// ctxKey, kiracıyı bağlamda taşımak için özel anahtar türüdür.
type ctxKey struct{}

// WithTenant, kiracı kimliğini bağlama iliştirir.
func WithTenant(ctx context.Context, id ID) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext, bağlamdaki kiracıyı döner; yoksa Default (tek-kiracılı mod).
func FromContext(ctx context.Context) ID {
	if v, ok := ctx.Value(ctxKey{}).(ID); ok && v != "" {
		return v
	}
	return Default
}
