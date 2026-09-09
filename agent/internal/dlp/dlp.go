// Package dlp, metin içeriğinde HASSAS VERİ (PII) sinyallerini saf-Go ile tespit
// eder — özellikle çıkarılabilir medyaya (USB) veri sızıntısı (DLP) göstergesi
// olarak. Aday desenler regex ile bulunur ve algoritmik olarak DOĞRULANIR (Luhn,
// TCKN sağlaması, IBAN mod-97) — bu, yanlış pozitifi ciddi biçimde azaltır.
//
// GİZLİLİK (KVKK veri-minimizasyonu): Bu paket hassas değerin KENDİSİNİ ASLA
// döndürmez veya loglamaz — yalnız TÜR + SAYI (redakte edilmiş sinyal) raporlar.
// Böylece tespit, hassas veriyi ikinci kez ifşa etmeden yapılır.
package dlp

import (
	"regexp"
	"strings"
)

// Signal, tek bir hassas-veri türünün redakte edilmiş sayımıdır.
type Signal struct {
	Kind  string `json:"kind"`  // "credit_card" | "tckn" | "iban" | "email"
	Count int    `json:"count"` // eşleşme sayısı (değer DEĞİL)
}

var (
	reCardCandidate  = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	reTCKNCandidate  = regexp.MustCompile(`\b\d{11}\b`)
	reIBANCandidate  = regexp.MustCompile(`\bTR(?:[ ]?\d){24}\b`)
	reEmailCandidate = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
)

// Scan, metindeki doğrulanmış hassas-veri sinyallerini (redakte, yalnız sayı) döner.
// Sinyal yoksa boş dilim döner.
func Scan(text string) []Signal {
	counts := map[string]int{}

	for _, m := range reCardCandidate.FindAllString(text, -1) {
		digits := stripNonDigits(m)
		if len(digits) >= 13 && len(digits) <= 19 && luhnValid(digits) {
			counts["credit_card"]++
		}
	}
	for _, m := range reTCKNCandidate.FindAllString(text, -1) {
		if tcknValid(m) {
			counts["tckn"]++
		}
	}
	for _, m := range reIBANCandidate.FindAllString(text, -1) {
		if ibanValidTR(m) {
			counts["iban"]++
		}
	}
	if n := len(reEmailCandidate.FindAllString(text, -1)); n > 0 {
		counts["email"] = n
	}

	// Kararlı sırada döndür (test edilebilirlik).
	var out []Signal
	for _, k := range []string{"credit_card", "tckn", "iban", "email"} {
		if c := counts[k]; c > 0 {
			out = append(out, Signal{Kind: k, Count: c})
		}
	}
	return out
}

func stripNonDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// luhnValid, Luhn (mod-10) sağlamasını doğrular (kredi kartı).
func luhnValid(digits string) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// tcknValid, T.C. Kimlik Numarası (11 hane) sağlamasını doğrular.
func tcknValid(s string) bool {
	if len(s) != 11 || s[0] == '0' {
		return false
	}
	var d [11]int
	for i := 0; i < 11; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		d[i] = int(s[i] - '0')
	}
	oddSum := d[0] + d[2] + d[4] + d[6] + d[8]
	evenSum := d[1] + d[3] + d[5] + d[7]
	c10 := ((oddSum * 7) - evenSum) % 10
	if c10 < 0 {
		c10 += 10
	}
	if c10 != d[9] {
		return false
	}
	total := 0
	for i := 0; i < 10; i++ {
		total += d[i]
	}
	return total%10 == d[10]
}

// ibanValidTR, Türkiye IBAN'ını (TR + 24 hane) mod-97 ile doğrular.
func ibanValidTR(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(s) != 26 || !strings.HasPrefix(s, "TR") {
		return false
	}
	// İlk 4 karakteri sona taşı, harfleri sayıya çevir (A=10..Z=35), mod 97 == 1.
	rearranged := s[4:] + s[:4]
	var num strings.Builder
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			num.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			num.WriteString(itoa2(int(r-'A') + 10))
		default:
			return false
		}
	}
	return mod97(num.String()) == 1
}

// itoa2, 10..35 aralığındaki bir sayıyı iki haneli string'e çevirir.
func itoa2(n int) string {
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

// mod97, çok uzun bir sayı dizesinin 97'ye göre kalanını parça parça hesaplar.
func mod97(s string) int {
	rem := 0
	for _, r := range s {
		rem = (rem*10 + int(r-'0')) % 97
	}
	return rem
}
