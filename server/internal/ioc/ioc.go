// Package ioc, tehdit istihbaratı (IoC) eşleştirmesidir: bilinen-kötü
// göstergeleri (IP, MAC, alan adı, hash, süreç adı) bir listeden yükler ve gelen
// olayların yapısal Details alanı + mesajı ile karşılaştırır. Eşleşme, bilinen bir
// tehdidin uç noktada görüldüğünü gösterir (yüksek-güven tespiti).
//
// Liste basit metin biçimindedir (operatör/feed dostu):
//
//	# yorum
//	10.13.37.5        known-c2
//	aa:bb:cc:dd:ee:ff  rogue-device
//	evil.example.com   phishing-altyapı
//	mimikatz.exe       kimlik-hırsızı
//
// İlk boşlukla-ayrılmış belirteç GÖSTERGEDİR; kalanı isteğe bağlı etikettir.
//
// ZENGİNLEŞTİRME (opsiyonel, geriye uyumlu): etiketten sonra `conf=` ve `src=`
// anahtar-değer belirteçleri ile GÜVEN düzeyi ve KAYNAK (feed) verilebilir:
//
//	1.2.3.4  known-c2  conf=high src=abuse.ch
//
// conf ∈ {low,medium,high,critical} (varsayılan medium); src serbest metin. Bu
// belirteçler etikete DAHİL EDİLMEZ; eşleşme olayına iliştirilir (önceliklendirme).
// Bağımlılıksız (yalnız stdlib).
package ioc

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Indicator, bir IoC göstergesinin etiketi + zenginleştirme meta verisidir.
type Indicator struct {
	Label      string `json:"label"`
	Confidence string `json:"confidence"`       // low | medium | high | critical
	Source     string `json:"source,omitempty"` // feed adı (ör. abuse.ch)
}

// Set, göstergeleri (küçük harfe normalize edilmiş) meta verisiyle tutar.
type Set struct {
	byValue map[string]Indicator
}

// Size, gösterge sayısını döner.
func (s *Set) Size() int {
	if s == nil {
		return 0
	}
	return len(s.byValue)
}

// Load, verilen okuyucudan gösterge listesini ayrıştırır.
func Load(r io.Reader) (*Set, error) {
	set := &Set{byValue: map[string]Indicator{}}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		val := strings.ToLower(fields[0])
		set.byValue[val] = parseIndicator(fields[1:])
	}
	return set, sc.Err()
}

// parseIndicator, etiket alanlarından conf=/src= zenginleştirme belirteçlerini
// ayıklar; kalan sözcükler etikettir (geriye uyumlu).
func parseIndicator(rest []string) Indicator {
	ind := Indicator{Confidence: "medium"}
	var labelWords []string
	for _, w := range rest {
		lw := strings.ToLower(w)
		switch {
		case strings.HasPrefix(lw, "conf="):
			c := strings.TrimPrefix(lw, "conf=")
			if c == "low" || c == "medium" || c == "high" || c == "critical" {
				ind.Confidence = c
			}
		case strings.HasPrefix(lw, "src="):
			ind.Source = strings.TrimPrefix(w, "src=") // özgün büyük/küçük harf korunur
		default:
			labelWords = append(labelWords, w)
		}
	}
	ind.Label = strings.Join(labelWords, " ")
	if ind.Label == "" {
		ind.Label = "etiketsiz"
	}
	return ind
}

// LoadFile, bir dosyadan gösterge listesi yükler.
func LoadFile(path string) (*Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Load(f)
}

// ErrBadSignature, IoC dosyası imzası doğrulanamadığında döner.
var ErrBadSignature = errors.New("ioc: gösterge listesi imzası GEÇERSİZ — yükleme reddedildi")

// LoadFileSigned, IoC göstergelerini YALNIZ Ed25519 imzası doğrulandıktan sonra
// yükler (kurcalamaya karşı; imzalı tespit kuralı / YARA kuralı ile aynı desen).
// Kurcalanmış bir IoC feed'i bilinen-kötü göstergeleri sessizce ÇIKARARAK tespiti
// körleştirebilir; imza bunu önler (fail-closed). İmza `<path>.sig` içinde base64.
func LoadFileSigned(path string, pub ed25519.PublicKey) (*Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sigB64, err := os.ReadFile(path + ".sig")
	if err != nil {
		return nil, fmt.Errorf("ioc: imza dosyası (%s.sig) okunamadı: %w", path, err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil {
		return nil, fmt.Errorf("ioc: imza base64 çözülemedi: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, data, sig) {
		return nil, ErrBadSignature
	}
	return Load(bytes.NewReader(data))
}

// Match, olayın Details string değerleri ile göstergeleri (tam, küçük/büyük harf
// duyarsız) ve mesajı (alt dize) karşılaştırır. İlk eşleşmenin etiketini döner
// (geriye uyumlu). Set boş/nil ise asla eşleşmez (özellik kapalı).
func (s *Set) Match(details map[string]any, message string) (label, indicator string, ok bool) {
	ind, val, hit := s.MatchIndicator(details, message)
	if !hit {
		return "", "", false
	}
	return ind.Label, val, true
}

// MatchIndicator, Match ile aynı eşleştirmeyi yapar ancak zenginleştirilmiş
// göstergeyi (etiket + güven + kaynak) döner — önceliklendirme/olay Details'i için.
func (s *Set) MatchIndicator(details map[string]any, message string) (ind Indicator, indicator string, ok bool) {
	if s == nil || len(s.byValue) == 0 {
		return Indicator{}, "", false
	}
	// 1) Details string değerleri — tam eşleşme (ip/mac/process gibi yapısal alanlar).
	for _, v := range details {
		if str, isStr := v.(string); isStr {
			if got, hit := s.byValue[strings.ToLower(strings.TrimSpace(str))]; hit {
				return got, str, true
			}
		}
	}
	// 2) Mesaj — gösterge alt dize olarak geçiyorsa (mesaja gömülü alan adı/hash).
	msg := strings.ToLower(message)
	for val, got := range s.byValue {
		if strings.Contains(msg, val) {
			return got, val, true
		}
	}
	return Indicator{}, "", false
}
