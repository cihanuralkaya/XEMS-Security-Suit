package contentscan

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ruleJSON, harici imzalı kural dosyasının JSON şemasıdır.
//
//	{
//	  "rules": [
//	    {"name":"Ornek","severity":"HIGH","condition":"any",
//	     "strings":["literal-metin"], "hex":["de ad be ef"]}
//	  ]
//	}
type ruleJSON struct {
	Name      string   `json:"name"`
	Severity  string   `json:"severity"`
	Condition string   `json:"condition"`
	Strings   []string `json:"strings"`
	Hex       []string `json:"hex"`
}

type ruleFile struct {
	Rules []ruleJSON `json:"rules"`
}

// ParseRules, kural JSON baytlarını derlenmiş bir RuleSet'e çevirir. Her kuralın
// literal string'leri ve hex desenleri ham baytlara açılır. Adı olmayan ya da hiç
// deseni olmayan kural reddedilir (fail-closed).
func ParseRules(data []byte) (RuleSet, error) {
	var rf ruleFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return RuleSet{}, fmt.Errorf("contentscan: kural JSON çözülemedi: %w", err)
	}
	var rs RuleSet
	for i, rj := range rf.Rules {
		if strings.TrimSpace(rj.Name) == "" {
			return RuleSet{}, fmt.Errorf("contentscan: kural #%d adsız", i)
		}
		var pats [][]byte
		for _, s := range rj.Strings {
			if s != "" {
				pats = append(pats, []byte(s))
			}
		}
		for _, h := range rj.Hex {
			b, err := decodeHexPattern(h)
			if err != nil {
				return RuleSet{}, fmt.Errorf("contentscan: kural %q hex deseni geçersiz: %w", rj.Name, err)
			}
			if len(b) > 0 {
				pats = append(pats, b)
			}
		}
		if len(pats) == 0 {
			return RuleSet{}, fmt.Errorf("contentscan: kural %q desen içermiyor", rj.Name)
		}
		rs.Rules = append(rs.Rules, Rule{
			Name:      rj.Name,
			Severity:  strings.ToUpper(strings.TrimSpace(rj.Severity)),
			Condition: strings.ToLower(strings.TrimSpace(rj.Condition)),
			Patterns:  pats,
		})
	}
	if len(rs.Rules) == 0 {
		return RuleSet{}, errors.New("contentscan: kural kümesi boş")
	}
	return rs, nil
}

// decodeHexPattern, "de ad be ef" veya "deadbeef" gibi bir hex desenini ham
// baytlara çevirir (boşluklar yok sayılır).
func decodeHexPattern(s string) ([]byte, error) {
	clean := strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), ":", "")
	if clean == "" {
		return nil, nil
	}
	return hex.DecodeString(clean)
}

// ErrBadSignature, kural dosyası imzası doğrulanamadığında döner.
var ErrBadSignature = errors.New("contentscan: kural imzası GEÇERSİZ — yükleme reddedildi")

// LoadSigned, kural dosyasını YALNIZ Ed25519 imzası doğrulandıktan sonra yükler.
// İmza, kural JSON baytları üzerinedir ve `<rulesPath>.sig` dosyasında base64
// beklenir. Kuralları yazabilen ama imzalayamayan bir saldırgan, tespiti
// sıfırlayamaz (fail-closed). Anomali modeli imzalamasıyla aynı desendir.
func LoadSigned(rulesPath string, pub ed25519.PublicKey) (RuleSet, error) {
	data, err := os.ReadFile(rulesPath)
	if err != nil {
		return RuleSet{}, fmt.Errorf("contentscan: kural dosyası okunamadı: %w", err)
	}
	sigB64, err := os.ReadFile(rulesPath + ".sig")
	if err != nil {
		return RuleSet{}, fmt.Errorf("contentscan: imza dosyası (%s.sig) okunamadı: %w", rulesPath, err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigB64)))
	if err != nil {
		return RuleSet{}, fmt.Errorf("contentscan: imza base64 çözülemedi: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, data, sig) {
		return RuleSet{}, ErrBadSignature
	}
	return ParseRules(data)
}
