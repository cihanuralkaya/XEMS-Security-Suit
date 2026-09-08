// Package vuln, yüklü yazılım envanterini bilinen zafiyet (CVE/KB) veri kümesiyle
// eşleştirir. Veri kümesi operatör tarafından JSON dosyasından yüklenir
// (XEMS_VULN_FILE); IoC feed'iyle aynı desen. Bağımlılıksız (yalnız stdlib).
package vuln

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// Entry, bilinen bir zafiyet kaydıdır. Product, yüklü yazılım adında aranan
// (küçük/büyük harf duyarsız) alt-dizedir (ör. "7-zip", "log4j", "openssl 1.0").
type Entry struct {
	Product      string `json:"product"`
	CVE          string `json:"cve"`
	Severity     string `json:"severity"` // LOW/MEDIUM/HIGH/CRITICAL
	FixedVersion string `json:"fixed_version,omitempty"`
	Description  string `json:"description,omitempty"`
}

// Match, tek bir yazılım paketi için eşleşen zafiyeti (ilk eşleşme) döndürür.
func (e Entry) matches(pkg string) bool {
	if e.Product == "" {
		return false
	}
	return strings.Contains(strings.ToLower(pkg), strings.ToLower(e.Product))
}

// Finding, bir cihazda eşleşen zafiyeti (hangi pakete karşılık geldiğiyle) taşır.
type Finding struct {
	CVE         string `json:"cve"`
	Product     string `json:"product"` // veri kümesindeki ürün örüntüsü
	Package     string `json:"package"` // eşleşen yüklü paket adı
	Severity    string `json:"severity"`
	FixedIn     string `json:"fixed_in,omitempty"`
	Description string `json:"description,omitempty"`
}

// Set, yüklü zafiyet veri kümesidir.
type Set struct {
	entries []Entry
}

// Size, kayıt sayısını döner.
func (s *Set) Size() int {
	if s == nil {
		return 0
	}
	return len(s.entries)
}

// Load, JSON dizisinden zafiyet veri kümesi ayrıştırır. Her kayıt en az
// product/cve/severity taşımalıdır.
func Load(r io.Reader) (*Set, error) {
	var entries []Entry
	if err := json.NewDecoder(r).Decode(&entries); err != nil {
		return nil, fmt.Errorf("vuln: JSON ayrıştırılamadı: %w", err)
	}
	for i, e := range entries {
		if e.Product == "" || e.CVE == "" || e.Severity == "" {
			return nil, fmt.Errorf("vuln: kayıt[%d] eksik alan (product/cve/severity zorunlu)", i)
		}
	}
	return &Set{entries: entries}, nil
}

// LoadFile, bir dosyadan zafiyet veri kümesi yükler.
func LoadFile(path string) (*Set, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Load(f)
}

// Match, bir cihazın yüklü yazılım listesine karşı tüm eşleşen zafiyetleri döner
// (paket-atıflı). Aynı CVE birden çok pakete uyarsa her biri ayrı bildirilir.
func (s *Set) Match(software []string) []Finding {
	if s == nil || len(s.entries) == 0 {
		return nil
	}
	var out []Finding
	for _, pkg := range software {
		for _, e := range s.entries {
			if e.matches(pkg) {
				out = append(out, Finding{
					CVE: e.CVE, Product: e.Product, Package: pkg, Severity: e.Severity,
					FixedIn: e.FixedVersion, Description: e.Description,
				})
			}
		}
	}
	return out
}
