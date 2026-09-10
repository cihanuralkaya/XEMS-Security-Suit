package ioc

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

const sample = `
# tehdit istihbaratı feed'i
10.13.37.5        known-c2
AA:BB:CC:DD:EE:FF  rogue-device
evil.example.com   phishing
mimikatz.exe       kimlik-hirsizi
`

func mustLoad(t *testing.T) *Set {
	t.Helper()
	s, err := Load(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLoadAndSize(t *testing.T) {
	s := mustLoad(t)
	if s.Size() != 4 {
		t.Fatalf("4 gösterge beklenirdi, %d", s.Size())
	}
}

func TestMatchDetailsExact(t *testing.T) {
	s := mustLoad(t)
	// IP Details'te tam eşleşme.
	if lbl, ind, ok := s.Match(map[string]any{"ip": "10.13.37.5", "mac": "x"}, "yeni cihaz"); !ok || lbl != "known-c2" || ind != "10.13.37.5" {
		t.Fatalf("IP eşleşmeliydi: %s %s %v", lbl, ind, ok)
	}
	// MAC büyük/küçük harf duyarsız.
	if lbl, _, ok := s.Match(map[string]any{"mac": "aa:bb:cc:dd:ee:ff"}, ""); !ok || lbl != "rogue-device" {
		t.Fatalf("MAC (küçük harf) eşleşmeliydi: %s %v", lbl, ok)
	}
	// Süreç adı Details'te.
	if lbl, _, ok := s.Match(map[string]any{"process": "mimikatz.exe", "pid": 500}, ""); !ok || lbl != "kimlik-hirsizi" {
		t.Fatalf("süreç eşleşmeliydi: %s %v", lbl, ok)
	}
}

func TestMatchMessageSubstring(t *testing.T) {
	s := mustLoad(t)
	if lbl, _, ok := s.Match(nil, "bağlantı denendi: evil.example.com:443"); !ok || lbl != "phishing" {
		t.Fatalf("mesaja gömülü alan adı eşleşmeliydi: %s %v", lbl, ok)
	}
}

func TestNoMatch(t *testing.T) {
	s := mustLoad(t)
	if _, _, ok := s.Match(map[string]any{"ip": "8.8.8.8"}, "temiz olay"); ok {
		t.Fatal("temiz olay eşleşmemeliydi")
	}
	// Boş/nil set eşleşmez.
	var empty *Set
	if _, _, ok := empty.Match(map[string]any{"ip": "10.13.37.5"}, ""); ok {
		t.Fatal("nil set eşleşmemeliydi")
	}
}

func TestLoadSkipsCommentsAndBlanks(t *testing.T) {
	s, err := Load(strings.NewReader("# yorum\n\n   \n1.2.3.4\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Size() != 1 {
		t.Fatalf("yalnız 1 gösterge (yorum/boş atlanmalı), %d", s.Size())
	}
	if lbl, _, ok := s.Match(map[string]any{"ip": "1.2.3.4"}, ""); !ok || lbl != "etiketsiz" {
		t.Fatalf("etiketsiz gösterge eşleşmeliydi: %s %v", lbl, ok)
	}
}

func TestLoadEnrichmentMetadata(t *testing.T) {
	set, err := Load(strings.NewReader(
		"1.2.3.4  known-c2  conf=high src=abuse.ch\n" +
			"evil.example.com  phishing altyapısı\n" + // meta yok → varsayılan medium
			"deadbeef  hash conf=critical\n"))
	if err != nil {
		t.Fatal(err)
	}
	ind, val, ok := set.MatchIndicator(map[string]any{"ip": "1.2.3.4"}, "")
	if !ok || val != "1.2.3.4" {
		t.Fatalf("eşleşme bekleniyordu, %v %q", ok, val)
	}
	if ind.Label != "known-c2" || ind.Confidence != "high" || ind.Source != "abuse.ch" {
		t.Fatalf("zenginleştirme yanlış: %+v", ind)
	}
	// Meta olmayan → varsayılan medium, kaynak boş, etiket korunur.
	ind2, _, _ := set.MatchIndicator(map[string]any{"d": "evil.example.com"}, "")
	if ind2.Label != "phishing altyapısı" || ind2.Confidence != "medium" || ind2.Source != "" {
		t.Fatalf("varsayılan zenginleştirme yanlış: %+v", ind2)
	}
	// conf-only
	ind3, _, _ := set.MatchIndicator(map[string]any{"h": "deadbeef"}, "")
	if ind3.Label != "hash" || ind3.Confidence != "critical" {
		t.Fatalf("conf-only yanlış: %+v", ind3)
	}
}

func TestMatchBackwardCompatible(t *testing.T) {
	// Eski Match imzası hâlâ etiketi döndürmeli (geriye uyumluluk).
	set, _ := Load(strings.NewReader("1.2.3.4 c2 conf=high src=feed"))
	lbl, val, ok := set.Match(map[string]any{"ip": "1.2.3.4"}, "")
	if !ok || lbl != "c2" || val != "1.2.3.4" {
		t.Fatalf("Match geriye uyumlu değil: %q %q %v", lbl, val, ok)
	}
}

func TestLoadFileSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := []byte("1.2.3.4 c2 conf=high\nevil.com phishing\n")
	dir := t.TempDir()
	fp := dir + "/ioc.txt"
	if err := os.WriteFile(fp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fp+".sig", []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := LoadFileSigned(fp, pub)
	if err != nil {
		t.Fatalf("geçerli imza yüklenmeli: %v", err)
	}
	if set.Size() != 2 {
		t.Fatalf("2 gösterge beklenirdi, %d", set.Size())
	}
	// Kurcalama reddedilmeli.
	if err := os.WriteFile(fp, append(data, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFileSigned(fp, pub); err != ErrBadSignature {
		t.Fatalf("kurcalama ErrBadSignature vermeli, %v", err)
	}
}
