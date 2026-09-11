package secrets

import (
	"errors"
	"os"
	"testing"
)

func TestEnvProvider(t *testing.T) {
	p := NewEnvProvider("XEMS_").SetLookup(func(k string) (string, bool) {
		if k == "XEMS_DB_PASS" {
			return "gizli", true
		}
		return "", false
	})
	if v, ok, _ := p.Get("DB_PASS"); !ok || v != "gizli" {
		t.Errorf("env sırrı çözülmeli: %q ok=%v", v, ok)
	}
	if _, ok, _ := p.Get("YOK"); ok {
		t.Error("olmayan sır ok=false olmalı")
	}
}

func TestFileProvider(t *testing.T) {
	files := map[string][]byte{"/secrets/api_key": []byte("  anahtar-degeri\n")}
	p := NewFileProvider("/secrets").SetReader(func(path string) ([]byte, error) {
		if b, ok := files[path]; ok {
			return b, nil
		}
		return nil, os.ErrNotExist
	})
	if v, ok, _ := p.Get("api_key"); !ok || v != "anahtar-degeri" {
		t.Errorf("dosya sırrı kırpılıp çözülmeli: %q ok=%v", v, ok)
	}
	if _, ok, _ := p.Get("yok"); ok {
		t.Error("olmayan dosya ok=false")
	}
	// dizin-dışına kaçış reddedilmeli
	for _, bad := range []string{"../etc/passwd", "a/b", "..", "a\b"} {
		if _, ok, _ := p.Get(bad); ok {
			t.Errorf("güvensiz ad reddedilmeli: %q", bad)
		}
	}
}

func TestChainFallback(t *testing.T) {
	c := NewChain(
		MapProvider{}, // boş
		MapProvider{"token": "birinci"},
		MapProvider{"token": "ikinci"}, // erişilmemeli (ilk bulan kazanır)
	)
	if v, ok, _ := c.Get("token"); !ok || v != "birinci" {
		t.Errorf("ilk bulan dönmeli: %q", v)
	}
	if _, ok, _ := c.Get("yok"); ok {
		t.Error("hiçbirinde yoksa ok=false")
	}
}

func TestChainPropagatesError(t *testing.T) {
	boom := errors.New("sağlayıcı hatası")
	c := NewChain(errProvider{boom})
	if _, _, err := c.Get("x"); !errors.Is(err, boom) {
		t.Errorf("hata yayılmalı: %v", err)
	}
}

type errProvider struct{ err error }

func (e errProvider) Get(string) (string, bool, error) { return "", false, e.err }

func TestKeyRingRotation(t *testing.T) {
	kr := NewKeyRing(2)
	kr.Add("v1", []byte("key1"))
	kr.Add("v2", []byte("key2"))
	if v, key := kr.Current(); v != "v2" || string(key) != "key2" {
		t.Errorf("güncel v2/key2 olmalı: %q", v)
	}
	// eski sürüm hâlâ doğrulanabilir (örtüşme)
	if k, ok := kr.Get("v1"); !ok || string(k) != "key1" {
		t.Error("v1 örtüşme için erişilebilir olmalı")
	}
	// üçüncü ekleme v1'i tahliye eder (max=2)
	kr.Add("v3", []byte("key3"))
	if _, ok := kr.Get("v1"); ok {
		t.Error("v1 tahliye edilmeli (max=2)")
	}
	if got := kr.Versions(); len(got) != 2 || got[0] != "v2" || got[1] != "v3" {
		t.Errorf("sürümler [v2 v3] olmalı: %v", got)
	}
	// döndürülen anahtar kopya olmalı (mutasyon halkayı etkilememeli)
	_, key := kr.Current()
	key[0] = 'X'
	if _, k := kr.Current(); k[0] == 'X' {
		t.Error("Current kopya dönmeli (halka değişmemeli)")
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"":           "",
		"ab":         "**",
		"abcd":       "****",
		"sekizhane":  "se*****ne",
		"1234567890": "12******90",
	}
	for in, want := range cases {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q)=%q, beklenen %q", in, got, want)
		}
	}
}
