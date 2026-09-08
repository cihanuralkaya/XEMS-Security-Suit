package fim

import (
	"os"
	"path/filepath"
	"testing"
)

// Diff: ilk çağrı taban çizgisidir (değişiklik yok); sonra ekleme/değiştirme/silme
// doğru raporlanmalı ve taban çizgisi güncellenmeli.
func TestTrackerDiff(t *testing.T) {
	tr := &Tracker{}
	base := map[string]string{"/a": "h1", "/b": "h2"}
	if ch := tr.Diff(base); ch != nil {
		t.Fatalf("ilk çağrı taban çizgisi olmalı (değişiklik yok): %+v", ch)
	}
	// /a değişti, /c eklendi, /b silindi.
	next := map[string]string{"/a": "h1-yeni", "/c": "h3"}
	ch := tr.Diff(next)
	if len(ch) != 3 {
		t.Fatalf("3 değişiklik beklendi: %+v", ch)
	}
	got := map[string]ChangeType{}
	for _, c := range ch {
		got[c.Path] = c.Type
	}
	if got["/a"] != Modified || got["/c"] != Added || got["/b"] != Deleted {
		t.Fatalf("beklenen değişiklik türleri tutmadı: %+v", got)
	}
	// Taban çizgisi güncellendi: aynı küme tekrar → değişiklik yok.
	if ch2 := tr.Diff(next); len(ch2) != 0 {
		t.Fatalf("değişmeyen tarama sıfır değişiklik üretmeli: %+v", ch2)
	}
}

// Scan gerçek dosyaları hash'ler; içerik değişince hash değişmeli (uçtan uca çekirdek).
func TestScanHashesRealFiles(t *testing.T) {
	dir := t.TempDir()
	fp := filepath.Join(dir, "watched.txt")
	if err := os.WriteFile(fp, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	s1 := Scan([]string{dir})
	if s1[fp] == "" {
		t.Fatalf("dosya hash'lenmeliydi: %+v", s1)
	}
	if err := os.WriteFile(fp, []byte("v2-değişti"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := Scan([]string{dir})
	if s2[fp] == s1[fp] {
		t.Fatal("içerik değişince hash de değişmeliydi")
	}
	// Tracker ile birlikte: modified yakalanmalı.
	tr := &Tracker{}
	tr.Diff(s1)
	ch := tr.Diff(s2)
	if len(ch) != 1 || ch[0].Type != Modified || ch[0].Path != fp {
		t.Fatalf("modified değişikliği beklendi: %+v", ch)
	}
}
