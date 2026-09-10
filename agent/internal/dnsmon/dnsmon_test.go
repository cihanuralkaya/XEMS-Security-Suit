package dnsmon

import "testing"

func TestScoreDomainLegitNotSuspicious(t *testing.T) {
	// Yaygın meşru alanlar işaretlenmemeli (yanlış pozitif kontrolü).
	for _, d := range []string{
		"google.com", "microsoft.com", "cloudflare.com", "wikipedia.org",
		"salesforce.com", "amazon.com", "github.com", "route53.aws",
		"cdn.example.com", "mail.google.com",
	} {
		if s := ScoreDomain(d); s.Suspicious {
			t.Errorf("%q yanlışlıkla DGA işaretlendi: %+v", d, s)
		}
	}
}

func TestScoreDomainDGASuspicious(t *testing.T) {
	// DGA-benzeri rastgele/rakam-yoğun alanlar işaretlenmeli.
	for _, d := range []string{
		"xjdk3l2m9fqp.com",
		"kq7n8fj2wmxz.net",
		"1a2b3c4d5e6f7g.info",
		"qzwxrfvtbgnh.biz",
	} {
		if s := ScoreDomain(d); !s.Suspicious {
			t.Errorf("%q DGA işaretlenmeliydi: %+v", d, s)
		}
	}
}

func TestScoreDomainEmpty(t *testing.T) {
	if s := ScoreDomain(""); s.Suspicious {
		t.Fatal("boş alan işaretlenmemeli")
	}
	if s := ScoreDomain("..."); s.Suspicious {
		t.Fatal("geçersiz alan işaretlenmemeli")
	}
}

func TestSecondLevelLabel(t *testing.T) {
	cases := map[string]string{
		"example.com":      "example",
		"a.b.example.com":  "example",
		"localhost":        "localhost",
		"foo.co":           "foo",
		"xjdk3l2m9fqp.com": "xjdk3l2m9fqp",
	}
	for in, want := range cases {
		if got := secondLevelLabel(in); got != want {
			t.Errorf("secondLevelLabel(%q)=%q beklenen %q", in, got, want)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	if h := shannonEntropy("aaaa"); h != 0 {
		t.Fatalf("tek karakter entropi 0 olmalı, %v", h)
	}
	// "ab" → 1 bit.
	if h := shannonEntropy("ab"); h < 0.99 || h > 1.01 {
		t.Fatalf("'ab' entropi ~1 olmalı, %v", h)
	}
}

func TestParseIpconfigDisplayDNS(t *testing.T) {
	out := `
    example.com
    ----------------------------------------
    Record Name . . . . . : example.com
    Record Type . . . . . : 1
    A (Host) Record . . . : 93.184.216.34

    ----------------------------------------
    Kayıt Adı . . . . . . : xjdk3l2m9fqp.com
    Record Type . . . . . : 1

    Record Name . . . . . : example.com
`
	got := parseIpconfigDisplayDNS(out)
	if len(got) != 2 {
		t.Fatalf("2 benzersiz kayıt beklenirdi, %v", got)
	}
	// Benzersizlik: example.com iki kez var ama bir kez sayılmalı.
	seen := map[string]bool{}
	for _, n := range got {
		seen[n] = true
	}
	if !seen["example.com"] || !seen["xjdk3l2m9fqp.com"] {
		t.Fatalf("beklenen adlar yok: %v", got)
	}
}

func TestMaxConsonantRunDGA(t *testing.T) {
	// Uzun ünsüz dizili DGA (sesli oranı entropi kuralını tetiklemeyebilir) → yakalanmalı.
	s := ScoreDomain("xjqkbzmp.com")
	if s.MaxConsonantRun < 5 {
		t.Fatalf("uzun ünsüz dizisi beklenirdi, %d", s.MaxConsonantRun)
	}
	if !s.Suspicious {
		t.Fatalf("uzun ünsüz dizili alan şüpheli işaretlenmeli: %+v", s)
	}
}

func TestNormalDomainNotConsonantFlagged(t *testing.T) {
	// Gerçek alanlar 5+ ardışık ünsüz taşımaz → kural onları işaretlememeli.
	for _, d := range []string{"google.com", "microsoft.com", "wikipedia.org", "github.com"} {
		if s := ScoreDomain(d); s.Suspicious {
			t.Errorf("%q şüpheli işaretlenmemeliydi: %+v", d, s)
		}
	}
}
