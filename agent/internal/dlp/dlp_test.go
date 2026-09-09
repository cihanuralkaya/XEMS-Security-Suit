package dlp

import "testing"

func signalCount(sigs []Signal, kind string) int {
	for _, s := range sigs {
		if s.Kind == kind {
			return s.Count
		}
	}
	return 0
}

func TestLuhn(t *testing.T) {
	if !luhnValid("4111111111111111") { // geçerli Visa test numarası
		t.Fatal("geçerli Luhn reddedildi")
	}
	if luhnValid("4111111111111112") {
		t.Fatal("geçersiz Luhn kabul edildi")
	}
}

func TestScanCreditCard(t *testing.T) {
	text := "ödeme kartı 4111 1111 1111 1111 ve rastgele 1234567890123456 sayısı"
	sigs := Scan(text)
	// Yalnız Luhn-geçerli olan sayılmalı.
	if signalCount(sigs, "credit_card") != 1 {
		t.Fatalf("1 kredi kartı beklenirdi, %v", sigs)
	}
}

func TestTCKN(t *testing.T) {
	// Algoritmik olarak geçerli bir TCKN (d1=1, kalan 0'lar): d10=7, d11=8.
	valid := "10000000078"
	if !tcknValid(valid) {
		t.Fatalf("geçerli TCKN reddedildi: %s", valid)
	}
	if tcknValid("12345678901") {
		t.Fatal("geçersiz TCKN kabul edildi")
	}
	if tcknValid("00000000000") {
		t.Fatal("0 ile başlayan TCKN reddedilmeli")
	}
	sigs := Scan("kimlik no: 10000000078 test")
	if signalCount(sigs, "tckn") != 1 {
		t.Fatalf("1 TCKN beklenirdi, %v", sigs)
	}
}

func TestIBAN(t *testing.T) {
	// Yaygın geçerli TR IBAN örneği (mod-97).
	if !ibanValidTR("TR330006100519786457841326") {
		t.Fatal("geçerli TR IBAN reddedildi")
	}
	if ibanValidTR("TR330006100519786457841327") {
		t.Fatal("bozuk IBAN kabul edildi")
	}
	sigs := Scan("hesap TR33 0006 1005 1978 6457 8413 26 numarası")
	if signalCount(sigs, "iban") != 1 {
		t.Fatalf("1 IBAN beklenirdi, %v", sigs)
	}
}

func TestEmail(t *testing.T) {
	sigs := Scan("iletişim: a@b.com, c.d@e.org")
	if signalCount(sigs, "email") != 2 {
		t.Fatalf("2 e-posta beklenirdi, %v", sigs)
	}
}

func TestScanRedactsNoRawValues(t *testing.T) {
	// Sinyaller yalnız tür + sayı taşımalı (ham değer yok — gizlilik).
	sigs := Scan("kart 4111111111111111 mail x@y.com")
	for _, s := range sigs {
		if s.Kind == "" || s.Count <= 0 {
			t.Fatalf("geçersiz sinyal: %+v", s)
		}
	}
	if len(sigs) != 2 {
		t.Fatalf("kredi kartı + e-posta = 2 sinyal beklenirdi, %v", sigs)
	}
}

func TestScanClean(t *testing.T) {
	if sigs := Scan("bu metinde hassas veri yok, sıradan bir cümle."); len(sigs) != 0 {
		t.Fatalf("temiz metinde sinyal olmamalı, %v", sigs)
	}
}
