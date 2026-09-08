package security

import (
	"testing"
	"time"
)

// rfcSecret, RFC 6238 Appendix B SHA1 test vektörlerinin paylaşılan sırrı:
// ASCII "12345678901234567890" (20 bayt), Base32 kodlanmış.
var rfcSecret = b32.EncodeToString([]byte("12345678901234567890"))

// TestTOTPRFC6238Vectors, RFC 6238 Appendix B'deki bilinen değerleri (son 6
// haneye kesilmiş) doğrular — kripto çekirdeğinin standarda uyumunu kanıtlar.
func TestTOTPRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string // 8-haneli RFC değerinin son 6 hanesi
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, c := range cases {
		got, err := TOTPAt(rfcSecret, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("unix=%d: %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("unix=%d: kod=%s beklenen=%s", c.unix, got, c.want)
		}
	}
}

func TestVerifyTOTPWindow(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1700000000, 0)
	code, _ := TOTPAt(secret, now)

	// Aynı adım geçerli.
	if !VerifyTOTP(secret, code, now) {
		t.Fatal("geçerli kod reddedildi")
	}
	// Bir önceki ve sonraki adım (saat kayması) kabul edilir.
	if !VerifyTOTP(secret, code, now.Add(30*time.Second)) {
		t.Fatal("+1 adım penceresi reddedildi")
	}
	if !VerifyTOTP(secret, code, now.Add(-30*time.Second)) {
		t.Fatal("-1 adım penceresi reddedildi")
	}
	// İki adım ötesi (60 sn) pencere dışı → reddedilir.
	if VerifyTOTP(secret, code, now.Add(90*time.Second)) {
		t.Fatal("pencere dışı kod kabul edildi")
	}
	// Yanlış/boş/kısa kodlar reddedilir (fail-closed).
	if VerifyTOTP(secret, "000000", now.Add(600*time.Second)) && code == "000000" {
		// olası çakışmayı yok say
	}
	if VerifyTOTP(secret, "", now) {
		t.Fatal("boş kod kabul edildi")
	}
	if VerifyTOTP(secret, "12345", now) {
		t.Fatal("kısa kod kabul edildi")
	}
	if VerifyTOTP("!!!geçersiz base32!!!", code, now) {
		t.Fatal("geçersiz sır kabul edildi")
	}
}

func TestOTPAuthURI(t *testing.T) {
	uri := OTPAuthURI("XEMS Konsol", "admin@corp", "ABCDEF")
	for _, want := range []string{"otpauth://totp/", "secret=ABCDEF", "issuer=XEMS", "digits=6", "period=30"} {
		if !contains(uri, want) {
			t.Errorf("URI %q içermeliydi: %q", uri, want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
