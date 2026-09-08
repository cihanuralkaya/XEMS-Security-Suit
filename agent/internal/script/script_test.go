package script

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"runtime"
	"strings"
	"testing"
	"time"

	"xems.corp/suite/scriptwire"
)

// shell, OS'e uygun yorumlayıcı ve zararsız komut gövdeleri döner.
func shell() (interp, echoBody, sleepBody string) {
	if runtime.GOOS == "windows" {
		return "cmd", "echo merhaba", "ping -n 2 127.0.0.1"
	}
	return "sh", "echo merhaba", "sleep 1"
}

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestVerifyThenRun(t *testing.T) {
	interp, echoBody, _ := shell()
	pub, priv := keys(t)
	v, _ := NewVerifier(pub)

	s := scriptwire.Script{Interpreter: interp, Body: echoBody}
	sig := ed25519.Sign(priv, scriptwire.CanonicalBytes(s))

	if err := v.Verify(s, sig); err != nil {
		t.Fatalf("geçerli imza doğrulanamadı: %v", err)
	}
	res, err := Run(context.Background(), s, 10*time.Second, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Stdout, "merhaba") {
		t.Fatalf("çıktı 'merhaba' içermeli: %q", res.Stdout)
	}
	if res.ExitCode != 0 {
		t.Fatalf("çıkış kodu 0 olmalı, %d", res.ExitCode)
	}
}

func TestTamperedScriptRejected(t *testing.T) {
	interp, echoBody, _ := shell()
	pub, priv := keys(t)
	v, _ := NewVerifier(pub)

	s := scriptwire.Script{Interpreter: interp, Body: echoBody}
	sig := ed25519.Sign(priv, scriptwire.CanonicalBytes(s))

	// Saldırgan gövdeyi değiştirir → imza tutmamalı, çalıştırılmamalı.
	s.Body = "echo ELE_GECIRILDI"
	if err := v.Verify(s, sig); err != ErrBadSignature {
		t.Fatalf("değiştirilmiş script ErrBadSignature dönmeliydi: %v", err)
	}
}

func TestTimeout(t *testing.T) {
	interp, _, sleepBody := shell()
	s := scriptwire.Script{Interpreter: interp, Body: sleepBody}
	res, err := Run(context.Background(), s, 300*time.Millisecond, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut {
		t.Fatal("uzun script timeout ile sonlandırılmalıydı")
	}
}

func TestOutputCap(t *testing.T) {
	interp, echoBody, _ := shell()
	s := scriptwire.Script{Interpreter: interp, Body: echoBody}
	res, err := Run(context.Background(), s, 10*time.Second, 3) // 3 bayt sınır
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Stdout) > 3 {
		t.Fatalf("çıktı 3 baytla sınırlanmalıydı, %d bayt", len(res.Stdout))
	}
}

func TestUnsupportedInterpreter(t *testing.T) {
	_, err := Run(context.Background(), scriptwire.Script{Interpreter: "malware", Body: "x"}, time.Second, 1024)
	if err == nil {
		t.Fatal("desteklenmeyen yorumlayıcı reddedilmeliydi")
	}
}
