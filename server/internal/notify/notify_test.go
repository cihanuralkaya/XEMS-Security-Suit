package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebhookNotifierDeliversHighSeverity(t *testing.T) {
	got := make(chan Alert, 4)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var a Alert
		_ = json.NewDecoder(r.Body).Decode(&a)
		got <- a
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	n, err := NewWebhookNotifier(ts.URL, "HIGH", "")
	if err != nil {
		t.Fatal(err)
	}
	n.client = ts.Client() // test TLS sertifikasına güven

	// INFO eşik altında → gönderilmez.
	n.Notify(Alert{DeviceID: "d1", Severity: "INFO", Message: "rutin"})
	// HIGH → iletilir.
	n.Notify(Alert{DeviceID: "d2", Severity: "HIGH", Message: "şüpheli süreç", Category: "PROCESS"})

	select {
	case a := <-got:
		if a.Severity != "HIGH" || a.DeviceID != "d2" {
			t.Fatalf("beklenmeyen uyarı: %+v", a)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HIGH uyarı 2 sn içinde teslim edilmedi")
	}
	// INFO teslim edilmemeli (eşik filtresi).
	select {
	case a := <-got:
		t.Fatalf("INFO filtrelenmeliydi ama teslim edildi: %+v", a)
	case <-time.After(250 * time.Millisecond):
	}
}

func TestWebhookNotifierRejectsInsecureURL(t *testing.T) {
	if _, err := NewWebhookNotifier("http://insecure.example/hook", "HIGH", ""); err == nil {
		t.Fatal("http (TLS'siz) URL reddedilmeliydi")
	}
	if _, err := NewWebhookNotifier("bu bir url değil", "HIGH", ""); err == nil {
		t.Fatal("geçersiz URL reddedilmeliydi")
	}
}

func TestSlackFormatPayload(t *testing.T) {
	got := make(chan string, 2)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]string
		_ = json.NewDecoder(r.Body).Decode(&m)
		got <- m["text"]
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	n, err := NewWebhookNotifier(ts.URL, "HIGH", "slack")
	if err != nil {
		t.Fatal(err)
	}
	n.client = ts.Client()
	n.Notify(Alert{DeviceID: "dev-9", Severity: "CRITICAL", Category: "SECURITY",
		Message: "kurcalama tespit edildi", TechniqueID: "T1562", TechniqueName: "Impair Defenses", Tactic: "Defense Evasion"})

	select {
	case txt := <-got:
		for _, want := range []string{":rotating_light:", "*[CRITICAL]*", "kurcalama tespit edildi", "`dev-9`", "T1562"} {
			if !strings.Contains(txt, want) {
				t.Errorf("Slack metni %q içermeliydi: %q", want, txt)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Slack biçimli uyarı teslim edilmedi")
	}
}

func TestFormatDefaultsToJSON(t *testing.T) {
	n, _ := NewWebhookNotifier("https://x.example/h", "HIGH", "garip")
	if n.format != "json" {
		t.Fatalf("bilinmeyen biçim json'a düşmeliydi, %q", n.format)
	}
}

func TestSevRankOrdering(t *testing.T) {
	if !(sevRank("CRITICAL") > sevRank("HIGH") && sevRank("HIGH") > sevRank("MEDIUM") &&
		sevRank("MEDIUM") > sevRank("LOW") && sevRank("LOW") > sevRank("INFO") && sevRank("INFO") > sevRank("bilinmeyen")) {
		t.Fatal("önem düzeyi sıralaması yanlış")
	}
}

func TestWebhookHMACSignature(t *testing.T) {
	const secret = "topsecret"
	gotSig := make(chan string, 2)
	gotBody := make(chan []byte, 2)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody <- b
		gotSig <- r.Header.Get("X-XEMS-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	n, err := NewWebhookNotifier(ts.URL, "HIGH", "")
	if err != nil {
		t.Fatal(err)
	}
	n.client = ts.Client()
	n.SetHMACSecret(secret)
	n.Notify(Alert{DeviceID: "d1", Severity: "CRITICAL", Message: "test"})

	select {
	case sig := <-gotSig:
		body := <-gotBody
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		if sig != want {
			t.Fatalf("imza uyuşmuyor: got %q want %q", sig, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("imzalı webhook 2 sn içinde teslim edilmedi")
	}
}

func TestWebhookNoSignatureWhenUnset(t *testing.T) {
	gotSig := make(chan string, 2)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig <- r.Header.Get("X-XEMS-Signature")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	n, _ := NewWebhookNotifier(ts.URL, "HIGH", "")
	n.client = ts.Client()
	n.Notify(Alert{DeviceID: "d1", Severity: "CRITICAL", Message: "test"})
	select {
	case sig := <-gotSig:
		if sig != "" {
			t.Fatalf("sır yokken imza başlığı olmamalı, %q", sig)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook teslim edilmedi")
	}
}
