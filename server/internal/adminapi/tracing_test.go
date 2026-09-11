package adminapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"xems.corp/suite/server/internal/trace"
)

func TestTracingMiddlewarePropagates(t *testing.T) {
	srv, _ := newServer(t)
	srv.SetTracing(true)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1) traceparent'sız istek → yanıt geçerli bir traceparent + X-Trace-Id taşır.
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	tp := resp.Header.Get("traceparent")
	if tp == "" {
		t.Fatal("yanıt traceparent taşımalı")
	}
	tid, _, ok := trace.ParseTraceparent(tp)
	if !ok || !tid.IsValid() {
		t.Fatalf("yanıt traceparent geçerli olmalı: %q", tp)
	}
	if resp.Header.Get("X-Trace-Id") != tid.String() {
		t.Errorf("X-Trace-Id traceparent ile eşleşmeli")
	}

	// 2) gelen traceparent → yanıt AYNI trace-id'yi (çocuk span) korur.
	inTID, err := trace.NewTraceID()
	if err != nil {
		t.Fatal(err)
	}
	inSID, err := trace.NewSpanID()
	if err != nil {
		t.Fatal(err)
	}
	in := "00-" + inTID.String() + "-" + inSID.String() + "-01"
	req, _ := http.NewRequest("GET", ts.URL+"/healthz", nil)
	req.Header.Set("traceparent", in)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	outTID, _, ok := trace.ParseTraceparent(resp2.Header.Get("traceparent"))
	if !ok || outTID.String() != inTID.String() {
		t.Errorf("gelen trace-id korunmalı (çocuk span): in=%s out=%s", inTID, outTID)
	}
}

func TestTracingDisabledByDefault(t *testing.T) {
	srv, _ := newServer(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("traceparent") != "" {
		t.Error("izleme varsayılan kapalı olmalı (traceparent yok)")
	}
}
