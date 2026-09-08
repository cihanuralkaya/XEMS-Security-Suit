package grpc

import (
	"context"
	"sync"
	"testing"
	"time"

	xemsv1 "xems.corp/suite/gen/xems/v1"
)

type fakeProvider struct {
	mu     sync.Mutex
	bundle *xemsv1.PolicyBundle
}

func (f *fakeProvider) set(version string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bundle = &xemsv1.PolicyBundle{PolicyVersion: version}
}
func (f *fakeProvider) CurrentPolicy(_ context.Context, _ string) (*xemsv1.PolicyBundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bundle, nil
}

func TestStreamPolicyLoopInitialAndPush(t *testing.T) {
	fp := &fakeProvider{}
	fp.set("v1")
	notify := make(chan struct{}, 1)
	sent := make(chan string, 8)
	send := func(b *xemsv1.PolicyBundle) error { sent <- b.GetPolicyVersion(); return nil }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- streamPolicyLoop(ctx, "dev-1", "", fp, notify, send) }()

	// İlk paket v1 gönderilmeli.
	if got := recvTimeout(t, sent); got != "v1" {
		t.Fatalf("ilk paket v1 olmalı, %q", got)
	}

	// Politika v2'ye değişip bildirilince ANINDA itilmeli.
	fp.set("v2")
	notify <- struct{}{}
	if got := recvTimeout(t, sent); got != "v2" {
		t.Fatalf("push v2 olmalı, %q", got)
	}

	// Aynı sürüm için bildirim → gönderim OLMAMALI.
	notify <- struct{}{}
	select {
	case v := <-sent:
		t.Fatalf("aynı sürümde gönderim olmamalıydı: %q", v)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("ctx iptalinde nil dönmeliydi, %v", err)
	}
}

func TestStreamPolicyLoopNoPolicy(t *testing.T) {
	fp := &fakeProvider{} // bundle nil
	notify := make(chan struct{})
	sent := make(chan string, 1)
	send := func(b *xemsv1.PolicyBundle) error { sent <- b.GetPolicyVersion(); return nil }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- streamPolicyLoop(ctx, "dev-1", "", fp, notify, send) }()

	select {
	case <-sent:
		t.Fatal("atanmış politika yokken gönderim olmamalı")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func recvTimeout(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(time.Second):
		t.Fatal("gönderim beklenirken zaman aşımı")
		return ""
	}
}
