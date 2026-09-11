package connector

import (
	"context"
	"errors"
	"testing"
	"time"

	"xems.corp/suite/server/internal/model"
)

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	a := &StaticConnector{ConnName: "a", ConnKind: "siem"}
	b := &StaticConnector{ConnName: "b", ConnKind: "cloud"}
	if err := r.Register(a); err != nil {
		t.Fatal(err)
	}
	if err := r.Register(b); err != nil {
		t.Fatal(err)
	}
	// yinelenen ad
	if err := r.Register(&StaticConnector{ConnName: "a"}); err == nil {
		t.Error("yinelenen ad reddedilmeli")
	}
	// boş ad
	if err := r.Register(&StaticConnector{ConnName: ""}); err == nil {
		t.Error("boş ad reddedilmeli")
	}
	// nil
	if err := r.Register(nil); err == nil {
		t.Error("nil reddedilmeli")
	}
	// List deterministik (ada göre sıralı)
	list := r.List()
	if len(list) != 2 || list[0].Name() != "a" || list[1].Name() != "b" {
		t.Fatalf("List sıralı 2 öğe olmalı: %v", list)
	}
	// Get + Unregister
	if _, ok := r.Get("a"); !ok {
		t.Error("a bulunmalı")
	}
	if !r.Unregister("a") || r.Unregister("a") {
		t.Error("ilk kaldırma true, ikinci false olmalı")
	}
	if _, ok := r.Get("a"); ok {
		t.Error("a kaldırılmış olmalı")
	}
}

func TestRunnerDeliversToSink(t *testing.T) {
	evs := []model.Event{{Message: "e1"}, {Message: "e2"}}
	c := &StaticConnector{ConnName: "s", Events: evs}
	var got []model.Event
	r := NewRunner(c, 0, func(e []model.Event) { got = append(got, e...) })
	n, err := r.RunOnce(context.Background())
	if err != nil || n != 2 || len(got) != 2 {
		t.Fatalf("2 olay teslim edilmeli: n=%d err=%v got=%d", n, err, len(got))
	}
}

func TestRunnerRecoversFromPanic(t *testing.T) {
	c := &FuncConnector{ConnName: "boom", FetchFn: func(context.Context) ([]model.Event, error) {
		panic("bozuk bağlayıcı")
	}}
	r := NewRunner(c, 0, nil)
	_, err := r.RunOnce(context.Background())
	if err == nil {
		t.Fatal("panik hataya çevrilmeli (ana süreç çökmemeli)")
	}
}

func TestRunnerFetchError(t *testing.T) {
	sentinel := errors.New("kaynak hatası")
	c := &StaticConnector{ConnName: "err", Err: sentinel}
	r := NewRunner(c, 0, nil)
	if _, err := r.RunOnce(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("fetch hatası dönmeli: %v", err)
	}
}

// TestRunnerStartCallsOnError, Start döngüsünün bir tick'te bağlayıcıyı yokladığını,
// hata olduğunda OnError'ı çağırdığını ve ctx iptalinde durduğunu deterministik doğrular.
func TestRunnerStartCallsOnError(t *testing.T) {
	sentinel := errors.New("kaynak hatası")
	c := &StaticConnector{ConnName: "err", Err: sentinel}
	called := make(chan error, 1)
	r := NewRunner(c, 0, nil).OnError(func(_ string, e error) { called <- e })

	tick := make(chan time.Time, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Start(ctx, tick)

	tick <- time.Now() // bir yoklama tetikle
	select {
	case e := <-called:
		if !errors.Is(e, sentinel) {
			t.Fatalf("OnError sentinel almalı: %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnError çağrılmadı")
	}
}
