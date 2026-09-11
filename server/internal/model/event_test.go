package model

import (
	"strings"
	"testing"
	"time"
)

func TestEnsureIDDeterministic(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	mk := func() Event {
		return Event{TenantID: "t1", DeviceID: "d1", Sequence: 7, OccurredAt: at,
			Category: "SECURITY", Message: "powershell spawned"}
	}
	a, b := mk(), mk()
	ida, idb := a.EnsureID(), b.EnsureID()
	if ida != idb {
		t.Fatalf("aynı olay aynı kimliği vermeli: %q != %q", ida, idb)
	}
	if !strings.HasPrefix(ida, "evt_") || len(ida) != 4+32 {
		t.Fatalf("beklenmeyen kimlik biçimi: %q", ida)
	}
	// İçerik değişince kimlik değişmeli.
	c := mk()
	c.Message = "farklı"
	if c.EnsureID() == ida {
		t.Error("farklı içerik farklı kimlik vermeli")
	}
	// Zaten kimlik varsa korunur.
	d := mk()
	d.EventID = "evt_sabit"
	if d.EnsureID() != "evt_sabit" {
		t.Error("mevcut kimlik korunmalı")
	}
}

func TestNewCorrelationIDUnique(t *testing.T) {
	a, b := NewCorrelationID(), NewCorrelationID()
	if a == b {
		t.Error("korelasyon kimlikleri benzersiz olmalı")
	}
	if !strings.HasPrefix(a, "cor_") {
		t.Errorf("korelasyon kimliği cor_ ile başlamalı: %q", a)
	}
}
