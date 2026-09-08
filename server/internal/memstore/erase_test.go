package memstore

import (
	"context"
	"testing"
	"time"

	"xems.corp/suite/server/internal/enroll"
	"xems.corp/suite/server/internal/model"
)

// EraseDeviceData: cihazın olay + komut verisini siler, sertifikalarını iptal
// eder; BAŞKA cihazların verisine dokunmaz; denetim izi (bu katmanda yok) korunur.
func TestEraseDeviceDataRemovesBehavioralDataOnly(t *testing.T) {
	ctx := context.Background()
	s := New()
	d1 := enrollDevice(t, s)
	// İkinci cihaz (dokunulmamalı).
	d2, err := s.UpsertEnrollingDevice(ctx, enroll.DeviceEnrollment{MACBlindIndex: []byte("mac-other")})
	if err != nil {
		t.Fatal(err)
	}

	// d1 için olay + komut + sertifika; d2 için de olay.
	if _, err := s.SaveEvents(ctx, d1, []model.Event{
		{Sequence: 1, Category: "SECURITY", Severity: "HIGH", Message: "a", OccurredAt: time.Now()},
		{Sequence: 2, Category: "SYSTEM", Severity: "INFO", Message: "b", OccurredAt: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveEvents(ctx, d2, []model.Event{
		{Sequence: 1, Category: "SYSTEM", Severity: "INFO", Message: "c", OccurredAt: time.Now()},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnqueueCommand(ctx, d1, "COLLECT_DIAGNOSTICS", "admin1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveCertificate(ctx, enroll.CertRecord{
		DeviceID: d1, Serial: "42", Fingerprint: []byte("fp"),
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	ev, cmd, cert, err := s.EraseDeviceData(ctx, d1)
	if err != nil {
		t.Fatal(err)
	}
	if ev != 2 || cmd != 1 || cert != 1 {
		t.Fatalf("silme sayımları hatalı: olay=%d komut=%d cert=%d (2/1/1 beklenirdi)", ev, cmd, cert)
	}

	// d1 olayları gitmiş, d2 olayları durmalı.
	d1ev, _ := s.ListEvents(ctx, d1, "", "", 0)
	d2ev, _ := s.ListEvents(ctx, d2, "", "", 0)
	if len(d1ev) != 0 {
		t.Fatalf("d1 olayları silinmeliydi, kalan: %d", len(d1ev))
	}
	if len(d2ev) != 1 {
		t.Fatalf("d2 olaylarına dokunulmamalıydı, kalan: %d", len(d2ev))
	}

	// d1 sertifikaları iptal edilmiş olmalı (revocation tombstone kalır).
	certs, _ := s.CertsByDevice(ctx, d1)
	if len(certs) != 1 || !certs[0].Revoked {
		t.Fatalf("d1 sertifikası iptal (revoked) edilmeliydi: %+v", certs)
	}

	// İkinci silme çağrısı sıfır sayımla dönmeli (idempotent).
	ev2, cmd2, cert2, _ := s.EraseDeviceData(ctx, d1)
	if ev2 != 0 || cmd2 != 0 || cert2 != 0 {
		t.Fatalf("ikinci silme sıfır dönmeliydi: %d/%d/%d", ev2, cmd2, cert2)
	}
}
