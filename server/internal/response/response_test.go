package response

import (
	"context"
	"errors"
	"testing"

	"xems.corp/suite/server/internal/model"
)

// fakeStore, response.Store'u kaydederek uygular.
type fakeStore struct {
	cmds    []string // "deviceID:cmdType:issuedBy"
	status  map[string]string
	audits  []string // "action:targetID"
	failCmd bool
}

func newFake() *fakeStore { return &fakeStore{status: map[string]string{}} }

func (f *fakeStore) EnqueueCommand(_ context.Context, deviceID, cmdType, issuedBy string) error {
	if f.failCmd {
		return errors.New("kuyruk hatası")
	}
	f.cmds = append(f.cmds, deviceID+":"+cmdType+":"+issuedBy)
	return nil
}
func (f *fakeStore) SetDeviceStatus(_ context.Context, deviceID, status string) error {
	f.status[deviceID] = status
	return nil
}
func (f *fakeStore) WriteAudit(_ context.Context, adminID, action, _, targetID string) error {
	f.audits = append(f.audits, action+":"+targetID)
	return nil
}

func TestShouldTrigger(t *testing.T) {
	if _, ok := ShouldTrigger([]model.Event{{Severity: "INFO"}, {Severity: "HIGH"}}); ok {
		t.Fatal("KRİTİK olmadan tetiklenmemeliydi")
	}
	reason, ok := ShouldTrigger([]model.Event{{Severity: "LOW"}, {Severity: "CRITICAL", Message: "watchdog kurcalama"}})
	if !ok || reason != "watchdog kurcalama" {
		t.Fatalf("kritik olayda tetiklenmeliydi (reason=%q ok=%v)", reason, ok)
	}
	if _, ok := ShouldTrigger(nil); ok {
		t.Fatal("boş grup tetiklememeli")
	}
}

func TestAutoQuarantineEnqueuesAndAudits(t *testing.T) {
	f := newFake()
	a := New(f)
	if err := a.AutoQuarantine(context.Background(), "dev-1", "kritik olay"); err != nil {
		t.Fatal(err)
	}
	if len(f.cmds) != 1 || f.cmds[0] != "dev-1:QUARANTINE:" {
		t.Fatalf("karantina komutu kuyruğa alınmalıydı: %v", f.cmds)
	}
	if f.status["dev-1"] != "QUARANTINED" {
		t.Fatalf("durum QUARANTINED olmalıydı: %v", f.status)
	}
	if len(f.audits) != 1 || f.audits[0] != "AUTO_QUARANTINE:dev-1" {
		t.Fatalf("denetim izine yazılmalıydı: %v", f.audits)
	}
}

func TestAutoQuarantineReturnsErrOnEnqueueFailure(t *testing.T) {
	f := newFake()
	f.failCmd = true
	if err := New(f).AutoQuarantine(context.Background(), "dev-1", "x"); err == nil {
		t.Fatal("komut kuyruğa alınamazsa hata dönmeliydi")
	}
}
