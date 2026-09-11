package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// fixedClock, deterministik testler için artan zaman üreten bir saat döner:
// her çağrıda base + n*step (n çağrı sayısı).
func fixedClock(base time.Time, step time.Duration) func() time.Time {
	n := 0
	return func() time.Time {
		t := base.Add(time.Duration(n) * step)
		n++
		return t
	}
}

var testBase = time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)

func TestNewEvidenceComputesHashAndGenesis(t *testing.T) {
	content := []byte("zararlı-örnek-içerik")
	sum := sha256.Sum256(content)
	wantHash := hex.EncodeToString(sum[:])

	clock := fixedClock(testBase, time.Minute)
	e := NewEvidence("ev-1", "dev-9", "analyst-a", "live-collect", "evt-42", content, clock)

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"id", e.ID, "ev-1"},
		{"sha256", e.SHA256, wantHash},
		{"size", e.Size, int64(len(content))},
		{"device_id", e.DeviceID, "dev-9"},
		{"collector", e.Collector, "analyst-a"},
		{"method", e.AcquisitionMethod, "live-collect"},
		{"event_ref", e.EventRef, "evt-42"},
		{"custody_len", len(e.Custody), 1},
		{"genesis_action", e.Custody[0].Action, ActionCollected},
		{"genesis_actor", e.Custody[0].Actor, "analyst-a"},
		{"genesis_seq", e.Custody[0].Seq, 0},
		{"genesis_prev", e.Custody[0].PrevHash, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %v, beklenen %v", tt.name, tt.got, tt.want)
			}
		})
	}

	if e.CollectedAt != testBase {
		t.Fatalf("CollectedAt = %v, beklenen %v", e.CollectedAt, testBase)
	}
	if ok, at := e.Verify(); !ok {
		t.Fatalf("yeni delil zinciri sağlam olmalıydı, kırılma @%d", at)
	}
}

func TestNewEvidenceNilClock(t *testing.T) {
	// now nil iken panik olmamalı ve zincir sağlam olmalı.
	e := NewEvidence("ev-n", "dev", "c", "disk-image", "evt", []byte("x"), nil)
	if ok, at := e.Verify(); !ok {
		t.Fatalf("nil saat ile zincir sağlam olmalıydı, kırılma @%d", at)
	}
	if e.CollectedAt.IsZero() {
		t.Fatal("CollectedAt ayarlanmalıydı")
	}
}

func TestAppendAndConvenienceBuildValidChain(t *testing.T) {
	clock := fixedClock(testBase, time.Minute)
	e := NewEvidence("ev-2", "dev", "collector-1", "live-collect", "evt", []byte("payload"), clock)

	e.RecordAccess("analyst-b", clock)
	e.RecordTransfer("courier-1", clock)
	e.Seal("custodian-1", clock)

	wantActions := []string{ActionCollected, ActionAccessed, ActionTransferred, ActionSealed}
	if len(e.Custody) != len(wantActions) {
		t.Fatalf("custody uzunluğu = %d, beklenen %d", len(e.Custody), len(wantActions))
	}
	for i, c := range e.Custody {
		if c.Action != wantActions[i] {
			t.Errorf("kayıt[%d] action = %q, beklenen %q", i, c.Action, wantActions[i])
		}
		if c.Seq != i {
			t.Errorf("kayıt[%d] seq = %d, beklenen %d", i, c.Seq, i)
		}
		if i == 0 && c.PrevHash != "" {
			t.Errorf("genesis PrevHash boş olmalı, %q bulundu", c.PrevHash)
		}
		if i > 0 && c.PrevHash != e.Custody[i-1].Hash {
			t.Errorf("kayıt[%d] PrevHash önceki Hash'e bağlı değil", i)
		}
		if !ValidAction(c.Action) {
			t.Errorf("kayıt[%d] geçersiz eylem %q", i, c.Action)
		}
	}
	if ok, at := e.Verify(); !ok {
		t.Fatalf("oluşturulan zincir sağlam olmalıydı, kırılma @%d", at)
	}
}

func TestVerifyDetectsMiddleTampering(t *testing.T) {
	clock := fixedClock(testBase, time.Minute)
	e := NewEvidence("ev-3", "dev", "c", "live-collect", "evt", []byte("data"), clock)
	e.RecordAccess("a1", clock)   // seq 1
	e.RecordTransfer("a2", clock) // seq 2 (orta)
	e.RecordAccess("a3", clock)   // seq 3
	e.Seal("a4", clock)           // seq 4

	if ok, _ := e.Verify(); !ok {
		t.Fatal("kurcalama öncesi zincir sağlam olmalıydı")
	}

	// Ortadaki bir kaydın bir alanını değiştir (hash'i güncellemeden) → kurcalama.
	const brokenIdx = 2
	e.Custody[brokenIdx].Actor = "saldırgan"
	ok, at := e.Verify()
	if ok {
		t.Fatal("kurcalanmış orta kayıt için zincir kırılmalıydı")
	}
	if at != brokenIdx {
		t.Fatalf("kırılma indeksi = %d, beklenen %d", at, brokenIdx)
	}

	// Geri al → yine sağlam.
	e.Custody[brokenIdx].Actor = "a2"
	if ok, at := e.Verify(); !ok {
		t.Fatalf("geri alınınca zincir yine sağlam olmalıydı, kırılma @%d", at)
	}
}

func TestVerifyDetectsTamperVariants(t *testing.T) {
	build := func() *Evidence {
		clock := fixedClock(testBase, time.Minute)
		e := NewEvidence("ev-v", "dev", "c", "live-collect", "evt", []byte("d"), clock)
		e.RecordAccess("a1", clock)
		e.RecordTransfer("a2", clock)
		return &e
	}

	tests := []struct {
		name   string
		mutate func(e *Evidence)
		wantOK bool
		wantAt int
	}{
		{
			name:   "sağlam",
			mutate: func(e *Evidence) {},
			wantOK: true,
			wantAt: -1,
		},
		{
			name:   "action_degisti",
			mutate: func(e *Evidence) { e.Custody[1].Action = ActionSealed },
			wantOK: false,
			wantAt: 1,
		},
		{
			name:   "zaman_degisti",
			mutate: func(e *Evidence) { e.Custody[2].At = e.Custody[2].At.Add(time.Hour) },
			wantOK: false,
			wantAt: 2,
		},
		{
			name:   "hash_degisti",
			mutate: func(e *Evidence) { e.Custody[0].Hash = "deadbeef" },
			wantOK: false,
			wantAt: 0,
		},
		{
			name:   "prevhash_degisti",
			mutate: func(e *Evidence) { e.Custody[2].PrevHash = "00" },
			wantOK: false,
			wantAt: 2,
		},
		{
			name: "kayit_silindi", // araya silme → sonraki seq/prev bağı kırılır
			mutate: func(e *Evidence) {
				e.Custody = append(e.Custody[:1], e.Custody[2:]...)
			},
			wantOK: false,
			wantAt: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := build()
			tt.mutate(e)
			ok, at := e.Verify()
			if ok != tt.wantOK || at != tt.wantAt {
				t.Fatalf("Verify() = (%v, %d), beklenen (%v, %d)", ok, at, tt.wantOK, tt.wantAt)
			}
		})
	}
}

func TestVerifyContent(t *testing.T) {
	content := []byte("orijinal-delil-baytları")
	e := NewEvidence("ev-4", "dev", "c", "disk-image", "evt", content, fixedClock(testBase, time.Minute))

	tests := []struct {
		name    string
		content []byte
		want    bool
	}{
		{"eslesen", content, true},
		{"degistirilmis", []byte("orijinal-delil-baytlarX"), false},
		{"bos_uyumsuz", []byte{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.VerifyContent(tt.content); got != tt.want {
				t.Fatalf("VerifyContent = %v, beklenen %v", got, tt.want)
			}
		})
	}
}

func TestValidAction(t *testing.T) {
	tests := []struct {
		action string
		want   bool
	}{
		{ActionCollected, true},
		{ActionAccessed, true},
		{ActionTransferred, true},
		{ActionSealed, true},
		{"DELETED", false},
		{"", false},
		{"collected", false}, // büyük/küçük harf duyarlı
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			if got := ValidAction(tt.action); got != tt.want {
				t.Fatalf("ValidAction(%q) = %v, beklenen %v", tt.action, got, tt.want)
			}
		})
	}
}

func TestJSONRoundTrip(t *testing.T) {
	clock := fixedClock(testBase, time.Minute)
	e := NewEvidence("ev-5", "dev-1", "c", "live-collect", "evt", []byte("abc"), clock)
	e.RecordAccess("a1", clock)

	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// snake_case JSON etiketleri korunmalı.
	for _, key := range []string{`"sha256"`, `"device_id"`, `"acquisition_method"`, `"event_ref"`, `"collected_at"`, `"custody"`, `"prev_hash"`} {
		if !containsSub(string(raw), key) {
			t.Errorf("JSON %s etiketini içermeli: %s", key, raw)
		}
	}

	var back Evidence
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ok, at := back.Verify(); !ok {
		t.Fatalf("JSON turundan sonra zincir sağlam olmalıydı, kırılma @%d", at)
	}
	if back.SHA256 != e.SHA256 || back.Size != e.Size {
		t.Fatal("JSON turundan sonra alanlar korunmadı")
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
