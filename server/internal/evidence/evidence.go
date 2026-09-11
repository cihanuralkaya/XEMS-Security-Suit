// Package evidence, kurcalamaya-dayanıklı delil kayıtları ve ekle-yalnız (append-only),
// hash-zincirli bir gözetim-zinciri (chain of custody) izi sağlar (yol haritası §23).
//
// Tasarım, depodaki denetim izi (audit log) hash-zinciriyle aynı fikri yansıtır:
// her gözetim kaydı bir öncekinin hash'ini içerir; bu yüzden herhangi bir kaydın
// (silinmesi/değiştirilmesi) sonrası zincir kırılır ve Verify kırılmanın ilk
// konumunu bildirir. Ayrıca delil içeriği, kaydedilen SHA-256 özetiyle doğrulanabilir.
//
// Paket yalnızca standart kütüphaneye dayanır ve kendi kendine yeterlidir.
package evidence

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// Gözetim zincirinde izin verilen eylem türleri.
const (
	// ActionCollected, delilin ilk toplandığı genesis (başlangıç) kaydıdır.
	ActionCollected = "COLLECTED"
	// ActionAccessed, delile erişildiğini belgeler.
	ActionAccessed = "ACCESSED"
	// ActionTransferred, delilin bir aktörden diğerine devredildiğini belgeler.
	ActionTransferred = "TRANSFERRED"
	// ActionSealed, delilin mühürlendiğini (değiştirilemez hale getirildiğini) belgeler.
	ActionSealed = "SEALED"
)

// unitSep, alan sınırı ayracıdır (birleştirme belirsizliğini önler).
const unitSep = 0x1f

// ValidAction, verilen eylemin bilinen gözetim eylemlerinden biri olup olmadığını döner.
func ValidAction(action string) bool {
	switch action {
	case ActionCollected, ActionAccessed, ActionTransferred, ActionSealed:
		return true
	default:
		return false
	}
}

// CustodyEntry, gözetim zincirinde tek bir hash-bağlı kayıttır.
// Hash = SHA-256(kanonik(Seq, Actor, Action, At, EvidenceID, PrevHash)) (hex).
// İlk (genesis) kaydın PrevHash'i boştur ("").
type CustodyEntry struct {
	Seq      int       `json:"seq"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	At       time.Time `json:"at"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
}

// Evidence, kurcalamaya-dayanıklı bir delil kaydıdır: içeriğin SHA-256 özeti,
// toplama meta verileri ve ekle-yalnız bir gözetim zinciri (Custody) içerir.
type Evidence struct {
	ID                string         `json:"id"`
	SHA256            string         `json:"sha256"`
	Size              int64          `json:"size"`
	DeviceID          string         `json:"device_id"`
	Collector         string         `json:"collector"`
	AcquisitionMethod string         `json:"acquisition_method"`
	EventRef          string         `json:"event_ref"`
	CollectedAt       time.Time      `json:"collected_at"`
	Custody           []CustodyEntry `json:"custody"`
}

// NewEvidence, verilen içerikten SHA-256 özetini ve boyutunu hesaplayarak yeni bir
// delil kaydı üretir ve toplayıcı (collector) adına bir genesis COLLECTED gözetim
// kaydıyla zinciri başlatır. now enjekte edilerek deterministik testler sağlanır;
// nil ise time.Now kullanılır.
func NewEvidence(id, deviceID, collector, method, eventRef string, content []byte, now func() time.Time) Evidence {
	if now == nil {
		now = time.Now
	}
	sum := sha256.Sum256(content)
	at := now().UTC()
	e := Evidence{
		ID:                id,
		SHA256:            hex.EncodeToString(sum[:]),
		Size:              int64(len(content)),
		DeviceID:          deviceID,
		Collector:         collector,
		AcquisitionMethod: method,
		EventRef:          eventRef,
		CollectedAt:       at,
	}
	// Genesis kaydı: delili toplayan aktör, COLLECTED.
	e.appendEntry(collector, ActionCollected, at)
	return e
}

// custodyHash, bir gözetim kaydının kanonik hash'ini (hex SHA-256) hesaplar.
// Alanlar: Seq, Actor, Action, At (UnixNano), EvidenceID, PrevHash. EvidenceID
// dahil edilir; böylece kayıt belirli bir delile bağlanır ve kayıtlar delillerarası
// taşınamaz.
func custodyHash(seq int, actor, action string, atUnixNano int64, evidenceID, prevHash string) string {
	h := sha256.New()
	var num [8]byte
	binary.BigEndian.PutUint64(num[:], uint64(seq))
	h.Write(num[:])
	writeField(h, actor)
	writeField(h, action)
	binary.BigEndian.PutUint64(num[:], uint64(atUnixNano))
	h.Write(num[:])
	writeField(h, evidenceID)
	writeField(h, prevHash)
	return hex.EncodeToString(h.Sum(nil))
}

func writeField(h interface{ Write([]byte) (int, error) }, s string) {
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{unitSep})
}

// appendEntry, zincirin sonuna yeni bir hash-bağlı kayıt ekler (iç yardımcı).
func (e *Evidence) appendEntry(actor, action string, at time.Time) CustodyEntry {
	at = at.UTC()
	seq := len(e.Custody)
	prev := ""
	if seq > 0 {
		prev = e.Custody[seq-1].Hash
	}
	entry := CustodyEntry{
		Seq:      seq,
		Actor:    actor,
		Action:   action,
		At:       at,
		PrevHash: prev,
		Hash:     custodyHash(seq, actor, action, at.UnixNano(), e.ID, prev),
	}
	e.Custody = append(e.Custody, entry)
	return entry
}

// Append, zincire yeni bir hash-bağlı gözetim kaydı ekler ve eklenen kaydı döner.
// now enjekte edilerek deterministik testler sağlanır; nil ise time.Now kullanılır.
func (e *Evidence) Append(actor, action string, now func() time.Time) CustodyEntry {
	if now == nil {
		now = time.Now
	}
	return e.appendEntry(actor, action, now())
}

// RecordAccess, bir erişimi (ACCESSED) zincire kaydeden kolaylık yöntemidir.
func (e *Evidence) RecordAccess(actor string, now func() time.Time) CustodyEntry {
	return e.Append(actor, ActionAccessed, now)
}

// RecordTransfer, bir devri (TRANSFERRED) zincire kaydeden kolaylık yöntemidir.
func (e *Evidence) RecordTransfer(actor string, now func() time.Time) CustodyEntry {
	return e.Append(actor, ActionTransferred, now)
}

// Seal, delili mühürleyen (SEALED) kolaylık yöntemidir.
func (e *Evidence) Seal(actor string, now func() time.Time) CustodyEntry {
	return e.Append(actor, ActionSealed, now)
}

// Verify, gözetim zincirini baştan yeniden hesaplar ve bütünlüğünü doğrular.
// ok=true ise zincir sağlamdır ve brokenAt=-1'dir. Kurcalama varsa ok=false olur
// ve brokenAt, saklanan hash'in (ya da PrevHash/Seq bağının) yeniden hesaplananla
// uyuşmadığı ilk kaydın indeksidir.
func (e *Evidence) Verify() (ok bool, brokenAt int) {
	prev := ""
	for i, c := range e.Custody {
		if c.Seq != i || c.PrevHash != prev {
			return false, i
		}
		want := custodyHash(c.Seq, c.Actor, c.Action, c.At.UnixNano(), e.ID, prev)
		if want != c.Hash {
			return false, i
		}
		prev = c.Hash
	}
	return true, -1
}

// VerifyContent, verilen içeriğin SHA-256 özetinin, kaydedilen SHA256 ile eşleşip
// eşleşmediğini döner (delil içeriği bütünlüğü kontrolü).
func (e *Evidence) VerifyContent(content []byte) bool {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:]) == e.SHA256
}
