// Package persistence, kalıcılık (autostart) noktalarını izler: Windows Run
// anahtarları + zamanlanmış görevler, Linux cron + etkin systemd servisleri. Yeni
// eklenen girdiler PERSISTENCE_CHANGE (POLICY_VIOLATION) olayı olarak bildirilir —
// MITRE TA0003 (Persistence) tespiti; enforce (süreç) ve netconn (bağlantı)
// telemetrisinin kör noktasını kapatır (kötü amaçlı yazılım yeniden başlatmayı
// nasıl atlatıyor?).
//
// OS sorguları exec ile yapılır (platform dosyaları); ayrıştırma ve fark mantığı
// platform-bağımsız ve test edilebilir tutulur (usbmon/netconn deseni).
package persistence

import (
	"sort"
	"strings"
)

// Kind, bir kalıcılık girdisinin türüdür.
type Kind string

const (
	RunKey        Kind = "run_key"        // Windows HKLM/HKCU ...\Run
	ScheduledTask Kind = "scheduled_task" // Windows schtasks
	Cron          Kind = "cron"           // Linux cron
	SystemdUnit   Kind = "systemd_unit"   // Linux etkin systemd servisi
)

// Entry, tek bir autostart girdisidir.
type Entry struct {
	Kind  Kind
	Name  string // girdi adı (değer adı / görev adı / birim adı)
	Value string // komut/hedef (varsa)
}

// Key, tekilleştirme anahtarıdır (yeni-girdi takibi için).
func (e Entry) Key() string { return string(e.Kind) + "|" + e.Name + "|" + e.Value }

// Scanner, OS-özel autostart numaralandırması sağlar.
type Scanner interface {
	Scan() []Entry
}

// Scan, mevcut platformun kalıcılık girdilerini döner.
func Scan() []Entry { return NewScanner().Scan() }

// parseRunKeys, `reg query` çıktısını ayrıştırır. Satırlar:
//
//	ValueName    REG_SZ    C:\path\to.exe
//
// (girinti + REG_* tipi). Başlık/boş satırlar atlanır.
func parseRunKeys(out string) []Entry {
	var es []Entry
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "HKEY_") {
			continue
		}
		// REG_* tipini ayırıcı olarak kullan.
		var typIdx int = -1
		for _, rt := range []string{"REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ", "REG_DWORD", "REG_BINARY"} {
			if i := strings.Index(line, rt); i >= 0 {
				typIdx = i + len(rt)
				break
			}
		}
		if typIdx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:strings.Index(line, "REG_")])
		val := strings.TrimSpace(line[typIdx:])
		if name != "" {
			es = append(es, Entry{Kind: RunKey, Name: name, Value: val})
		}
	}
	return es
}

// parseSchtasks, `schtasks /query /fo csv /nh` çıktısındaki görev adlarını (ilk
// sütun, tırnaklı) ayrıştırır. "\Microsoft\" ile başlayan yerleşik görevler atlanır
// (gürültü azaltma; kötü amaçlı kalıcılık genelde kök/özel yolda).
func parseSchtasks(out string) []Entry {
	var es []Entry
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		name := line
		if i := strings.IndexByte(line, ','); i >= 0 {
			name = line[:i]
		}
		name = strings.Trim(name, "\"")
		if name == "" || strings.HasPrefix(name, `\Microsoft\`) || seen[name] {
			continue
		}
		seen[name] = true
		es = append(es, Entry{Kind: ScheduledTask, Name: name})
	}
	return es
}

// parseCron, cron dosyası/çıktısı satırlarını ayrıştırır. Yorum (#) ve boş satırlar
// atlanır; kalanlar ham komut satırı olarak alınır.
func parseCron(out string) []Entry {
	var es []Entry
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		es = append(es, Entry{Kind: Cron, Name: t})
	}
	return es
}

// Tracker, kalıcılık taban çizgisini tutar ve YENİ girdileri raporlar.
type Tracker struct {
	seen      map[string]Entry
	baselined bool
}

// Diff, mevcut taramayı taban çizgisiyle karşılaştırır ve YALNIZ yeni eklenen
// girdileri (deterministik, anahtara göre sıralı) döner. İlk çağrı taban çizgisidir.
// (Silmeler kalıcılık tehdidi olmadığından raporlanmaz.)
func (t *Tracker) Diff(current []Entry) []Entry {
	live := make(map[string]Entry, len(current))
	for _, e := range current {
		live[e.Key()] = e
	}
	if !t.baselined {
		t.seen = live
		t.baselined = true
		return nil
	}
	var added []Entry
	for k, e := range live {
		if _, ok := t.seen[k]; !ok {
			added = append(added, e)
		}
	}
	t.seen = live
	sort.Slice(added, func(i, j int) bool { return added[i].Key() < added[j].Key() })
	return added
}
