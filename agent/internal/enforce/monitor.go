// Package enforce, politika uygulamasını (enforcement) yürütür: çalışan
// süreçleri listeler, politika motoruyla değerlendirir, yasaklı olanları
// sonlandırır ve POLICY_VIOLATION olayı üretir.
//
// Süreç listeleme/sonlandırma OS'e özgüdür ve ProcessController arayüzünün
// arkasındadır (Windows implementasyonu controller_windows.go). Buradaki Monitor
// mantığı platformdan bağımsızdır ve sahte controller ile test edilebilir.
package enforce

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"xems.corp/suite/agent/internal/agentclock"
	"xems.corp/suite/agent/internal/anomaly"
	"xems.corp/suite/agent/internal/collector"
	"xems.corp/suite/agent/internal/policy"
)

// Process, çalışan bir süreçtir.
type Process struct {
	PID  uint32
	PPID uint32 // ebeveyn süreç kimliği (süreç soyağacı zenginleştirmesi)
	Name string
	Path string
}

// ProcessController, OS'e özgü süreç listeleme ve sonlandırma sağlar.
type ProcessController interface {
	List() ([]Process, error)
	Kill(pid uint32) error
}

// Monitor, tek bir değerlendirme turunu yürütür. Motor ajan tarafında sıcak
// değiştirildiğinden, geçerli motor her turda Tick'e verilir.
type Monitor struct {
	ctrl     ProcessController
	clock    *agentclock.Clock
	buf      *collector.Buffer
	self     uint32 // ajanın kendi PID'i — asla sonlandırılmaz
	detector *anomaly.Detector
	flagged  map[uint32]bool // anomali bildirilen PID'ler (tur-arası tekrar bastırma)
	// Süreç-yürütme telemetrisi (EDR görünürlüğü): yeni süreçler PROCESS olayı
	// olarak yayınlanır. İlk turda taban çizgisi sessizce alınır (açılış selini
	// önlemek için); sonraki turlarda yalnız YENİ süreçler bildirilir.
	procTelemetry bool
	procBaselined bool
	procSeen      map[uint32]bool
}

// NewMonitor oluşturur.
func NewMonitor(ctrl ProcessController, clock *agentclock.Clock, buf *collector.Buffer, selfPID uint32) *Monitor {
	return &Monitor{ctrl: ctrl, clock: clock, buf: buf, self: selfPID, flagged: map[uint32]bool{}, procSeen: map[uint32]bool{}}
}

// SetAnomalyDetector, davranışsal anomali tespitini etkinleştirir. nil (varsayılan)
// ise anomali skorlama yapılmaz — enforce davranışı değişmez.
func (m *Monitor) SetAnomalyDetector(d *anomaly.Detector) { m.detector = d }

// SetProcessTelemetry, süreç-yürütme telemetrisini açar/kapatır (varsayılan kapalı;
// ajan main açar). Açıkken her turda yeni süreçler PROCESS/INFO olayı üretir.
func (m *Monitor) SetProcessTelemetry(on bool) { m.procTelemetry = on }

// emitProcessTelemetry, bir önceki tura göre YENİ süreçleri PROCESS olayı olarak
// yayınlar. İlk tur taban çizgisidir (yayın yok). Ölü PID'ler budanır (PID
// yeniden-kullanımı yeni süreç sayılır). Ajanın kendisi ve pid 0 atlanır.
func (m *Monitor) emitProcessTelemetry(procs []Process, now time.Time) {
	if !m.procTelemetry {
		return
	}
	live := make(map[uint32]bool, len(procs))
	for _, p := range procs {
		live[p.PID] = true
	}
	if !m.procBaselined {
		m.procSeen = live
		m.procBaselined = true
		return
	}
	for _, p := range procs {
		if p.PID == m.self || p.PID == 0 || m.procSeen[p.PID] {
			continue
		}
		det := map[string]any{"process": p.Name, "pid": int(p.PID), "ppid": int(p.PPID)}
		if p.Path != "" {
			det["path"] = p.Path
		}
		addParentChain(det, procs, p.PID)
		m.emitCatDetails("PROCESS", "INFO", now,
			fmt.Sprintf("süreç başlatıldı: %s (pid=%d, ppid=%d)", p.Name, p.PID, p.PPID), det)
	}
	m.procSeen = live
}

// Tick, bir değerlendirme turu yürütür: süreçleri listeler, verilen motora göre
// yasaklıları tespit edip sonlandırır ve olay üretir. Sonlandırılan süreç
// sayısını döner.
func (m *Monitor) Tick(engine *policy.Engine) (int, error) {
	procs, err := m.ctrl.List()
	if err != nil {
		return 0, err
	}
	now, synced := m.clock.Now()

	// Süreç-yürütme telemetrisi (etkinse): yeni süreçleri yayınla.
	m.emitProcessTelemetry(procs, now)

	enforced := 0
	for _, p := range procs {
		if p.PID == m.self || p.PID == 0 {
			continue // ajanın kendisini ve sistem boşta sürecini atla
		}

		// Davranışsal anomali skorlama (etkinse): tüm süreçler modele beslenir;
		// eşiği aşan ve daha önce bildirilmemiş bir süreç için SECURITY olayı üret.
		if m.detector != nil {
			res := m.detector.Observe(anomaly.ProcessObservation{
				Name: p.Name, Path: p.Path, Hour: now.Hour(),
			})
			if res.Anomalous && !m.flagged[p.PID] {
				m.flagged[p.PID] = true
				sev := "MEDIUM"
				if res.Score >= 0.9 {
					sev = "HIGH"
				}
				det := map[string]any{"process": p.Name, "pid": int(p.PID), "score": res.Score}
				addParentChain(det, procs, p.PID)
				m.emitCatDetails("SECURITY", sev, now, fmt.Sprintf(
					"anomali: olağandışı süreç davranışı: %s (pid=%d, skor=%.2f)", p.Name, p.PID, res.Score), det)
			}
		}

		target := p.Path
		if target == "" {
			target = p.Name
		}

		var dec policy.Decision
		if synced {
			dec = engine.EvaluateProcess(target, now)
		} else {
			// Saat çıpası yoksa yalnız her-zaman-yasak kuralları uygulanır.
			dec = engine.EvaluateAlways(target)
		}
		if !dec.Blocked {
			continue
		}

		// Süreç-AĞACI sonlandırma: yasaklı süreci çocuklarıyla birlikte öldür (önce
		// alt süreçler → yeniden-ebeveynlenerek/çocuk-doğurarak kaçışı önle).
		kids := descendants(procs, p.PID)
		for _, k := range kids {
			_ = m.ctrl.Kill(k) // best-effort; ana hedef aşağıda
		}
		det := map[string]any{"process": p.Name, "pid": int(p.PID), "rule": dec.RuleID,
			"reason": dec.Reason, "killed_children": len(kids)}
		addParentChain(det, procs, p.PID)
		if err := m.ctrl.Kill(p.PID); err != nil {
			m.emitCatDetails("POLICY_VIOLATION", "CRITICAL", time.Now(),
				fmt.Sprintf("yasaklı süreç sonlandırılamadı: %s (pid=%d, kural=%s): %v", p.Name, p.PID, dec.RuleID, err),
				det)
			continue
		}
		suffix := ""
		if len(kids) > 0 {
			suffix = fmt.Sprintf(" (+%d alt süreç)", len(kids))
		}
		m.emitCatDetails("POLICY_VIOLATION", "HIGH", time.Now(),
			fmt.Sprintf("yasaklı süreç sonlandırıldı: %s (pid=%d, kural=%s, sebep=%s)%s", p.Name, p.PID, dec.RuleID, dec.Reason, suffix),
			det)
		enforced++
	}
	return enforced, nil
}

// parsePPIDStat, Linux /proc/<pid>/stat içeriğinden ebeveyn PID'ini (ppid) çıkarır.
// stat biçimi "pid (comm) state ppid ...". comm ')' ve boşluk içerebildiğinden
// ayrıştırma SON ')' sonrasından yapılır (kötü niyetli süreç adına karşı sağlam).
// Ayrıştırılamazsa 0 döner.
func parsePPIDStat(s string) uint32 {
	rp := strings.LastIndexByte(s, ')')
	if rp < 0 || rp+1 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[rp+1:]) // [state, ppid, pgrp, ...]
	if len(fields) < 2 {
		return 0
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil || ppid < 0 {
		return 0
	}
	return uint32(ppid)
}

// maxChainDepth, ebeveyn zinciri yürüyüşünün üst sınırıdır (döngü/aşırı derinlik
// koruması).
const maxChainDepth = 16

// parentChain, verilen PID'in ebeveyn süreç zincirini (yakın ebeveyn → kök) süreç
// adlarıyla döner. Döngü (görülen PID) ve derinlik sınırıyla güvenlidir. Ebeveyn
// bilinmiyorsa boş döner.
func parentChain(procs []Process, pid uint32) []string {
	byPID := make(map[uint32]Process, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}
	self, ok := byPID[pid]
	if !ok {
		return nil
	}
	var chain []string
	seen := map[uint32]bool{pid: true}
	cur := self.PPID
	for i := 0; i < maxChainDepth && cur != 0 && !seen[cur]; i++ {
		seen[cur] = true
		p, ok := byPID[cur]
		if !ok {
			break
		}
		name := p.Name
		if name == "" {
			name = fmt.Sprintf("pid-%d", cur)
		}
		chain = append(chain, name)
		cur = p.PPID
	}
	return chain
}

// descendants, verilen PID'in tüm alt süreçlerini (çocuk, torun…) döner. Süreç
// listesinden PPID ile ağaç kurulur; genişlik-öncelikli gezilir (döngü koruması).
// Süreç-ağacı sonlandırmada kullanılır (yasaklı süreci çocuklarıyla öldür).
func descendants(procs []Process, pid uint32) []uint32 {
	childrenOf := make(map[uint32][]uint32, len(procs))
	for _, p := range procs {
		if p.PPID != 0 {
			childrenOf[p.PPID] = append(childrenOf[p.PPID], p.PID)
		}
	}
	var out []uint32
	seen := map[uint32]bool{pid: true}
	queue := []uint32{pid}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, c := range childrenOf[cur] {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
				queue = append(queue, c)
			}
		}
	}
	return out
}

// addParentChain, ebeveyn zincirini (varsa) Details'e "parent_chain" olarak ekler.
func addParentChain(det map[string]any, procs []Process, pid uint32) {
	if chain := parentChain(procs, pid); len(chain) > 0 {
		anyChain := make([]any, len(chain))
		for i, s := range chain {
			anyChain[i] = s
		}
		det["parent_chain"] = anyChain
	}
}

func (m *Monitor) emit(severity, message string) {
	m.emitCat("POLICY_VIOLATION", severity, time.Now(), message)
}

func (m *Monitor) emitCat(category, severity string, at time.Time, message string) {
	m.emitCatDetails(category, severity, at, message, nil)
}

// emitCatDetails, yapısal ek veriyle (süreç/pid/kural…) olay üretir. Details,
// konsol olay-detay panelinde gösterilir ve sunucuda saklanır.
func (m *Monitor) emitCatDetails(category, severity string, at time.Time, message string, details map[string]any) {
	m.buf.Add(collector.Event{
		Category:   category,
		Severity:   severity,
		Message:    message,
		OccurredAt: at,
		Details:    details,
	})
}
