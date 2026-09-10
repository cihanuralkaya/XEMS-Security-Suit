package enforce

import (
	"errors"
	"strings"
	"testing"
	"time"

	"xems.corp/suite/agent/internal/agentclock"
	"xems.corp/suite/agent/internal/anomaly"
	"xems.corp/suite/agent/internal/collector"
	"xems.corp/suite/agent/internal/policy"
)

func TestMonitorEmitsAnomalyEvent(t *testing.T) {
	// Önceden eğitilmiş detektör: normal mesai-saati taban çizgisi.
	det := anomaly.NewDetector(0.7, nil)
	for i := 0; i < 18; i++ {
		det.Observe(anomaly.ProcessObservation{Name: "chrome.exe", Path: `C:\pf\chrome.exe`, Hour: 13 + i%3})
	}

	ctrl := &fakeCtrl{procs: []Process{{PID: 500, Name: "mimikatz.exe", Path: `C:\Temp\mimikatz.exe`}}}
	buf := collector.NewBuffer(100)
	threeAM := time.Date(2026, 8, 28, 3, 0, 0, 0, time.UTC) // gece yarısı, taban çizgisi dışı
	mon := NewMonitor(ctrl, fixedClock(threeAM), buf, 42)
	mon.SetAnomalyDetector(det)

	// Kural yok → sonlandırma yok; yalnız anomali skorlama çalışmalı.
	if _, err := mon.Tick(policy.New(policy.Bundle{})); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range buf.Pending(10) {
		if e.Category == "SECURITY" && strings.Contains(e.Message, "anomali") {
			found = true
		}
	}
	if !found {
		t.Fatal("aykırı süreç için SECURITY 'anomali' olayı beklenirdi")
	}

	// Detektör ayarlanmamışsa (geriye uyumlu) anomali olayı üretilmemeli.
	buf2 := collector.NewBuffer(100)
	mon2 := NewMonitor(ctrl, fixedClock(threeAM), buf2, 42)
	if _, err := mon2.Tick(policy.New(policy.Bundle{})); err != nil {
		t.Fatal(err)
	}
	if buf2.Len() != 0 {
		t.Fatalf("detektörsüz anomali olayı olmamalıydı, %d olay", buf2.Len())
	}
}

// fakeCtrl, gerçek OS'a dokunmadan controller'ı taklit eder.
type fakeCtrl struct {
	procs   []Process
	killed  []uint32
	failPID uint32
}

func (f *fakeCtrl) List() ([]Process, error) { return f.procs, nil }
func (f *fakeCtrl) Kill(pid uint32) error {
	if pid == f.failPID {
		return errors.New("erişim reddedildi")
	}
	f.killed = append(f.killed, pid)
	return nil
}

func weekdays(ds ...time.Weekday) [7]bool {
	var a [7]bool
	for _, d := range ds {
		a[int(d)] = true
	}
	return a
}

// fixedClock, Now() daima verilen sunucu zamanını döndürecek şekilde senkronize
// bir saat üretir (yerel kaynak sabit).
func fixedClock(server time.Time) *agentclock.Clock {
	c := agentclock.New(func() time.Time { return server })
	c.Sync(server)
	return c
}

func TestEnforceAlwaysBlock(t *testing.T) {
	ctrl := &fakeCtrl{procs: []Process{
		{PID: 100, PPID: 200, Name: "torrent.exe", Path: "D:\\x\\torrent.exe"},
		{PID: 200, Name: "notepad.exe"},
		{PID: 42, Name: "agent.exe"}, // self — asla öldürülmemeli
	}}
	buf := collector.NewBuffer(100)
	mon := NewMonitor(ctrl, fixedClock(time.Now()), buf, 42)
	engine := policy.New(policy.Bundle{Rules: []policy.Rule{
		{ID: "b1", Type: policy.RuleAppBlockAlways, Target: "torrent.exe"},
	}})

	n, err := mon.Tick(engine)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || len(ctrl.killed) != 1 || ctrl.killed[0] != 100 {
		t.Fatalf("yalnız torrent.exe(100) sonlandırılmalıydı, killed=%v n=%d", ctrl.killed, n)
	}
	if buf.Len() != 1 {
		t.Fatalf("1 POLICY_VIOLATION olayı beklenirdi, %d", buf.Len())
	}
	// Olay yapısal Details taşımalı (konsol detay paneli + sunucu saklama).
	ev := buf.Pending(1)[0]
	if ev.Details == nil || ev.Details["process"] != "torrent.exe" ||
		ev.Details["pid"] != 100 || ev.Details["rule"] != "b1" {
		t.Fatalf("olay Details {process,pid,rule} taşımalıydı: %+v", ev.Details)
	}
	// Ebeveyn zinciri de iliştirilmeli (torrent'in ebeveyni notepad).
	chain, _ := ev.Details["parent_chain"].([]any)
	if len(chain) != 1 || chain[0] != "notepad.exe" {
		t.Fatalf("parent_chain [notepad.exe] olmalıydı: %+v", ev.Details["parent_chain"])
	}
}

func TestEnforceAuditOnlyDoesNotKill(t *testing.T) {
	// Denetim modu: yasaklı süreç TESPİT edilir + olay üretilir ama ÖLDÜRÜLMEZ.
	ctrl := &fakeCtrl{procs: []Process{
		{PID: 100, PPID: 5, Name: "torrent.exe"},
		{PID: 200, PPID: 100, Name: "torrent-helper.exe"},
		{PID: 42, Name: "agent.exe"},
	}}
	buf := collector.NewBuffer(10)
	mon := NewMonitor(ctrl, fixedClock(time.Now()), buf, 42)
	mon.SetAuditOnly(true)
	engine := policy.New(policy.Bundle{Rules: []policy.Rule{
		{ID: "b1", Type: policy.RuleAppBlockAlways, Target: "torrent.exe"},
	}})

	n, err := mon.Tick(engine)
	if err != nil {
		t.Fatal(err)
	}
	// Hiçbir süreç öldürülmemeli.
	if len(ctrl.killed) != 0 {
		t.Fatalf("denetim modunda hiçbir süreç öldürülmemeli, killed=%v", ctrl.killed)
	}
	// Yine de eşleşen süreç sayılır ve olay üretilir.
	if n != 1 || buf.Len() != 1 {
		t.Fatalf("1 eşleşme + 1 olay beklenirdi, n=%d olay=%d", n, buf.Len())
	}
	ev := buf.Pending(1)[0]
	if ev.Severity != "MEDIUM" || ev.Details["audit_only"] != true {
		t.Fatalf("olay MEDIUM + audit_only:true taşımalı: sev=%s det=%+v", ev.Severity, ev.Details)
	}
	if ev.Details["would_kill_children"] != 1 {
		t.Fatalf("would_kill_children=1 beklenirdi: %+v", ev.Details)
	}
	if !strings.Contains(ev.Message, "DENETİM MODU") {
		t.Fatalf("mesaj denetim modunu belirtmeli: %q", ev.Message)
	}
}

func TestParsePPIDStat(t *testing.T) {
	// Normal.
	if got := parsePPIDStat("100 (bash) S 42 100 100 0 -1 4194304"); got != 42 {
		t.Fatalf("ppid 42 beklenirdi, %d", got)
	}
	// comm ')' ve boşluk içeriyor (kötü niyetli süreç adı) → son ')' esas alınır.
	if got := parsePPIDStat("7 (weird ) name) S 3 7 7"); got != 3 {
		t.Fatalf("parantezli comm'de ppid 3 beklenirdi, %d", got)
	}
	// Bozuk girdi → 0.
	if got := parsePPIDStat("bozuk"); got != 0 {
		t.Fatalf("bozuk girdi 0 dönmeliydi, %d", got)
	}
}

func TestDescendants(t *testing.T) {
	// bad(100) → child(200) → grandchild(300); ayrıca ilgisiz(400).
	procs := []Process{
		{PID: 100, PPID: 10, Name: "bad.exe"},
		{PID: 200, PPID: 100, Name: "child.exe"},
		{PID: 300, PPID: 200, Name: "grandchild.exe"},
		{PID: 400, PPID: 10, Name: "other.exe"},
	}
	got := descendants(procs, 100)
	set := map[uint32]bool{}
	for _, p := range got {
		set[p] = true
	}
	if len(got) != 2 || !set[200] || !set[300] {
		t.Fatalf("torunlar {200,300} beklenirdi: %v", got)
	}
	// Yaprak süreç → boş.
	if d := descendants(procs, 300); len(d) != 0 {
		t.Fatalf("yaprak süreç boş dönmeliydi: %v", d)
	}
	// Döngü koruması (a↔b).
	cyc := []Process{{PID: 1, PPID: 2}, {PID: 2, PPID: 1}}
	if d := descendants(cyc, 1); len(d) > 1 {
		t.Fatalf("döngü sınırlanmalıydı: %v", d)
	}
}

func TestKillTreeTerminatesChildren(t *testing.T) {
	// torrent(100) → helper(200); torrent yasaklı → ikisi de öldürülmeli.
	ctrl := &fakeCtrl{procs: []Process{
		{PID: 100, PPID: 5, Name: "torrent.exe"},
		{PID: 200, PPID: 100, Name: "torrent-helper.exe"},
		{PID: 42, Name: "agent.exe"},
	}}
	buf := collector.NewBuffer(10)
	mon := NewMonitor(ctrl, fixedClock(time.Now()), buf, 42)
	engine := policy.New(policy.Bundle{Rules: []policy.Rule{
		{ID: "b1", Type: policy.RuleAppBlockAlways, Target: "torrent.exe"},
	}})
	if _, err := mon.Tick(engine); err != nil {
		t.Fatal(err)
	}
	killed := map[uint32]bool{}
	for _, k := range ctrl.killed {
		killed[k] = true
	}
	if !killed[100] || !killed[200] {
		t.Fatalf("ana süreç + alt süreç öldürülmeliydi: %v", ctrl.killed)
	}
	// Olay Details killed_children sayısını taşımalı.
	ev := buf.Pending(1)[0]
	if ev.Details["killed_children"] != 1 {
		t.Fatalf("killed_children=1 beklenirdi: %+v", ev.Details)
	}
}

func TestParentChain(t *testing.T) {
	// explorer(10) → cmd(20) → torrent(100)
	procs := []Process{
		{PID: 10, PPID: 4, Name: "explorer.exe"},
		{PID: 20, PPID: 10, Name: "cmd.exe"},
		{PID: 100, PPID: 20, Name: "torrent.exe"},
		{PID: 4, PPID: 0, Name: "System"},
	}
	got := parentChain(procs, 100)
	want := []string{"cmd.exe", "explorer.exe", "System"}
	if len(got) != len(want) {
		t.Fatalf("zincir uzunluğu yanlış: %v (beklenen %v)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("zincir[%d]=%s beklenen %s (%v)", i, got[i], want[i], got)
		}
	}
	// Bilinmeyen PID → boş.
	if c := parentChain(procs, 999); c != nil {
		t.Fatalf("bilinmeyen PID boş dönmeliydi: %v", c)
	}
	// Döngü koruması: a↔b birbirini ebeveyn gösterir → sonsuz döngü yok.
	cyc := []Process{{PID: 1, PPID: 2, Name: "a"}, {PID: 2, PPID: 1, Name: "b"}}
	if c := parentChain(cyc, 1); len(c) > 2 {
		t.Fatalf("döngü sınırlanmalıydı: %v", c)
	}
}

func TestEnforceTimeBlockWhenSynced(t *testing.T) {
	// Cuma 20:00 — mesai-dışı game.exe yasağı aktif.
	fri2000 := time.Date(2026, 8, 28, 20, 0, 0, 0, time.UTC)
	start, _ := policy.ParseHHMM("18:00")
	end, _ := policy.ParseHHMM("08:00")
	engine := policy.New(policy.Bundle{Rules: []policy.Rule{
		{ID: "t1", Type: policy.RuleAppTimeBlock, Target: "game.exe",
			Start: start, End: end, ActiveDays: weekdays(time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday)},
	}})
	ctrl := &fakeCtrl{procs: []Process{{PID: 7, Name: "game.exe"}}}
	buf := collector.NewBuffer(100)
	mon := NewMonitor(ctrl, fixedClock(fri2000), buf, 1)

	n, _ := mon.Tick(engine)
	if n != 1 || len(ctrl.killed) != 1 || ctrl.killed[0] != 7 {
		t.Fatalf("mesai-dışı game.exe sonlandırılmalıydı, killed=%v", ctrl.killed)
	}
}

func TestNoTimeEnforceWhenClockUnsynced(t *testing.T) {
	// Senkronize edilmemiş saat: zaman-bloğu uygulanmamalı, ama her-zaman-yasak uygulanmalı.
	start, _ := policy.ParseHHMM("18:00")
	end, _ := policy.ParseHHMM("08:00")
	engine := policy.New(policy.Bundle{Rules: []policy.Rule{
		{ID: "t1", Type: policy.RuleAppTimeBlock, Target: "game.exe",
			Start: start, End: end, ActiveDays: weekdays(time.Friday)},
		{ID: "b1", Type: policy.RuleAppBlockAlways, Target: "malware.exe"},
	}})
	ctrl := &fakeCtrl{procs: []Process{
		{PID: 7, Name: "game.exe"},
		{PID: 9, Name: "malware.exe"},
	}}
	buf := collector.NewBuffer(100)
	unsynced := agentclock.New(time.Now) // Sync çağrılmadı
	mon := NewMonitor(ctrl, unsynced, buf, 1)

	n, _ := mon.Tick(engine)
	// game.exe (zaman-bloğu) DOKUNULMAMALI; malware.exe (her-zaman) sonlandırılmalı.
	if n != 1 || len(ctrl.killed) != 1 || ctrl.killed[0] != 9 {
		t.Fatalf("saat senkronsuzken yalnız her-zaman-yasak uygulanmalıydı, killed=%v", ctrl.killed)
	}
}

func TestKillFailureEmitsCriticalEvent(t *testing.T) {
	ctrl := &fakeCtrl{
		procs:   []Process{{PID: 100, Name: "torrent.exe"}},
		failPID: 100,
	}
	buf := collector.NewBuffer(100)
	mon := NewMonitor(ctrl, fixedClock(time.Now()), buf, 1)
	engine := policy.New(policy.Bundle{Rules: []policy.Rule{
		{ID: "b1", Type: policy.RuleAppBlockAlways, Target: "torrent.exe"},
	}})

	n, _ := mon.Tick(engine)
	if n != 0 {
		t.Fatalf("sonlandırma başarısızsa enforced=0 olmalı, %d", n)
	}
	if buf.Len() != 1 {
		t.Fatalf("başarısızlık için 1 olay üretilmeliydi, %d", buf.Len())
	}
	ev := buf.Pending(1)[0]
	if ev.Severity != "CRITICAL" {
		t.Errorf("başarısız sonlandırma CRITICAL olmalı, %s", ev.Severity)
	}
}

// Süreç-yürütme telemetrisi: ilk tur taban çizgisi (yayın yok); sonraki turda
// YENİ süreçler PROCESS/INFO olayı üretir; mevcut süreçler tekrar bildirilmez.
func TestProcessTelemetryEmitsNewProcesses(t *testing.T) {
	ctrl := &fakeCtrl{procs: []Process{
		{PID: 100, Name: "init"},
		{PID: 200, Name: "bash"},
		{PID: 42, Name: "agent.exe"}, // self — telemetride atlanmalı
	}}
	buf := collector.NewBuffer(100)
	mon := NewMonitor(ctrl, fixedClock(time.Now()), buf, 42)
	mon.SetProcessTelemetry(true)
	engine := policy.New(policy.Bundle{}) // boş: engelleme yok

	countProc := func() int {
		n := 0
		for _, e := range buf.Pending(100) {
			if e.Category == "PROCESS" {
				n++
			}
		}
		return n
	}

	// 1. tur: taban çizgisi — PROCESS olayı olmamalı.
	if _, err := mon.Tick(engine); err != nil {
		t.Fatal(err)
	}
	if countProc() != 0 {
		t.Fatalf("taban çizgisi turunda PROCESS olayı olmamalı, %d", countProc())
	}

	// Yeni bir süreç belirir.
	ctrl.procs = append(ctrl.procs, Process{PID: 300, Name: "evil.exe", PPID: 200, Path: `C:\tmp\evil.exe`})
	if _, err := mon.Tick(engine); err != nil {
		t.Fatal(err)
	}
	procEvents := 0
	var last collector.Event
	for _, e := range buf.Pending(100) {
		if e.Category == "PROCESS" {
			procEvents++
			last = e
		}
	}
	if procEvents != 1 {
		t.Fatalf("yalnız 1 yeni süreç (evil.exe) bildirilmeliydi, %d", procEvents)
	}
	if last.Severity != "INFO" || last.Details["pid"] != 300 || last.Details["process"] != "evil.exe" {
		t.Fatalf("PROCESS olayı ayrıntıları hatalı: sev=%s det=%v", last.Severity, last.Details)
	}
	if last.Details["path"] != `C:\tmp\evil.exe` {
		t.Fatalf("path ayrıntısı eksik: %v", last.Details["path"])
	}

	// 3. tur: değişiklik yok → yeni PROCESS olayı olmamalı (300 artık biliniyor).
	before := countProc()
	if _, err := mon.Tick(engine); err != nil {
		t.Fatal(err)
	}
	if countProc() != before {
		t.Fatalf("değişiklik yokken yeni PROCESS olayı üretilmemeli (%d → %d)", before, countProc())
	}
}
