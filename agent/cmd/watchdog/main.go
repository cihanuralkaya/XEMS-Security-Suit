// Command watchdog, ajanı canlı tutan gözetmen süreçtir.
//
// Sorumluluk: ajanı bir alt süreç olarak çalıştırır, çökerse backoff'lu yeniden
// başlatır ve OTA staged güncellemesini (update.Prepare'in staging'e yazdığı)
// çalıştırmalar arasında swap eder; yeni sürüm deneme penceresinde çökerse
// rollback eder.
//
// NOT (inceleme #5): Bu, kaza sonucu sonlanmalara karşı ilk savunmadır; SYSTEM
// yetkili müdahaleye karşı gerçek koruma ayrı bir faz (sürücü + PPL/ELAM).
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"xems.corp/suite/agent/internal/liveness"
	"xems.corp/suite/agent/internal/standdown"
	"xems.corp/suite/agent/internal/watchdog"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[watchdog] ")

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	agentBin := getenv("XEMS_AGENT_BIN", defaultAgentBin())
	dataDir := getenv("XEMS_AGENT_DATA", "./agent-data")
	stageDir := filepath.Join(dataDir, "updates")

	// Kendi canlılık beacon'unu yaz (ajanın PeerGuard'ı bunu izler; watchdog
	// ölürse ajan onu yeniden başlatır — karşılıklı gözetim).
	wdBeacon := liveness.NewBeacon(filepath.Join(dataDir, "watchdog.beacon"))
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			_ = wdBeacon.Write(time.Now())
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()

	runner := watchdog.NewExecRunner(agentBin)
	swapper := watchdog.NewFileSwapper(agentBin, stageDir)
	sup := watchdog.NewSupervisor(runner, swapper, watchdog.Options{
		BaseBackoff: time.Second,
		MaxBackoff:  30 * time.Second,
		TrialWindow: 15 * time.Second,
		// İmzalı çevrimdışı offboard: ajan geçerli jetonu doğrulayıp stand-down
		// işaretini bıraktıysa gözetimi bırak (yeniden başlatma).
		StandDown: func() bool { return standdown.Exists(dataDir) },
		Log:       func(m string) { log.Println(m) },
	})

	log.Printf("ajan gözetleniyor: %s", agentBin)
	if err := sup.Run(ctx); err != nil && err != context.Canceled {
		log.Printf("gözetim durdu: %v", err)
	}
	log.Println("watchdog kapandı.")
}

func defaultAgentBin() string {
	if runtime.GOOS == "windows" {
		return "./agent.exe"
	}
	return "./agent"
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
