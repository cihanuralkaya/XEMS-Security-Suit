// Package mitre, üretilen güvenlik olaylarını MITRE ATT&CK tekniklerine eşler.
// Bu, olaylara taktik/teknik bağlamı ekler (SOC üçgenlemesi, kapsama raporu) ve
// dış bağımlılık gerektirmez — statik, denetlenebilir bir eşleme tablosudur.
//
// Eşleme, sistemin GERÇEKTE ürettiği olay kategorileri/mesajlarına dayanır
// (agent/internal/enforce, quarantine, cmd/agent, discovery). Bir tespitin
// "hangi düşman tekniğini gözlemlediğini" belirtir — kanonik savunma pratiği.
package mitre

import "strings"

// Technique, bir ATT&CK tekniğidir.
type Technique struct {
	ID     string `json:"id"`     // ör. "T1059"
	Name   string `json:"name"`   // ör. "Command and Scripting Interpreter"
	Tactic string `json:"tactic"` // ör. "Execution"
}

// Teknik sabitleri (kapsanan alt küme).
var (
	tExecutionScript = Technique{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution"}
	tUserExecution   = Technique{ID: "T1204", Name: "User Execution", Tactic: "Execution"}
	tImpairDefenses  = Technique{ID: "T1562", Name: "Impair Defenses", Tactic: "Defense Evasion"}
	tSupplyChain     = Technique{ID: "T1195", Name: "Supply Chain Compromise", Tactic: "Initial Access"}
	tNetworkDiscover = Technique{ID: "T1046", Name: "Network Service Discovery", Tactic: "Discovery"}
	tProcInjection   = Technique{ID: "T1055", Name: "Process Injection", Tactic: "Defense Evasion"}
	// Genişletilmiş kapsam (sistemin ürettiği yeni olay türleri):
	tAutostart     = Technique{ID: "T1547", Name: "Boot or Logon Autostart Execution", Tactic: "Persistence"}
	tAppLayerC2    = Technique{ID: "T1071", Name: "Application Layer Protocol", Tactic: "Command and Control"}
	tExfilAltProto = Technique{ID: "T1048", Name: "Exfiltration Over Alternative Protocol", Tactic: "Exfiltration"}
	tIndicatorRem  = Technique{ID: "T1070", Name: "Indicator Removal", Tactic: "Defense Evasion"}
	tIngressTool   = Technique{ID: "T1105", Name: "Ingress Tool Transfer", Tactic: "Command and Control"}
)

// Catalog, sistemin eşleyebildiği tekniklerin tam listesini (kapsama matrisi)
// deterministik sırada döner. ATT&CK kapsama görünümü için kullanılır.
func Catalog() []Technique {
	return []Technique{
		tSupplyChain,     // T1195
		tNetworkDiscover, // T1046
		tProcInjection,   // T1055
		tExecutionScript, // T1059
		tUserExecution,   // T1204
		tImpairDefenses,  // T1562
		tAutostart,       // T1547
		tAppLayerC2,      // T1071
		tExfilAltProto,   // T1048
		tIndicatorRem,    // T1070
		tIngressTool,     // T1105
	}
}

// Classify, bir olay kategorisi ve mesajına göre ATT&CK tekniğini döner. Eşleşme
// yoksa (Technique{}, false) döner (operasyonel/nötr olaylar: SYSTEM, AGENT_UPDATE).
// SECURITY kategorisi birden çok tespiti kapsar; mesaj içeriğiyle inceltilir.
func Classify(category, message string) (Technique, bool) {
	m := strings.ToLower(message)
	switch category {
	case "NETWORK_DISCOVERY":
		return tNetworkDiscover, true
	case "NETWORK_CONN":
		// Giden bağlantı telemetrisi → uygulama-katmanı C2 kanalı bağlamı.
		return tAppLayerC2, true
	case "POLICY_VIOLATION":
		// Kalıcılık (autostart) girdisi mi, yoksa yasaklı süreç yürütmesi mi?
		if strings.Contains(m, "kalıcılık") || strings.Contains(m, "persistence") ||
			strings.Contains(m, "autostart") || strings.Contains(m, "run key") ||
			strings.Contains(m, "cron") || strings.Contains(m, "systemd") ||
			strings.Contains(m, "zamanlanmış görev") || strings.Contains(m, "scheduled task") {
			return tAutostart, true
		}
		return tUserExecution, true
	case "SECURITY":
		switch {
		case strings.Contains(m, "dlp") || strings.Contains(m, "hassas veri") ||
			strings.Contains(m, "veri sızıntısı") || strings.Contains(m, "exfil"):
			return tExfilAltProto, true // veri sızdırma (DLP)
		case strings.Contains(m, "dga") || strings.Contains(m, "beacon") ||
			strings.Contains(m, "ioc eşleşmesi") || strings.Contains(m, "periyodik") ||
			strings.Contains(m, "c2"):
			return tAppLayerC2, true // C2 / beacon / IoC
		case strings.Contains(m, "yanal hareket") || strings.Contains(m, "lateral"):
			return tNetworkDiscover, true // iç-ağ tarama / yanal hareket
		case strings.Contains(m, "içerik-tarama") || strings.Contains(m, "yara"):
			return tIngressTool, true // bilinen-kötü içerik (dışarıdan getirilen araç)
		case strings.Contains(m, "dosya bütünlüğü") || strings.Contains(m, "fim"):
			return tIndicatorRem, true // dosya kurcalama/silme (iz temizleme)
		case strings.Contains(m, "güncelleme"): // sahte/bozuk OTA reddi
			return tSupplyChain, true
		case strings.Contains(m, "script"): // imzasız/sahte script reddi
			return tExecutionScript, true
		case strings.Contains(m, "anomali"): // olağandışı süreç davranışı
			return tProcInjection, true
		case strings.Contains(m, "kurcalama") || strings.Contains(m, "tamper") ||
			strings.Contains(m, "watchdog") || strings.Contains(m, "karantina") ||
			strings.Contains(m, "öz-tasdik") || strings.Contains(m, "devre dışı"):
			return tImpairDefenses, true
		default:
			// Sınıflandırılamayan SECURITY olayı: savunma-etkisizleştirme varsay.
			return tImpairDefenses, true
		}
	default:
		return Technique{}, false
	}
}
