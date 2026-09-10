package notify

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// SIEM iletici: yüksek önem düzeyli olayları bir SIEM'e syslog üzerinden CEF
// (ArcSight) veya LEEF (QRadar) biçiminde iletir. UDP/TCP; asenkron best-effort
// (kuyruk dolarsa düşürülür — olay-alım yolu bloke olmaz). Bağımlılıksız.

// sevToCEF, önem düzeyini CEF 0-10 ölçeğine eşler.
func sevToCEF(s string) int {
	switch s {
	case "CRITICAL":
		return 10
	case "HIGH":
		return 8
	case "MEDIUM":
		return 6
	case "LOW":
		return 4
	case "INFO":
		return 2
	default:
		return 0
	}
}

// cefEscapeHeader, CEF başlık alanlarında \ ve | karakterlerini kaçırır.
func cefEscapeHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// cefEscapeExt, CEF uzantı (extension) değerlerinde \ ve = karakterlerini kaçırır.
func cefEscapeExt(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "=", `\=`)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// formatCEF, bir uyarıyı CEF satırı olarak biçimlendirir.
//
//	CEF:0|XEMS|Suite|<ver>|<signatureID>|<name>|<sev>|<extension>
func formatCEF(a Alert, product, version string) string {
	ext := "deviceExternalId=" + cefEscapeExt(a.DeviceID) +
		" cat=" + cefEscapeExt(a.Category) +
		" rt=" + fmt.Sprintf("%d", a.OccurredAt.UnixMilli())
	if a.TechniqueID != "" {
		ext += " cs1Label=MitreTechnique cs1=" + cefEscapeExt(a.TechniqueID+" "+a.TechniqueName)
	}
	if a.Tactic != "" {
		ext += " cs2Label=MitreTactic cs2=" + cefEscapeExt(a.Tactic)
	}
	if a.Tenant != "" {
		ext += " cs3Label=Tenant cs3=" + cefEscapeExt(a.Tenant)
	}
	return fmt.Sprintf("CEF:0|XEMS|%s|%s|%s|%s|%d|%s",
		cefEscapeHeader(product), cefEscapeHeader(version),
		cefEscapeHeader(a.Category), cefEscapeHeader(a.Message), sevToCEF(a.Severity), ext)
}

// formatLEEF, bir uyarıyı LEEF 2.0 satırı olarak biçimlendirir (tab ayraçlı).
//
//	LEEF:2.0|XEMS|Suite|<ver>|<eventID>|<attrs>
func formatLEEF(a Alert, product, version string) string {
	attrs := "devTime=" + a.OccurredAt.Format(time.RFC3339) +
		"\tsev=" + fmt.Sprintf("%d", sevToCEF(a.Severity)) +
		"\tsrc=" + a.DeviceID +
		"\tcat=" + a.Category +
		"\tmsg=" + strings.ReplaceAll(a.Message, "\n", " ")
	if a.TechniqueID != "" {
		attrs += "\tmitreTechnique=" + a.TechniqueID
	}
	if a.Tenant != "" {
		attrs += "\ttenant=" + a.Tenant
	}
	return fmt.Sprintf("LEEF:2.0|XEMS|%s|%s|%s|%s", product, version, a.Category, attrs)
}

// syslogPriority, RFC 3164 <PRI> öneki (facility local0=16, önem düzeyine göre).
func syslogPriority(sev string) int {
	// syslog severity: 0=emerg..7=debug. Eşleme: CRITICAL→2, HIGH→3, MEDIUM→4, LOW→5, INFO→6.
	sysSev := 6
	switch sev {
	case "CRITICAL":
		sysSev = 2
	case "HIGH":
		sysSev = 3
	case "MEDIUM":
		sysSev = 4
	case "LOW":
		sysSev = 5
	}
	return 16*8 + sysSev // local0
}

// SyslogNotifier, uyarıları bir SIEM'e syslog+CEF/LEEF olarak iletir.
type SyslogNotifier struct {
	addr    string
	proto   string // "udp" | "tcp"
	format  string // "cef" | "leef"
	minSev  int
	product string
	version string
	host    string
	ch      chan Alert
}

// NewSyslogNotifier, verilen SIEM adresine (host:port) ileten bir notifier kurar.
// proto "tcp"/"udp" (varsayılan udp); format "cef"/"leef" (varsayılan cef).
func NewSyslogNotifier(addr, proto, format, minSeverity, version string) (*SyslogNotifier, error) {
	if addr == "" {
		return nil, fmt.Errorf("notify: SIEM adresi boş")
	}
	if proto != "tcp" {
		proto = "udp"
	}
	if format != "leef" {
		format = "cef"
	}
	ms := sevRank(minSeverity)
	if ms == 0 {
		ms = sevRank("HIGH")
	}
	host, _ := os.Hostname()
	n := &SyslogNotifier{
		addr: addr, proto: proto, format: format, minSev: ms,
		product: "Suite", version: nonEmpty(version, "0.0.0"), host: host,
		ch: make(chan Alert, queueSize),
	}
	go n.worker()
	return n, nil
}

// Notify, uyarıyı eşik üstündeyse kuyruğa alır (best-effort; doluysa düşürür).
func (n *SyslogNotifier) Notify(a Alert) {
	if sevRank(a.Severity) < n.minSev {
		return
	}
	select {
	case n.ch <- a:
	default:
		log.Printf("notify(siem): kuyruk dolu, uyarı düşürüldü (device=%s)", a.DeviceID)
	}
}

func (n *SyslogNotifier) worker() {
	for a := range n.ch {
		n.send(a)
	}
}

func (n *SyslogNotifier) send(a Alert) {
	var body string
	if n.format == "leef" {
		body = formatLEEF(a, n.product, n.version)
	} else {
		body = formatCEF(a, n.product, n.version)
	}
	// RFC 3164 syslog: <PRI>Mmm dd hh:mm:ss host tag: msg
	line := fmt.Sprintf("<%d>%s %s XEMS: %s", syslogPriority(a.Severity),
		time.Now().Format("Jan _2 15:04:05"), n.host, body)
	conn, err := net.DialTimeout(n.proto, n.addr, httpTimeout)
	if err != nil {
		log.Printf("notify(siem): bağlanılamadı %s: %v", n.addr, err)
		return
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(httpTimeout))
	if _, err := conn.Write([]byte(line + "\n")); err != nil {
		log.Printf("notify(siem): gönderim hatası: %v", err)
	}
}

// Multi, bir uyarıyı birden çok notifier'a dağıtır (webhook + SIEM birlikte).
type Multi struct{ notifiers []Notifier }

// NewMulti, nil olmayan notifier'ları birleştiren bir fan-out oluşturur.
func NewMulti(ns ...Notifier) *Multi {
	var out []Notifier
	for _, n := range ns {
		if n != nil {
			out = append(out, n)
		}
	}
	return &Multi{notifiers: out}
}

// Notify, uyarıyı tüm alt notifier'lara iletir.
func (m *Multi) Notify(a Alert) {
	for _, n := range m.notifiers {
		n.Notify(a)
	}
}

// Len, birleşik notifier sayısını döner.
func (m *Multi) Len() int { return len(m.notifiers) }

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
