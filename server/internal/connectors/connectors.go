package connectors

import (
	"bufio"
	"context"
	"os"
	"strings"
	"time"

	"xems.corp/suite/server/internal/connector"
	"xems.corp/suite/server/internal/logingest"
	"xems.corp/suite/server/internal/model"
)

// Puller, bir kaynaktan ham kayıtları çeker (satır-tabanlı formatlar için her öğe bir
// satır; belge-tabanlı formatlar için her öğe tam bir belge). Çevrimdışı test/dosya
// ya da çevrimiçi HTTP ile enjekte edilir — connector çekirdeği kaynaktan bağımsızdır.
type Puller func(ctx context.Context) ([]string, error)

// Normalizer, tek bir ham kaydı kanonik olaylara çevirir (now enjekte edilir).
type Normalizer func(raw string, now time.Time) ([]model.Event, error)

// LogConnector, bir Puller + Normalizer'dan connector.Connector üretir. §29 XDR
// kaynakları ve §30 Cloud için ortak taşıyıcı.
type LogConnector struct {
	ConnName string
	ConnKind string
	pull     Puller
	norm     Normalizer
	now      func() time.Time
}

// NewLogConnector, verilen ad/tür/puller/normalizer ile bir bağlayıcı kurar.
// now nil → time.Now.
func NewLogConnector(name, kind string, pull Puller, norm Normalizer, now func() time.Time) *LogConnector {
	if now == nil {
		now = time.Now
	}
	return &LogConnector{ConnName: name, ConnKind: kind, pull: pull, norm: norm, now: now}
}

func (c *LogConnector) Name() string { return c.ConnName }
func (c *LogConnector) Kind() string { return c.ConnKind }
func (c *LogConnector) Health() error {
	if c.pull == nil || c.norm == nil {
		return errNotConfigured
	}
	return nil
}

// Fetch, kaynaktan ham kayıtları çeker ve her birini normalize ederek kanonik olay
// dilimini döner. Tek bir kaydın normalize hatası diğerlerini engellemez (best-effort).
func (c *LogConnector) Fetch(ctx context.Context) ([]model.Event, error) {
	if c.pull == nil || c.norm == nil {
		return nil, errNotConfigured
	}
	raws, err := c.pull(ctx)
	if err != nil {
		return nil, err
	}
	now := c.now()
	var out []model.Event
	for _, raw := range raws {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if evs, nerr := c.norm(raw, now); nerr == nil {
			out = append(out, evs...)
		}
	}
	return out, nil
}

// errNotConfigured, puller/normalizer eksik olduğunda döner.
var errNotConfigured = notConfiguredError("connectors: bağlayıcı yapılandırılmamış (puller/normalizer eksik)")

type notConfiguredError string

func (e notConfiguredError) Error() string { return string(e) }

// --- Normalizer adaptörleri (logingest'i sararak) --------------------------

func recToEvents(rec logingest.Record) []model.Event {
	ev := rec.Event
	if ev.DeviceID == "" {
		ev.DeviceID = rec.DeviceID
	}
	return []model.Event{ev}
}

// SyslogNormalizer, syslog satırını normalize eder (§29).
func SyslogNormalizer(raw string, now time.Time) ([]model.Event, error) {
	rec, err := logingest.NormalizeSyslog(raw, now)
	if err != nil {
		return nil, err
	}
	return recToEvents(rec), nil
}

// CEFNormalizer, CEF satırını normalize eder (§29).
func CEFNormalizer(raw string, now time.Time) ([]model.Event, error) {
	rec, err := logingest.NormalizeCEF(raw, now)
	if err != nil {
		return nil, err
	}
	return recToEvents(rec), nil
}

// LEEFNormalizer, LEEF satırını normalize eder (§29).
func LEEFNormalizer(raw string, now time.Time) ([]model.Event, error) {
	rec, err := logingest.NormalizeLEEF(raw, now)
	if err != nil {
		return nil, err
	}
	return recToEvents(rec), nil
}

// JSONNormalizer, XEMS JSON kaydını/dizisini normalize eder (§29).
func JSONNormalizer(raw string, now time.Time) ([]model.Event, error) {
	recs, err := logingest.NormalizeJSON([]byte(raw), now)
	if err != nil {
		return nil, err
	}
	var out []model.Event
	for _, r := range recs {
		out = append(out, recToEvents(r)...)
	}
	return out, nil
}

// WinEventNormalizer, Windows olay-günlüğü JSON'unu normalize eder (§29).
func WinEventNormalizer(raw string, now time.Time) ([]model.Event, error) {
	recs, err := logingest.NormalizeWinEvent([]byte(raw), now)
	if err != nil {
		return nil, err
	}
	var out []model.Event
	for _, r := range recs {
		out = append(out, recToEvents(r)...)
	}
	return out, nil
}

// CloudNormalizer, verilen sağlayıcı için bulut denetim normalizer'ı döner (§30).
func CloudNormalizer(provider string) Normalizer {
	return func(raw string, now time.Time) ([]model.Event, error) {
		return NormalizeCloudAudit([]byte(raw), provider, now)
	}
}

// --- Somut bağlayıcı kurucuları ---------------------------------------------

// NewSyslogConnector, ağ/güvenlik-duvarı syslog kaynağı için bağlayıcı (§29).
func NewSyslogConnector(name string, pull Puller) *LogConnector {
	return NewLogConnector(name, "network", pull, SyslogNormalizer, nil)
}

// NewCEFConnector, CEF (SIEM/firewall) kaynağı için bağlayıcı (§29).
func NewCEFConnector(name string, pull Puller) *LogConnector {
	return NewLogConnector(name, "siem", pull, CEFNormalizer, nil)
}

// NewWinEventConnector, Windows olay-günlüğü (kimlik/uç) kaynağı için bağlayıcı (§29).
func NewWinEventConnector(name string, pull Puller) *LogConnector {
	return NewLogConnector(name, "identity", pull, WinEventNormalizer, nil)
}

// NewCloudConnector, bulut denetim-log kaynağı için bağlayıcı (§30). provider ör.
// "aws" | "azure" | "gcp" | "m365".
func NewCloudConnector(name, provider string, pull Puller) *LogConnector {
	return NewLogConnector(name, "cloud", pull, CloudNormalizer(provider), nil)
}

// Compile-time: LogConnector, connector.Connector arayüzünü karşılar.
var _ connector.Connector = (*LogConnector)(nil)

// --- Pullers ----------------------------------------------------------------

// SlicePuller, sabit bir kayıt dilimini döndüren puller'dır (test/demo).
func SlicePuller(records []string) Puller {
	return func(context.Context) ([]string, error) { return records, nil }
}

// FilePuller, bir dosyanın satırlarını (satır-tabanlı formatlar) döndüren çevrimdışı
// puller'dır. Belge-tabanlı formatlar (JSON/WinEvent/Cloud) için dosyanın tamamını tek
// kayıt olarak döndürmek üzere whole=true kullanın.
func FilePuller(path string, whole bool) Puller {
	return func(context.Context) ([]string, error) {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if whole {
			var b strings.Builder
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
			for sc.Scan() {
				b.WriteString(sc.Text())
				b.WriteByte('\n')
			}
			return []string{b.String()}, sc.Err()
		}
		var lines []string
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		return lines, sc.Err()
	}
}
