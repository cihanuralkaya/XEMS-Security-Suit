// Package chaos, platformun dayanıklılık (resilience) beklentilerini testlerde
// doğrulamak için saf-Go bir arıza-enjeksiyon koşum takımı sağlar (§41). Diğer
// paketler bunu TESTLERİNDE içe aktarır: gerçek bir C2/işçi/DB/ağ olmadan,
// denetlenebilir koşullar altında "kaos" üretilir ve sistemin beklenen biçimde
// kurtulup kurtulmadığı ileri sürülür.
//
// Tasarım ilkesi DETERMİNİZM'dir: olasılıklar enjekte edilen bir kaynaktan
// (func() float64) çözülür ve gecikmeler enjekte edilen sanal saat (Clock)
// üzerinden uygulanır — gerçek uyku, duvar-saati veya gerçek rastgelelik yoktur,
// bu yüzden testler tekrar-üretilebilir ve akmaz (flaky değildir).
package chaos

import (
	"errors"
	"math/rand"
	"sync"
	"time"
)

// Enjekte edilen arızaların döndürdüğü duyarlı (sentinel) hatalar. Çağıranlar
// errors.Is ile bunları ayırt edip (ör. yeniden-deneme) kurtarma davranışını
// test edebilir.
var (
	// ErrDropped, op'un hiç çalıştırılmadan düşürüldüğünü belirtir (paket kaybı).
	ErrDropped = errors.New("chaos: işlem düşürüldü")
	// ErrTimeout, op'un zaman aşımına uğradığını belirtir.
	ErrTimeout = errors.New("chaos: işlem zaman aşımına uğradı")
	// ErrFault, adlandırılmamış genel enjekte arızasıdır.
	ErrFault = errors.New("chaos: enjekte edilen arıza")

	// Senaryoya özgü hatalar.
	ErrC2Down        = errors.New("chaos: C2 sunucusu kapalı")
	ErrWorkerDown    = errors.New("chaos: işçi süreç öldü")
	ErrDBUnavailable = errors.New("chaos: veritabanı erişilemez")
	ErrCertExpired   = errors.New("chaos: sertifika süresi doldu")
	ErrQueueFull     = errors.New("chaos: kuyruk taştı")
)

// Clock, gerçek uyku olmadan testlerde ilerletilebilen sanal bir saattir.
// FaultInjector gecikmeleri bu saati ilerleterek "uygular"; böylece zamana
// bağlı mantık gerçek beklemeye gerek kalmadan sınanabilir.
type Clock struct {
	mu sync.Mutex
	t  time.Time
}

// NewClock, "start" anından başlayan bir sanal saat kurar.
func NewClock(start time.Time) *Clock { return &Clock{t: start} }

// Now, saatin şu anki değerini döner.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// Advance, saati d kadar ileri alır.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Config, bir FaultInjector'ın birleştirilebilir (composable) arıza kiplerini
// tanımlar. Sıfır-değerli Config hiçbir arıza enjekte etmez (kimlik/no-op).
type Config struct {
	// Delay, her op için eklenen gecikmedir (sanal saatte ilerletilip kaydedilir).
	Delay time.Duration
	// DropProb [0,1], op'u hiç çalıştırmadan düşürme (ErrDropped) olasılığıdır.
	DropProb float64
	// TimeoutProb [0,1], ErrTimeout döndürme olasılığıdır.
	TimeoutProb float64
	// FailProb [0,1], FailErr (veya ErrFault) döndürme olasılığıdır.
	FailProb float64
	// FailErr, FailProb tetiklendiğinde dönen hatadır; nil ise ErrFault kullanılır.
	FailErr error
	// DuplicateProb [0,1], op'u iki kez çağırma (yinelenen teslim) olasılığıdır.
	DuplicateProb float64
	// ReorderSize > 0 ise op'lar bu boyutta bir tamponda tutulur ve tampon
	// dolunca rastgele biri bırakılır — sırasız (out-of-order) teslim üretir.
	ReorderSize int
}

// FaultInjector, genel bir op üzerine yapılandırılabilir arıza kipleri uygular.
// Eşzamanlı-güvenlidir.
type FaultInjector struct {
	mu      sync.Mutex
	cfg     Config
	prob    func() float64  // [0,1) olasılık kaynağı (enjekte edilir)
	clock   *Clock          // sanal saat; gecikmeler buraya uygulanır
	reorder []func() error  // yeniden-sıralama tamponu
	delays  []time.Duration // uygulanan gecikmelerin kaydı
	stats   Stats           // gözlemlenebilirlik sayaçları
}

// Stats, bir FaultInjector'ın enjekte ettiği arızaların sayımlarıdır.
type Stats struct {
	Dropped    int           // düşürülen op sayısı
	TimedOut   int           // zaman aşımına uğrayan op sayısı
	Failed     int           // hata ile dönen op sayısı
	Duplicated int           // kopya olarak tekrar çağrılan op sayısı
	Delayed    int           // gecikme uygulanan op sayısı
	TotalDelay time.Duration // uygulanan gecikmelerin toplamı
}

// New, verilen Config ile bir FaultInjector kurar. prob nil ise zaman-tohumlu
// bir rastgele kaynak kullanılır (üretim kullanımı); testler determinizm için
// kendi kaynaklarını enjekte etmelidir. clock nil olabilir (gecikmeler yalnız
// kaydedilir, ilerletilecek saat yoktur).
func New(cfg Config, prob func() float64, clock *Clock) *FaultInjector {
	if prob == nil {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		prob = r.Float64
	}
	return &FaultInjector{cfg: cfg, prob: prob, clock: clock}
}

// Do, op'u yapılandırılmış arıza kiplerine tabi tutarak çalıştırır. Uygulama
// sırası: gecikme → düşürme/zaman-aşımı/hata (sonlandırıcı) → yeniden-sıralama
// tamponu → yürütme (+ olası kopya). Sonlandırıcı bir arıza tetiklenirse op hiç
// çağrılmaz ve ilgili hata döner.
func (fi *FaultInjector) Do(op func() error) error {
	if fi == nil {
		if op != nil {
			return op()
		}
		return nil
	}
	if op == nil {
		return nil
	}

	// 1) Gecikme: sanal saati ilerlet ve kaydet (gerçek uyku yok).
	if fi.cfg.Delay > 0 {
		fi.mu.Lock()
		fi.delays = append(fi.delays, fi.cfg.Delay)
		fi.stats.Delayed++
		fi.stats.TotalDelay += fi.cfg.Delay
		fi.mu.Unlock()
		if fi.clock != nil {
			fi.clock.Advance(fi.cfg.Delay)
		}
	}

	// 2) Sonlandırıcı arızalar: op çalıştırılmaz.
	if fi.fire(fi.cfg.DropProb) {
		fi.count(func(s *Stats) { s.Dropped++ })
		return ErrDropped
	}
	if fi.fire(fi.cfg.TimeoutProb) {
		fi.count(func(s *Stats) { s.TimedOut++ })
		return ErrTimeout
	}
	if fi.fire(fi.cfg.FailProb) {
		fi.count(func(s *Stats) { s.Failed++ })
		if fi.cfg.FailErr != nil {
			return fi.cfg.FailErr
		}
		return ErrFault
	}

	// 3) Yeniden-sıralama tamponu etkinse op'u sıraya al.
	if fi.cfg.ReorderSize > 0 {
		return fi.buffer(op)
	}

	// 4) Normal yürütme (olası kopya ile).
	return fi.exec(op)
}

// fire, p olasılığıyla (p<=0 → asla, p>=1 → her zaman) true döner. Olasılık
// enjekte edilen kaynaktan çözülür.
func (fi *FaultInjector) fire(p float64) bool {
	if p <= 0 {
		return false
	}
	fi.mu.Lock()
	v := fi.prob()
	fi.mu.Unlock()
	return v < p
}

// exec, op'u çalıştırır; DuplicateProb tetiklenirse ikinci kez de çağırır.
// İlk çağrının hatası döner (kopyanınki yalnız ilk başarılıysa kullanılır).
func (fi *FaultInjector) exec(op func() error) error {
	err := op()
	if fi.fire(fi.cfg.DuplicateProb) {
		fi.count(func(s *Stats) { s.Duplicated++ })
		if e := op(); err == nil {
			err = e
		}
	}
	return err
}

// buffer, op'u yeniden-sıralama tamponuna ekler. Tampon kapasiteyi aşarsa
// rastgele bir girdi seçilip bırakılır (sırasız teslim); aksi halde op elde
// tutulur ve nil döner (gecikmeli teslim).
func (fi *FaultInjector) buffer(op func() error) error {
	fi.mu.Lock()
	fi.reorder = append(fi.reorder, op)
	if len(fi.reorder) <= fi.cfg.ReorderSize {
		fi.mu.Unlock()
		return nil
	}
	n := len(fi.reorder)
	idx := int(fi.prob() * float64(n))
	if idx < 0 {
		idx = 0
	}
	if idx >= n {
		idx = n - 1
	}
	released := fi.reorder[idx]
	fi.reorder = append(fi.reorder[:idx], fi.reorder[idx+1:]...)
	fi.mu.Unlock()
	return fi.exec(released)
}

// Flush, yeniden-sıralama tamponunda bekleyen tüm op'ları çalıştırır ve
// dönen hataları birleştirir. Tampon boşaltılır.
func (fi *FaultInjector) Flush() error {
	if fi == nil {
		return nil
	}
	fi.mu.Lock()
	pending := fi.reorder
	fi.reorder = nil
	fi.mu.Unlock()
	var errs []error
	for _, op := range pending {
		if e := fi.exec(op); e != nil {
			errs = append(errs, e)
		}
	}
	return errors.Join(errs...)
}

// Pending, yeniden-sıralama tamponunda bekleyen op sayısını döner.
func (fi *FaultInjector) Pending() int {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	return len(fi.reorder)
}

// Stats, şimdiye dek enjekte edilen arızaların sayımlarının anlık kopyasını döner.
func (fi *FaultInjector) Stats() Stats {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	return fi.stats
}

func (fi *FaultInjector) count(f func(*Stats)) {
	fi.mu.Lock()
	f(&fi.stats)
	fi.mu.Unlock()
}

// --- Senaryolar (§41) -------------------------------------------------------

// Scenario, yol-haritasının dayanıklılık senaryolarını numaralandırır. Her biri
// bir Config'e eşlenir ve ondan bir FaultInjector kurulabilir.
type Scenario int

const (
	KillC2                Scenario = iota // C2 sunucusunu öldür
	KillWorker                            // bir işçi sürecini öldür
	DisconnectDB                          // veritabanı bağlantısını kopar
	NetworkDelay                          // ağ gecikmesi enjekte et
	PacketLoss                            // paket kaybı enjekte et
	DuplicateEvent                        // olayları yinele
	OutOfOrderEvent                       // olayları sırasız teslim et
	AgentDisconnect                       // ajan bağlantısını kopar
	CertificateExpiration                 // sertifika süresini doldur
	QueueOverflow                         // olay kuyruğunu taşır
)

// Scenarios, tüm senaryoları bildirim sırasında döner.
func Scenarios() []Scenario {
	return []Scenario{
		KillC2, KillWorker, DisconnectDB, NetworkDelay, PacketLoss,
		DuplicateEvent, OutOfOrderEvent, AgentDisconnect,
		CertificateExpiration, QueueOverflow,
	}
}

// String, senaryonun insan-okunur adını döner.
func (s Scenario) String() string {
	switch s {
	case KillC2:
		return "KillC2"
	case KillWorker:
		return "KillWorker"
	case DisconnectDB:
		return "DisconnectDB"
	case NetworkDelay:
		return "NetworkDelay"
	case PacketLoss:
		return "PacketLoss"
	case DuplicateEvent:
		return "DuplicateEvent"
	case OutOfOrderEvent:
		return "OutOfOrderEvent"
	case AgentDisconnect:
		return "AgentDisconnect"
	case CertificateExpiration:
		return "CertificateExpiration"
	case QueueOverflow:
		return "QueueOverflow"
	default:
		return "UnknownScenario"
	}
}

// Config, senaryoyu karşılık gelen arıza yapılandırmasına eşler.
func (s Scenario) Config() Config {
	switch s {
	case KillC2:
		return Config{FailProb: 1, FailErr: ErrC2Down}
	case KillWorker:
		return Config{TimeoutProb: 1}
	case DisconnectDB:
		return Config{FailProb: 1, FailErr: ErrDBUnavailable}
	case NetworkDelay:
		return Config{Delay: 2 * time.Second}
	case PacketLoss:
		return Config{DropProb: 0.5}
	case DuplicateEvent:
		return Config{DuplicateProb: 1}
	case OutOfOrderEvent:
		return Config{ReorderSize: 3}
	case AgentDisconnect:
		return Config{DropProb: 1}
	case CertificateExpiration:
		return Config{FailProb: 1, FailErr: ErrCertExpired}
	case QueueOverflow:
		return Config{FailProb: 1, FailErr: ErrQueueFull}
	default:
		return Config{}
	}
}

// Inject, senaryodan bir FaultInjector kurar (New'e yönlendiren kolaylık).
func (s Scenario) Inject(prob func() float64, clock *Clock) *FaultInjector {
	return New(s.Config(), prob, clock)
}

// --- Dayanıklılık beklentisi yardımcıları -----------------------------------

// RetryUntil, op başarılı olana dek fi üzerinden en çok attempts kez çağırır.
// "Otomatik kurtarma" beklentisini kanıtlar: geçici arızalardan sonra eninde
// sonunda başarıya ulaşıldığını ve kaç denemede ulaşıldığını döner. Başarı
// halinde err nil; aksi halde son hata döner.
func RetryUntil(fi *FaultInjector, attempts int, op func() error) (tries int, err error) {
	for tries = 1; tries <= attempts; tries++ {
		if fi == nil {
			err = op()
		} else {
			err = fi.Do(op)
		}
		if err == nil {
			return tries, nil
		}
	}
	return attempts, err
}

// Guard, yıkıcı eylemlerin anahtar-başına yalnızca bir kez yürütülmesini
// sağlayan idempotent bir korumadır. "Yinelenen yıkıcı eylem yok" beklentisini
// kanıtlar: DuplicateEvent arızası op'u iki kez çağırsa bile, aynı anahtarlı
// eylem yalnız bir kez işlenir; sonraki çağrılar ilk sonucu döner.
type Guard struct {
	mu   sync.Mutex
	done map[string]error
}

// NewGuard, boş bir Guard kurar.
func NewGuard() *Guard { return &Guard{done: make(map[string]error)} }

// Once, key ilk kez görülüyorsa action'ı çalıştırır ve sonucunu belleğe alır;
// aksi halde action'ı ÇALIŞTIRMADAN ilk sonucu döner.
func (g *Guard) Once(key string, action func() error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err, ok := g.done[key]; ok {
		return err
	}
	err := action()
	g.done[key] = err
	return err
}

// Executed, şimdiye dek yürütülen benzersiz eylem (anahtar) sayısını döner.
func (g *Guard) Executed() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.done)
}
