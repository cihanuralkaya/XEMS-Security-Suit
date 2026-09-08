package watchdog

import (
	"context"
	"time"
)

// Runner, gözetlenen süreci çalıştırır. Run, süreci başlatır ve süreç çıkana
// dek bloklar: temiz çıkışta nil, çökmede hata döner; ctx iptal edilirse süreci
// sonlandırıp ctx hatası döner.
type Runner interface {
	Run(ctx context.Context) error
}

// Swapper, OTA staged güncellemesinin uygulanmasını sağlar.
type Swapper interface {
	PendingStaged() (version, path string, ok bool)
	Swap() error
	Rollback() error
}

// Supervisor, ajanı gözetler: çökerse backoff'lu yeniden başlatır ve bekleyen
// staged güncellemeyi çalıştırmalar arasında uygular; yeni sürüm deneme
// penceresi içinde çökerse rollback eder.
type Supervisor struct {
	runner  Runner
	swapper Swapper

	baseBackoff time.Duration
	maxBackoff  time.Duration
	trialWindow time.Duration // yeni sürüm bu süreden önce çökerse rollback

	standDown func() bool // true → gözetimi bırak (imzalı offline offboard)

	now   func() time.Time
	sleep func(time.Duration)
	log   func(string)
}

// Options, Supervisor ayarlarıdır.
type Options struct {
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	TrialWindow time.Duration
	// StandDown, her (yeniden) başlatmadan ÖNCE danışılır. true dönerse gözetim
	// döngüsü ajanı yeniden başlatmadan durur (imzalı çevrimdışı offboard: ajan
	// geçerli bir stand-down jetonu doğruladığında bir işaret dosyası bırakır;
	// bu kanca onu okur). Böylece tamper-koruması BİLİNÇLİ olarak sonlandırılır.
	StandDown func() bool
	Now       func() time.Time
	Sleep     func(time.Duration)
	Log       func(string)
}

// NewSupervisor oluşturur. Sıfır alanlar makul varsayılanlarla doldurulur.
func NewSupervisor(runner Runner, swapper Swapper, o Options) *Supervisor {
	if o.BaseBackoff == 0 {
		o.BaseBackoff = time.Second
	}
	if o.MaxBackoff == 0 {
		o.MaxBackoff = 30 * time.Second
	}
	if o.TrialWindow == 0 {
		o.TrialWindow = 10 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Sleep == nil {
		o.Sleep = time.Sleep
	}
	if o.Log == nil {
		o.Log = func(string) {}
	}
	return &Supervisor{
		runner: runner, swapper: swapper,
		baseBackoff: o.BaseBackoff, maxBackoff: o.MaxBackoff, trialWindow: o.TrialWindow,
		standDown: o.StandDown,
		now:       o.Now, sleep: o.Sleep, log: o.Log,
	}
}

// Run, gözetim döngüsünü çalıştırır (ctx iptal edilene dek bloklar).
func (s *Supervisor) Run(ctx context.Context) error {
	backoff := s.baseBackoff
	onTrial := false

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// İmzalı çevrimdışı offboard: ajan stand-down işaretini bıraktıysa
		// gözetimi bırak (ajanı yeniden başlatma). Tamper-koruması burada
		// BİLİNÇLİ olarak sona erer — yalnız yetkili imzalı jetonla tetiklenir.
		if s.standDown != nil && s.standDown() {
			s.log("stand-down işareti bulundu, gözetim durduruluyor (offline offboard)")
			return nil
		}

		// Çalıştırmadan önce bekleyen staged güncelleme varsa uygula.
		if ver, _, ok := s.swapper.PendingStaged(); ok {
			if err := s.swapper.Swap(); err != nil {
				s.log("swap başarısız: " + err.Error())
			} else {
				s.log("yeni sürüme geçildi (deneme): " + ver)
				onTrial = true
			}
		}

		start := s.now()
		err := s.runner.Run(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		ran := s.now().Sub(start)

		if err == nil {
			// Temiz çıkış: yine de yeniden başlat (servis sürekli çalışmalı).
			// ANCAK anında (baseBackoff'tan kısa) çıkışta busy-loop'u önlemek için
			// bir tur bekle — yoksa 0 ile hemen çıkan bir ikili CPU'yu döngüyle yer.
			s.log("ajan temiz çıktı, yeniden başlatılıyor")
			onTrial = false
			if ran < s.baseBackoff {
				s.sleep(s.baseBackoff)
			}
			backoff = s.baseBackoff
			continue
		}

		// Çökme.
		if onTrial && ran < s.trialWindow {
			s.log("yeni sürüm deneme penceresinde çöktü, rollback yapılıyor")
			if rbErr := s.swapper.Rollback(); rbErr != nil {
				s.log("rollback başarısız: " + rbErr.Error())
			}
			onTrial = false
			backoff = s.baseBackoff
		} else {
			s.log("ajan çöktü, yeniden başlatılacak")
			backoff = nextBackoff(backoff, s.maxBackoff)
			onTrial = false
		}
		s.sleep(backoff)
	}
}

func nextBackoff(cur, max time.Duration) time.Duration {
	n := cur * 2
	if n > max {
		return max
	}
	return n
}
