// Package config, C2 sunucusunun yapılandırmasını ortam değişkenlerinden yükler.
package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"xems.corp/suite/server/internal/tenant"
)

// Config, C2 sunucusunun çalışma-zamanı ayarlarıdır.
type Config struct {
	// mTLS'li AgentService dinleyicisi (kayıtlı ajanlar).
	ListenAgent string
	// Tek yönlü TLS'li EnrollmentService dinleyicisi (henüz sertifikası olmayan ajanlar).
	ListenEnroll string
	// TLS'li admin HTTP API dinleyicisi.
	ListenAdmin string

	// Admin oturum token'ı ve enrollment token ömürleri.
	AdminSessionTTL time.Duration
	EnrollTokenTTL  time.Duration

	// event_logs saklama süresi (gün) — dolan partition'lar DROP edilir (KVKK).
	RetentionDays int

	// Giriş kaba-kuvvet koruması: istemci başına izin verilen başarısız deneme ve
	// eşik aşılınca kilit süresi.
	LoginMaxAttempts int
	LoginLockout     time.Duration

	// PostgreSQL bağlantı dizesi (pgx DSN / URL).
	DatabaseURL string

	// PEM dosya yolları.
	CACertPath     string // istemci sertifikalarını imzalayan CA
	CAKeyPath      string
	ServerCertPath string // gRPC sunucu (TLS) sertifikası
	ServerKeyPath  string

	// Ana anahtar (32 bayt), base64. Alan şifreleme ve blind index alt
	// anahtarları bundan türetilir. Diske DÜZ yazılmaz; ortamdan/sır yöneticisinden gelir.
	MasterKey []byte

	// Eski ana anahtarlar (anahtar rotasyonu örtüşmesi): XEMS_MASTER_KEY_OLD,
	// virgülle ayrılmış base64 32-baytlık anahtarlar. Yeni veri MasterKey ile
	// şifrelenir; eski veri bu anahtarlarla ÇÖZÜLMEYE devam eder (veri kaybı yok).
	// Tüm eski veri yeniden şifrelendikten sonra kaldırılabilir.
	MasterKeysOld [][]byte

	// İmzalanan istemci sertifikalarının ömrü (kısa ömür + yenileme modeli).
	ClientCertTTL time.Duration

	// TenantID, bu dağıtımın kiracı kimliğidir (çok-kiracılı temel; Faz 1).
	// XEMS_TENANT_ID; belirtilmezse "default" (tek-kiracılı, geriye uyumlu).
	TenantID string
}

// Load, ortam değişkenlerinden Config üretir ve doğrular.
func Load() (*Config, error) {
	c := &Config{
		ListenAgent:      getenv("XEMS_LISTEN_AGENT", ":8443"),
		ListenEnroll:     getenv("XEMS_LISTEN_ENROLL", ":8444"),
		ListenAdmin:      getenv("XEMS_LISTEN_ADMIN", ":8445"),
		AdminSessionTTL:  getdur("XEMS_ADMIN_SESSION_TTL", 12*time.Hour),
		EnrollTokenTTL:   getdur("XEMS_ENROLL_TOKEN_TTL", 24*time.Hour),
		CACertPath:       os.Getenv("XEMS_CA_CERT"),
		CAKeyPath:        os.Getenv("XEMS_CA_KEY"),
		ServerCertPath:   os.Getenv("XEMS_SERVER_CERT"),
		ServerKeyPath:    os.Getenv("XEMS_SERVER_KEY"),
		ClientCertTTL:    getdur("XEMS_CLIENT_CERT_TTL", 720*time.Hour), // 30 gün
		RetentionDays:    getint("XEMS_RETENTION_DAYS", 90),
		LoginMaxAttempts: getint("XEMS_LOGIN_MAX_ATTEMPTS", 5),
		LoginLockout:     getdur("XEMS_LOGIN_LOCKOUT", 15*time.Minute),
	}

	// Hassas değerler ya doğrudan env'den ya da <KEY>_FILE dosyasından okunur
	// (systemd LoadCredential / Docker-K8s secrets / Vault agent — düz-metin env
	// yerine dosya-tabanlı sır; bkz. deploy/HARDENING.md).
	dbURL, err := secretEnv("XEMS_DATABASE_URL")
	if err != nil {
		return nil, err
	}
	c.DatabaseURL = dbURL

	mk, err := secretEnv("XEMS_MASTER_KEY")
	if err != nil {
		return nil, err
	}
	if mk == "" {
		return nil, fmt.Errorf("config: XEMS_MASTER_KEY zorunlu (env veya XEMS_MASTER_KEY_FILE)")
	}
	key, err := base64.StdEncoding.DecodeString(mk)
	if err != nil {
		return nil, fmt.Errorf("config: XEMS_MASTER_KEY base64 çözülemedi: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("config: XEMS_MASTER_KEY 32 bayt olmalı (base64 çözülünce), %d bayt", len(key))
	}
	c.MasterKey = key

	// Eski ana anahtarlar (rotasyon örtüşmesi; opsiyonel). Dosya-tabanlı sır da desteklenir.
	old, err := secretEnv("XEMS_MASTER_KEY_OLD")
	if err != nil {
		return nil, err
	}
	if old != "" {
		for _, part := range strings.Split(old, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			ok, err := base64.StdEncoding.DecodeString(part)
			if err != nil {
				return nil, fmt.Errorf("config: XEMS_MASTER_KEY_OLD base64 çözülemedi: %w", err)
			}
			if len(ok) != 32 {
				return nil, fmt.Errorf("config: XEMS_MASTER_KEY_OLD her anahtar 32 bayt olmalı, %d bayt", len(ok))
			}
			c.MasterKeysOld = append(c.MasterKeysOld, ok)
		}
	}

	// Zorunlu TLS materyali yolları — erken, anlaşılır hata (yanlış-yapılandırmayı
	// başlangıçta yakala; demo modu dahil gRPC sunucuları TLS gerektirir).
	for _, m := range []struct{ name, val string }{
		{"XEMS_CA_CERT", c.CACertPath}, {"XEMS_CA_KEY", c.CAKeyPath},
		{"XEMS_SERVER_CERT", c.ServerCertPath}, {"XEMS_SERVER_KEY", c.ServerKeyPath},
	} {
		if m.val == "" {
			return nil, fmt.Errorf("config: %s zorunlu (TLS materyali yolu)", m.name)
		}
	}
	// Sayısal alanlar makul olmalı (0/negatif değer sessiz hataya yol açar).
	if c.RetentionDays < 1 {
		return nil, fmt.Errorf("config: XEMS_RETENTION_DAYS >= 1 olmalı, %d verildi", c.RetentionDays)
	}
	if c.LoginMaxAttempts < 1 {
		return nil, fmt.Errorf("config: XEMS_LOGIN_MAX_ATTEMPTS >= 1 olmalı, %d verildi", c.LoginMaxAttempts)
	}

	// Kiracı kimliği (çok-kiracılı temel; boşsa "default"). Geçersizse başlatma durur.
	tid, err := tenant.Normalize(os.Getenv("XEMS_TENANT_ID"))
	if err != nil {
		return nil, fmt.Errorf("config: XEMS_TENANT_ID geçersiz: %w", err)
	}
	c.TenantID = string(tid)

	// XEMS_DATABASE_URL boşsa sunucu bellek-içi DEMO deposuyla başlar (kalıcılık yok).
	return c, nil
}

// secretEnv, hassas bir değeri döner: <key> ayarlıysa onu; değilse <key>_FILE
// ayarlıysa o dosyanın kırpılmış içeriğini (systemd LoadCredential / Docker-K8s
// secrets / Vault agent gibi dosya-tabanlı sır sağlayıcıları). İkisi de yoksa boş.
// Böylece sırlar düz-metin ortam değişkeni olarak sızmaz (proc/environ, ps).
func secretEnv(key string) (string, error) {
	if v := os.Getenv(key); v != "" {
		return v, nil
	}
	if p := os.Getenv(key + "_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", fmt.Errorf("config: %s_FILE okunamadı: %w", key, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getint(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getdur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
