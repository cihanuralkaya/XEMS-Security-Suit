package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

// setValid, geçerli bir yapılandırma için gereken tüm zorunlu env'leri ayarlar.
func setValid(t *testing.T) {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	t.Setenv("XEMS_MASTER_KEY", key)
	t.Setenv("XEMS_CA_CERT", "/x/ca.crt")
	t.Setenv("XEMS_CA_KEY", "/x/ca.key")
	t.Setenv("XEMS_SERVER_CERT", "/x/s.crt")
	t.Setenv("XEMS_SERVER_KEY", "/x/s.key")
}

func TestLoadValid(t *testing.T) {
	setValid(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.MasterKey) != 32 || c.CACertPath == "" {
		t.Fatalf("geçerli config beklenirdi: %+v", c)
	}
}

func TestLoadRejectsMissingMasterKey(t *testing.T) {
	t.Setenv("XEMS_MASTER_KEY", "")
	if _, err := Load(); err == nil {
		t.Fatal("eksik master key reddedilmeliydi")
	}
}

func TestLoadRejectsShortMasterKey(t *testing.T) {
	t.Setenv("XEMS_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 16)))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "32 bayt") {
		t.Fatalf("kısa master key reddedilmeliydi: %v", err)
	}
}

func TestLoadRejectsMissingTLSPaths(t *testing.T) {
	setValid(t)
	t.Setenv("XEMS_SERVER_CERT", "") // birini kaldır
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "XEMS_SERVER_CERT") {
		t.Fatalf("eksik TLS yolu reddedilmeliydi: %v", err)
	}
}

func TestLoadRejectsBadNumeric(t *testing.T) {
	setValid(t)
	t.Setenv("XEMS_RETENTION_DAYS", "0")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "XEMS_RETENTION_DAYS") {
		t.Fatalf("geçersiz saklama günü reddedilmeliydi: %v", err)
	}
}
