package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"xems.corp/suite/agent/internal/transport"
)

// identity, ajanın kalıcı kimliğidir (mTLS için).
type identity struct {
	deviceID string
	certPEM  []byte
	keyPEM   []byte
	caPEM    []byte
}

// ensureEnrolled, diskte kayıtlı kimlik varsa yükler; yoksa tek kullanımlık
// token + CSR ile enroll eder ve kimliği kalıcılaştırır.
func ensureEnrolled(ctx context.Context, cfg envConfig) (*identity, error) {
	keyPath := filepath.Join(cfg.dataDir, "agent.key")
	crtPath := filepath.Join(cfg.dataDir, "agent.crt")
	caPath := filepath.Join(cfg.dataDir, "ca-chain.pem")
	didPath := filepath.Join(cfg.dataDir, "device_id")

	if fileExists(keyPath) && fileExists(crtPath) && fileExists(caPath) && fileExists(didPath) {
		return loadIdentity(keyPath, crtPath, caPath, didPath)
	}

	// Enroll gerekli.
	if cfg.token == "" {
		return nil, fmt.Errorf("kayıtlı kimlik yok ve XEMS_ENROLL_TOKEN verilmedi")
	}
	if cfg.caPath == "" {
		return nil, fmt.Errorf("XEMS_CA_PEM (güven çıpası CA) verilmedi")
	}
	embeddedCA, err := os.ReadFile(cfg.caPath)
	if err != nil {
		return nil, fmt.Errorf("gömülü CA okunamadı: %w", err)
	}

	keyPEM, csrPEM, err := transport.GenerateKeyAndCSR("pending-enrollment")
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	resp, err := transport.Enroll(ctx, cfg.enrollAddr, embeddedCA, cfg.serverName, cfg.token, csrPEM,
		transport.EnrollInfo{Hostname: host, MACAddress: primaryMAC(), OSInfo: runtime.GOOS})
	if err != nil {
		return nil, fmt.Errorf("enroll başarısız: %w", err)
	}

	if err := os.MkdirAll(cfg.dataDir, 0o700); err != nil {
		return nil, err
	}
	// Özel anahtar yalnız sahibine okunur (0600).
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(crtPath, resp.GetClientCertPem(), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(caPath, resp.GetCaChainPem(), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(didPath, []byte(resp.GetDeviceId()), 0o644); err != nil {
		return nil, err
	}

	return &identity{
		deviceID: resp.GetDeviceId(),
		certPEM:  resp.GetClientCertPem(),
		keyPEM:   keyPEM,
		caPEM:    resp.GetCaChainPem(),
	}, nil
}

func loadIdentity(keyPath, crtPath, caPath, didPath string) (*identity, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(crtPath)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	did, err := os.ReadFile(didPath)
	if err != nil {
		return nil, err
	}
	return &identity{deviceID: string(did), certPEM: certPEM, keyPEM: keyPEM, caPEM: caPEM}, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
