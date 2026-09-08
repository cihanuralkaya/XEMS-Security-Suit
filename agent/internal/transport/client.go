// Package transport, ajanın C2 ile gRPC iletişimini sağlar: enrollment (tek
// yönlü TLS) ve rutin AgentService çağrıları (mTLS).
package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	xemsv1 "xems.corp/suite/gen/xems/v1"
)

// GenerateKeyAndCSR, ajan için yeni bir EC anahtar çifti ve CSR üretir. Özel
// anahtar cihazdan çıkmaz; yalnız keyPEM olarak yerel diske (korumalı) yazılır.
func GenerateKeyAndCSR(commonName string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return keyPEM, csrPEM, nil
}

// EnrollInfo, kayıt sırasında sunucuya bildirilen cihaz bilgileridir.
type EnrollInfo struct {
	Hostname   string
	MACAddress string
	OSInfo     string
}

// Enroll, tek yönlü TLS ile EnrollmentService'e bağlanır ve tek kullanımlık
// token + CSR ile imzalı istemci sertifikası alır. caPEM, sunucuyu doğrulamak
// için kuruluma gömülü CA sertifikasıdır (güven çıpası).
func Enroll(ctx context.Context, addr string, caPEM []byte, serverName, token string, csrPEM []byte, info EnrollInfo) (*xemsv1.EnrollResponse, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("transport: gömülü CA PEM'i yüklenemedi")
	}
	creds := credentials.NewTLS(&tls.Config{
		RootCAs:          pool,
		ServerName:       serverName,
		MinVersion:       tls.VersionTLS13,
		VerifyConnection: pinVerifier(), // SPKI pinning (ayarlıysa)
	})
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("transport: enroll bağlantısı: %w", err)
	}
	defer conn.Close()

	cli := xemsv1.NewEnrollmentServiceClient(conn)
	return cli.Enroll(ctx, &xemsv1.EnrollRequest{
		EnrollmentToken: token,
		CsrPem:          csrPEM,
		Hostname:        info.Hostname,
		MacAddress:      info.MACAddress,
		OsInfo:          info.OSInfo,
	})
}

// CertHolder, ajanın geçerli istemci sertifikasını atomik tutar. Sertifika
// yenilendiğinde güncellenir; TLS her el sıkışmada GetClientCertificate ile
// güncel sertifikayı okur, böylece yeniden bağlanmalarda yeni sertifika kullanılır.
type CertHolder struct {
	p atomic.Pointer[tls.Certificate]
}

// NewCertHolder, PEM cert+key'den bir tutucu oluşturur.
func NewCertHolder(certPEM, keyPEM []byte) (*CertHolder, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("transport: istemci sertifikası yüklenemedi: %w", err)
	}
	h := &CertHolder{}
	h.p.Store(&cert)
	return h, nil
}

// Set, tutulan sertifikayı yeni cert+key ile değiştirir (yenileme sonrası).
func (h *CertHolder) Set(certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("transport: yeni sertifika yüklenemedi: %w", err)
	}
	h.p.Store(&cert)
	return nil
}

func (h *CertHolder) current() *tls.Certificate { return h.p.Load() }

func (h *CertHolder) tlsConfig(caPEM []byte, serverName string) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("transport: CA zinciri yüklenemedi")
	}
	return &tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return h.current(), nil
		},
		RootCAs:          pool,
		ServerName:       serverName,
		MinVersion:       tls.VersionTLS13,
		VerifyConnection: pinVerifier(), // SPKI pinning (ayarlıysa)
	}, nil
}

// DialAgent, mTLS ile AgentService'e bağlanır. İstemci sertifikası holder'dan
// DİNAMİK okunur; yenileme sonrası yeni bağlantılar güncel sertifikayı kullanır.
func DialAgent(addr string, holder *CertHolder, caPEM []byte, serverName string) (xemsv1.AgentServiceClient, *grpc.ClientConn, error) {
	cfg, err := holder.tlsConfig(caPEM, serverName)
	if err != nil {
		return nil, nil, err
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return nil, nil, fmt.Errorf("transport: agent bağlantısı: %w", err)
	}
	return xemsv1.NewAgentServiceClient(conn), conn, nil
}

// Renew, mTLS ile enroll endpoint'ine bağlanıp mevcut sertifikayla (token'sız)
// yenileme yapar; yeni cert+key üretir, holder'ı günceller ve PEM'leri döner
// (çağıran diske yazar). notAfter yeni sertifikanın bitiş zamanıdır.
func Renew(ctx context.Context, enrollAddr string, holder *CertHolder, caPEM []byte, serverName string) (newCertPEM, newKeyPEM []byte, notAfter time.Time, err error) {
	keyPEM, csrPEM, err := GenerateKeyAndCSR("renew")
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	cfg, err := holder.tlsConfig(caPEM, serverName)
	if err != nil {
		return nil, nil, time.Time{}, err
	}
	conn, err := grpc.NewClient(enrollAddr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("transport: yenileme bağlantısı: %w", err)
	}
	defer conn.Close()

	resp, err := xemsv1.NewEnrollmentServiceClient(conn).RenewCertificate(ctx, &xemsv1.RenewRequest{CsrPem: csrPEM})
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("transport: RenewCertificate: %w", err)
	}
	if err := holder.Set(resp.GetClientCertPem(), keyPEM); err != nil {
		return nil, nil, time.Time{}, err
	}
	return resp.GetClientCertPem(), keyPEM, resp.GetCertNotAfter().AsTime(), nil
}
