// Package grpc, domain servislerini gRPC transport'una bağlayan ince
// adaptörlerdir.
//
// NOT: Bu paket üretilen proto kodunu (xems.corp/suite/gen/xems/v1) kullanır;
// derlenmesi için önce `make proto` (buf generate) çalıştırılmalıdır.
package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	xemsv1 "xems.corp/suite/gen/xems/v1"
	"xems.corp/suite/server/internal/enroll"
)

// EnrollmentHandler, EnrollmentService gRPC sunucusunu uygular.
type EnrollmentHandler struct {
	xemsv1.UnimplementedEnrollmentServiceServer
	svc *enroll.Service
}

// NewEnrollmentHandler oluşturur.
func NewEnrollmentHandler(svc *enroll.Service) *EnrollmentHandler {
	return &EnrollmentHandler{svc: svc}
}

// Enroll, proto isteğini domain'e çevirir, servisi çağırır ve yanıtı map'ler.
func (h *EnrollmentHandler) Enroll(ctx context.Context, req *xemsv1.EnrollRequest) (*xemsv1.EnrollResponse, error) {
	res, err := h.svc.Enroll(ctx, enroll.Input{
		Token:      req.GetEnrollmentToken(),
		CSRPEM:     req.GetCsrPem(),
		Hostname:   req.GetHostname(),
		MACAddress: req.GetMacAddress(),
		OSInfo:     req.GetOsInfo(),
	})
	if err != nil {
		if err == enroll.ErrInvalidToken {
			// Ayrıntı sızdırma: istemciye yalnız genel bir ret mesajı.
			return nil, status.Error(codes.PermissionDenied, "enrollment reddedildi")
		}
		return nil, status.Error(codes.Internal, "enrollment işlenemedi")
	}
	return &xemsv1.EnrollResponse{
		DeviceId:      res.DeviceID,
		ClientCertPem: res.ClientCertPEM,
		CaChainPem:    res.CAChainPEM,
		CertNotAfter:  timestamppb.New(res.NotAfter),
	}, nil
}

// RenewCertificate, mevcut mTLS bağlantısı üzerinden sertifika yeniler. Kimlik
// istemci sertifikasının CN'inden (=device_id) alınır; token GEREKMEZ. Yeni
// sertifika olmayan (henüz kayıtsız) bir bağlantıdan gelirse reddedilir.
func (h *EnrollmentHandler) RenewCertificate(ctx context.Context, req *xemsv1.RenewRequest) (*xemsv1.EnrollResponse, error) {
	deviceID, err := DeviceIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "yenileme için geçerli istemci sertifikası gerekli")
	}
	res, err := h.svc.Renew(ctx, deviceID, req.GetCsrPem())
	if err != nil {
		if errors.Is(err, enroll.ErrDeviceRevoked) {
			return nil, status.Error(codes.PermissionDenied, "cihaz iptal edilmiş — yenileme reddedildi")
		}
		return nil, status.Error(codes.Internal, "yenileme işlenemedi")
	}
	return &xemsv1.EnrollResponse{
		DeviceId:      res.DeviceID,
		ClientCertPem: res.ClientCertPEM,
		CaChainPem:    res.CAChainPEM,
		CertNotAfter:  timestamppb.New(res.NotAfter),
	}, nil
}
