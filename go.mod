module xems.corp/suite

go 1.25.0

// Çekirdek paketler (server/internal/security, .../enroll, .../config) yalnız
// standart kütüphane kullanır ve bu bağımlılıklar olmadan da test edilebilir:
//   go test ./server/internal/security/... ./server/internal/enroll/... ./server/internal/config/...
//
// Aşağıdaki bağımlılıklar DB katmanı ve gRPC transport'u içindir; `go mod tidy`
// ile go.sum üretildikten sonra `make proto` + `make build` çalışır.
require (
	github.com/jackc/pgx/v5 v5.9.2
	google.golang.org/grpc v1.82.1
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/crypto v0.50.0
	golang.org/x/sys v0.43.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/text v0.39.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
)
