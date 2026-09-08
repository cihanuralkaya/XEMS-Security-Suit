module xems.corp/suite

go 1.23.0

// Çekirdek paketler (server/internal/security, .../enroll, .../config) yalnız
// standart kütüphane kullanır ve bu bağımlılıklar olmadan da test edilebilir:
//   go test ./server/internal/security/... ./server/internal/enroll/... ./server/internal/config/...
//
// Aşağıdaki bağımlılıklar DB katmanı ve gRPC transport'u içindir; `go mod tidy`
// ile go.sum üretildikten sonra `make proto` + `make build` çalışır.
require (
	github.com/jackc/pgx/v5 v5.6.0
	google.golang.org/grpc v1.66.0
	google.golang.org/protobuf v1.34.2
)

require (
	golang.org/x/crypto v0.36.0
	golang.org/x/sys v0.31.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sync v0.12.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240604185151-ef581f913117 // indirect
)
