# XDR/MDM — geliştirme görevleri
# Not: Go, buf ve protoc-gen eklentileri kurulu olmalı (bkz. README).

.PHONY: proto tidy build build-server build-agent build-watchdog test e2e dev-certs release smoke clean fmt fmt-check vet check check-all

## proto: .proto dosyalarından Go kodunu üretir (gen/ altına).
proto:
	buf lint
	buf generate

## tidy: go.mod/go.sum düzenler.
tidy:
	go mod tidy

## build: tüm ikilileri derler.
build: build-server build-agent build-watchdog

build-server:
	go build -o bin/c2 ./server/cmd/c2

build-agent:
	go build -o bin/agent ./agent/cmd/agent

build-watchdog:
	go build -o bin/watchdog ./agent/cmd/watchdog

## fmt: izlenen tüm Go kaynaklarını gofmt ile yerinde biçimlendirir.
##      (git ls-files: yerel scratch/gitignore'lı dizinleri hariç tutar — CI temiz
##       checkout'ta neyi görüyorsa onu biçimlendirir.)
fmt:
	git ls-files '*.go' | xargs gofmt -w

## fmt-check: biçimsiz izlenen dosya varsa hata verir (CI gofmt kapısıyla aynı sonuç).
fmt-check:
	@unformatted="$$(git ls-files '*.go' | xargs gofmt -l)"; \
	if [ -n "$$unformatted" ]; then \
		echo "Biçimsiz dosyalar (make fmt ile düzeltin):"; echo "$$unformatted"; exit 1; \
	fi

## vet: go vet ./... — CI bunu çalıştırır ama `go test` ÇALIŞTIRMAZ; commit öncesi
##      atlanması kırmızı CI'nın en sık nedenidir.
vet:
	go vet ./...

## check: commit öncesi CI-paritesi HIZLI kapı (gofmt + vet + test). Push'tan önce çalıştırın.
check: fmt-check vet test

## check-all: check + uçtan uca smoke (tam yerel CI-paritesi; proto üretimi buf gerektirir, ayrı: make proto).
check-all: check smoke

## test: tüm birim + entegrasyon testlerini çalıştırır.
test:
	go test ./...

## e2e: yalnız uçtan-uca entegrasyon testini çalıştırır (gerçek mTLS gRPC).
e2e:
	go test -v ./server/internal/e2e/...

## smoke: gerçek c2 + agent'ı ayağa kaldırıp uçtan uca zinciri iddialarla test eder.
smoke:
	bash scripts/smoke-test.sh

## dev-certs: GELİŞTİRME CA + sunucu sertifikası üretir (./dev-certs).
dev-certs:
	go run ./tools/gencerts -out ./dev-certs -name xdr-c2

## release: tüm ikilileri Windows+Linux için çapraz derler (dist/).
##          Kullanım: make release VERSION=1.0.0
release:
	scripts/build-release.sh $(VERSION)

clean:
	rm -rf bin gen dist dev-certs
