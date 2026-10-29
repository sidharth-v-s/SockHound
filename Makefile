GO ?= go
BINARY := bin/sockhound
DIST_BINARY := dist/sockhound
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -X github.com/zoro/sockhound/internal/version.Version=$(VERSION)

.PHONY: build test vet fmt check clean release run-scan

build:
	@mkdir -p bin
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/sockhound

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

check: fmt vet test build

clean:
	rm -rf ./bin ./dist

release:
	@mkdir -p dist
	$(GO) build -trimpath -ldflags "-s -w $(LDFLAGS)" -o $(DIST_BINARY) ./cmd/sockhound

run-scan: build
	./$(BINARY) scan
