BINARY_NAME := satisfactory-simpfun-for-steamservice-start-script
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)
GO := go
GOFLAGS := -trimpath -buildvcs=false
DIST_DIR := dist

GOOS_LINUX := linux
GOARCH_AMD64 := amd64
GOARCH_ARM64 := arm64

.PHONY: all build build-linux build-linux-arm64 build-all compress clean test fmt vet help

all: clean build

build: build-linux

build-linux:
	CGO_ENABLED=0 GOOS=$(GOOS_LINUX) GOARCH=$(GOARCH_AMD64) $(GO) build $(GOFLAGS) -tags netgo -ldflags="$(LDFLAGS) -extldflags '-static'" -o $(DIST_DIR)/$(BINARY_NAME) .

build-linux-arm64:
	CGO_ENABLED=0 GOOS=$(GOOS_LINUX) GOARCH=$(GOARCH_ARM64) $(GO) build $(GOFLAGS) -tags netgo -ldflags="$(LDFLAGS) -extldflags '-static'" -o $(DIST_DIR)/$(BINARY_NAME)-arm64 .

build-all: build-linux build-linux-arm64

compress:
	@if command -v upx >/dev/null 2>&1; then \
		upx --best --lzma -9 $(DIST_DIR)/$(BINARY_NAME); \
		upx --best --lzma -9 $(DIST_DIR)/$(BINARY_NAME)-arm64; \
	fi

clean:
	$(GO) clean
	rm -rf $(DIST_DIR)

test:
	$(GO) test -v -race ./...

fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

lint: vet
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	fi

mod-tidy:
	$(GO) mod tidy

mod-download:
	$(GO) mod download

help:
	@echo "Available targets:"
	@echo "  all               - Clean and build for Linux amd64"
	@echo "  build             - Build for Linux amd64"
	@echo "  build-linux       - Build for Linux amd64"
	@echo "  build-linux-arm64 - Build for Linux arm64"
	@echo "  build-all         - Build for Linux amd64 and arm64"
	@echo "  compress          - Compress binaries with UPX"
	@echo "  clean             - Remove build artifacts"
	@echo "  test              - Run tests"
	@echo "  fmt               - Format code"
	@echo "  vet               - Run go vet"
	@echo "  lint              - Run golangci-lint"
	@echo "  mod-tidy          - Run go mod tidy"
	@echo "  mod-download      - Download dependencies"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION: $(VERSION)"
	@echo "  BUILD_TIME: $(BUILD_TIME)"
