BINARY_NAME := cidr-calculator
PKG := github.com/smford/cidr-calculator
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := -s -w \
	-X '$(PKG)/internal/cli.Version=$(VERSION)' \
	-X '$(PKG)/internal/cli.Commit=$(COMMIT)' \
	-X '$(PKG)/internal/cli.BuildDate=$(BUILD_DATE)'

.PHONY: all build test test-race bench cover lint fmt install docker-build snapshot clean

all: lint test build

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY_NAME) .

test:
	go test -v ./...

test-race:
	go test -v -race ./...

bench:
	go test -bench=. -benchmem ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	@echo "Run 'go tool cover -html=coverage.out' to view in browser"

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "Unformatted files found. Run 'make fmt'" && exit 1)

fmt:
	gofmt -w -s .

docker-build:
	docker build -t $(BINARY_NAME):latest .

snapshot:
	goreleaser release --snapshot --clean

install:
	go install -ldflags "$(LDFLAGS)" .

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME)-* coverage.out coverage.html
