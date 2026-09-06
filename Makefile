# Shinkiro — Ephemeral Deception & Attacker Intelligence Mesh

BINARY=bin/shinkiro
SRC=$(shell find . -name "*.go")
DOCKER_IMAGE?=shinkiro:local
COMPOSE_FILE=deploy/docker/docker-compose.yml

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS = -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: all build clean test run lint bench fuzz docker-build compose-up compose-down

all: build

build:
	@mkdir -p bin
	@echo "🔨 Building Shinkiro $(VERSION)..."
	@go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/shinkiro
	@echo "✅ Binary compiled at $(BINARY)"

test:
	@echo "🧪 Running unit tests..."
	@go test -v -race ./...

run: build
	@./$(BINARY) up

clean:
	@rm -rf bin/ data/
	@echo "🧹 Cleaned build artifacts."

lint:
	@go vet ./...

bench:
	@echo "⚡ Running performance benchmarks..."
	@go test -run=^$$ -bench=. -benchmem ./...

fuzz:
	@echo "🛡️  Running security fuzz tests across protocol decoders..."
	@go test -fuzz=FuzzRedisDecoy -fuzztime=5s ./internal/decoys/redis
	@go test -fuzz=FuzzPostgresDecoy -fuzztime=5s ./internal/decoys/postgres
	@go test -fuzz=FuzzDockerDecoy -fuzztime=5s ./internal/decoys/docker
	@go test -fuzz=FuzzVirtualFSExecute -fuzztime=5s ./internal/decoys/ssh
	@go test -fuzz=FuzzModbusDecoy -fuzztime=5s ./internal/decoys/modbus
	@echo "✅ All fuzz targets passed without panics or crashes."

docker-build:
	@echo "🐳 Building $(DOCKER_IMAGE)..."
	@docker build -f deploy/docker/Dockerfile -t $(DOCKER_IMAGE) .
	@echo "✅ Image tagged $(DOCKER_IMAGE)"

compose-up: docker-build
	@docker compose -f $(COMPOSE_FILE) up -d
	@echo "✅ Compose stack up (see deploy/README.md)"

compose-down:
	@docker compose -f $(COMPOSE_FILE) down
