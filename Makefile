# Shinkiro — Ephemeral Deception & Attacker Intelligence Mesh

BINARY=bin/shinkiro
SRC=$(shell find . -name "*.go")

.PHONY: all build clean test run lint bench fuzz

all: build

build:
	@mkdir -p bin
	@echo "🔨 Building Shinkiro..."
	@go build -o $(BINARY) cmd/shinkiro/main.go
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
	@echo "✅ All fuzz targets passed without panics or crashes."
