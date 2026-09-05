# Implementation Tasks: Shinkiro (蜃気楼)

## Slice 1: Foundation & Legacy Purge
- [ ] TASK-1.1: Purge legacy Python prototype code from previous prototypes and initialize Go module (`go mod init github.com/Haiagari/shinkiro`).
- [ ] TASK-1.2: Establish core directory layout (`cmd/shinkiro`, `internal/core`, `internal/decoys`, `internal/intel`, `internal/defense`).
- [ ] TASK-1.3: Create baseline `Makefile` (`build`, `test`, `run`) and `.gitignore`.

## Slice 2: Core Multiplexer & Connection Sandboxing
- [ ] TASK-2.1: Define `Decoy` interface and configuration schemas in `internal/decoys/decoy.go` and `internal/config`.
- [ ] TASK-2.2: Implement `internal/core/multiplexer.go` to bind and manage concurrent listeners with graceful shutdown context.
- [ ] TASK-2.3: Write unit tests for multiplexer lifecycle, connection timeouts, and port collision handling.

## Slice 3: Protocol Decoys (SSH, Redis, Docker, HTTP)
- [ ] TASK-3.1: Implement `internal/decoys/ssh` with OpenSSH banner emulation, credential trapping, and in-memory virtual shell.
- [ ] TASK-3.2: Implement `internal/decoys/redis` with RESP protocol parsing, synthetic `INFO`, and Lua `EVAL` payload capture.
- [ ] TASK-3.3: Implement `internal/decoys/docker` with REST API simulation for crypto-mining container creation probes.
- [ ] TASK-3.4: Implement `internal/decoys/http` for canary `.env` and `.git/config` reconnaissance probes.
- [ ] TASK-3.5: Write unit tests for all 4 protocol decoys using mock `net.Conn` fixtures.

## Slice 4: Threat Intelligence & Dynamic Defense
- [ ] TASK-4.1: Implement `internal/intel/engine.go` to aggregate decoy events and extract IoCs (SHA-256 hashes, URLs, credentials).
- [ ] TASK-4.2: Implement JSONL structured audit log writer with rolling rotation.
- [ ] TASK-4.3: Implement `internal/defense/blocklist.go` for automated iptables/nftables export.
- [ ] TASK-4.4: Write unit tests for threat scoring and blocklist generation.

## Slice 5: CLI Entrypoint & Terminal Visualizer (TUI)
- [ ] TASK-5.1: Build `cmd/shinkiro/main.go` with subcommands: `up`, `status`, `export`, and `tui`.
- [ ] TASK-5.2: Implement live interactive dashboard with Bubbletea (`internal/tui`).
- [ ] TASK-5.3: End-to-end integration test validating simulated attack traffic against all active honeypot ports.
