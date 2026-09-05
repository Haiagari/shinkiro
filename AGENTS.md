# AGENTS.md — Shinkiro Project Architecture & Guidelines

**Scope:** [Haiagari/shinkiro](https://github.com/Haiagari/shinkiro) — Ephemeral Cyber Deception & Attacker Intelligence Mesh.

---

## 1. Product Truth

| Dimension | Specification |
|---|---|
| Product | **Shinkiro (蜃気楼)** |
| Language | **Go 1.24+** |
| License | **AGPL-3.0-only** |
| Core Philosophy | Zero-footprint, in-memory deception, fail-closed security, live telemetry |
| Protocol Decoys | SSH, Redis, Docker API, HTTP Traps, PostgreSQL, Kubernetes API |
| Active Defense | Dynamic `iptables`, `nftables`, and kernel-level `eBPF / XDP` mitigation |
| User Interface | Interactive Terminal Dashboard (Bubbletea + Lipgloss) & Headless Daemon |

---

## 2. Directory Layout & Architecture

```text
shinkiro/
├── cmd/
│   └── shinkiro/             # CLI entrypoint (up, tui, export, kernel, version)
├── config.yaml               # Default runtime configuration
├── deploy/
│   ├── docker/               # Multi-stage Dockerfile and docker-compose.yml
│   └── systemd/              # Production systemd service unit
├── internal/
│   ├── config/               # YAML & CLI parameters
│   ├── core/                 # Listener multiplexer, connection deadlines
│   ├── decoys/
│   │   ├── decoy.go          # Unified Decoy interface
│   │   ├── docker/           # Docker REST API emulator
│   │   ├── http/             # Canary HTTP recon traps
│   │   ├── k8s/              # Kubernetes control-plane emulator
│   │   ├── postgres/         # PostgreSQL 3.0 protocol emulator
│   │   ├── redis/            # Redis RESP wire protocol emulator
│   │   └── ssh/              # OpenSSH server & in-memory VirtualFS shell
│   ├── defense/              # iptables & nftables rule generator
│   ├── ebpf/                 # eBPF/XDP kernel drop generator
│   ├── intel/                # Telemetry ingestion, threat scoring, IoC extraction
│   └── tui/                  # Bubbletea live adversary dashboard
├── Makefile                  # Build, test, lint, and run targets
└── README.md
```

---

## 3. Mandatory Engineering Rules

- **Conventional Commits**: `feat(scope):`, `fix(scope):`, `docs(scope):`, etc.
- **Zero Attribution**: Never include `Co-Authored-By` or AI trailer lines.
- **Fail-Closed**: Any unhandled network error must cleanly terminate the socket without exposing host details.
- **Zero Host Mutation**: Decoys must execute purely in memory; never spawn host OS processes or touch real filesystem paths for attacker commands.
- **Comprehensive Unit Testing**: All protocol parsers must be tested via in-memory pipes (`net.Pipe()`).
