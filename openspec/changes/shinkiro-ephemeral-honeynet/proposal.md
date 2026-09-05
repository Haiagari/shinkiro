# Proposal: Shinkiro — Ephemeral Deception & Attacker Intelligence Mesh

## 1. Intent & Context
Pivot the existing repository (`Shinkiro`) away from LLM prompt firewalling and re-architect it from scratch into **Shinkiro (蜃気楼)**: a high-performance, single-binary cyber deception engine and ephemeral honeypot network written in **Go**.

Traditional honeypots (Cowrie, Dionaea, T-Pot) are monolithic, resource-heavy, and difficult to deploy in modern cloud-native environments. Shinkiro addresses this by offering a zero-footprint, memory-jailed deception mesh that simulates attractive vulnerable services, records adversary behavior in real-time, extracts actionable Threat Intelligence (TTPs, IoCs), and feeds automated firewall blocking rules.

## 2. Scope & Capabilities
- **Language & Runtime:** Single self-contained Go binary (`shinkiro`) with zero external runtime dependencies.
- **Deception Services (In-Memory Protocol Emulators):**
  - `decoy-ssh`: Emulates OpenSSH banners, captures credentials, provides a sandboxed virtual shell, logs full terminal sessions (tty recording).
  - `decoy-redis`: Emulates Redis RESP protocol, captures unauthenticated attempts, keys, and rogue Lua `EVAL` payloads.
  - `decoy-docker`: Emulates exposed unauthenticated Docker Engine API (`/v1.24/version`, `/containers/json`, `/containers/create`) to intercept crypto-mining deployment attempts.
  - `decoy-http`: Traps common reconnaissance probes (`/.env`, `/.git/config`, `/aws/credentials`, `/wp-login.php`) and serves canary-seeded synthetic responses.
- **Attacker Profiling & Threat Telemetry:**
  - Real-time IP profiling: Geolocation, ASN, Reverse DNS, and fingerprinting (JA3/JA4, user-agent).
  - IoC extraction: Hashes of uploaded/downloaded scripts, botnet signatures, brute-force password lists.
  - Fail-closed event bus for structured JSONL & syslog event emission.
- **Active Defense:**
  - Automated dynamic blocklist generation (iptables, nftables, Cloudflare WAF, CIDR export).
- **Interactive TUI:**
  - Terminal dashboard (Bubbletea + Lipgloss) visualizing active probes, geographic origins, and captured attacker sessions live.

## 3. Impact & Migration
- Complete wipe of legacy Python prototype files from previous prototypes.
- Creation of Go workspace, modules, and hexagonal package layout:
  - `cmd/shinkiro/`: Main entry point and CLI commands (`up`, `daemon`, `export`, `tui`).
  - `internal/core/`: Network listener multiplexer, state machine, and configuration engine.
  - `internal/decoys/`: Protocol-specific in-memory emulators (`ssh/`, `redis/`, `docker/`, `http/`).
  - `internal/intel/`: Telemetry processing, enrichment, IoC generation, and defense feed formatters.
  - `internal/tui/`: Real-time interactive terminal UI.
- Alignment with Haiagari brand standards and AGPL/MIT open-source licensing.

## 4. Verification & Criteria
- Unit tests for all protocol parsers without binding real privileged ports (mocked `net.Conn`).
- End-to-end integration tests using Docker/loopback testing connections against decoys.
- Zero external dependencies beyond Go standard library and selected UI/TUI packages.
