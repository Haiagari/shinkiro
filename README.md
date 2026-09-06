# 蜃気楼 Shinkiro

**Ephemeral Cyber Deception & Attacker Intelligence Mesh**  
*In-memory honeynet, protocol decoys, IoC extraction, STIX/CEF/Syslog/ECS exporters, SOAR-lite playbooks, and text exporters for nftables / iptables / sample eBPF rules — not a live kernel XDP loader.*

[![Version](https://img.shields.io/badge/version-1.0.0-6366f1?style=flat-square)](CHANGELOG.md)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat-square)](https://golang.org/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-f59e0b?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20(prebuilt)%20%7C%20macOS%20(source)-blue?style=flat-square)](#quick-start)

> **Honesty note:** The static `tests-passing` badge was removed. CI runs `make test` on pushes/PRs to `main` (see `.github/workflows/ci.yml`); badge status is not auto-linked from Actions.

---

## What is Shinkiro

**Shinkiro (蜃気楼 — *mirage*)** is a single-binary cyber deception engine written in Go. It multiplexes lightweight, memory-jailed protocol emulators across common internet, cloud, and IoT attack surfaces.

Adversaries scanning your perimeter encounter responsive decoy services that capture credentials, probes, and exploit attempts without granting host access. Telemetry is scored, optionally correlated across decoys, and can drive SOAR-lite actions (`block_ip` / `alert`) plus **exported** firewall rule text — operators apply those rules themselves.

### What is implemented today

| Area | Reality in this tree |
| :--- | :--- |
| **15 decoys** | SSH, Telnet, MQTT, SMB, Redis, Docker, HTTP, Postgres, K8s, AWS IMDS, Mongo, Elastic, SMTP, DNS, Modbus — see matrix below |
| **CLI** | `up`, `tui`, `simulate`, `export` (nftables/iptables text), `kernel`/`ebpf` (rule script text), `cef`/`syslog`/`stix`/`ecs`, `canary`, `cluster hub` |
| **Defense exporters** | `internal/defense` + `internal/ebpf.FilterManager.RenderScript()` emit rule text; sample XDP C lives under `internal/ebpf/c/` — **no live BPF map loader / `BPF_MAP_UPDATE`** |
| **GeoIP** | Heuristic / demo prefix table in `internal/intel/geoip` — **not** a MaxMind offline database |
| **Cluster** | HTTP ingest hub (`POST /api/v1/cluster/ingest`) — **not** encrypted UDP gossip |
| **PCAP** | Libpcap 2.4 **writer package** exists (`internal/pcap`) but is **not wired** into `cmd/shinkiro` / the multiplexer pipeline |
| **Supply chain** | Release CI: Linux amd64/arm64 binaries, `checksums.txt`, Cosign **`sign-blob`** on checksums, Syft SPDX + CycloneDX SBOMs — **not** SLSA Level 3 provenance |
| **Deploy** | Dockerfile + Compose + Helm are runnable with a **local** image (`shinkiro:local`); no GHCR publish in release CI — see `deploy/README.md` |

<p align="center">
  <img src="docs/diagrams/architecture-darkmode.jpg" alt="Shinkiro System Architecture" width="100%">
</p>

<details>
<summary><b>View Mermaid Source Diagram</b></summary>

```mermaid
graph TD
    subgraph Adversary ["🌐 Adversary Traffic Vectors"]
        Attacker["Adversary Probes<br/>(SSH, Telnet, Redis, Docker, Postgres, K8s, MQTT, SMB, Modbus OT)"]
    end

    subgraph Core ["🛡️ Shinkiro Core Multiplexer"]
        Mux["In-Memory Multiplexer<br/>- Strict Read/Write Deadlines<br/>- Slowloris Defense<br/>- PCAP writer NOT wired in main"]
    end

    subgraph Decoys ["🎭 Active Protocol Decoys (15)"]
        D1["SSH :2222"]
        D2["Telnet :2323"]
        D3["Redis :6379"]
        D4["Docker :2375"]
        D5["MQTT :1883"]
        D6["Postgres :5432"]
        D7["SMB :4445"]
        D8["AWS IMDS :8169"]
        D9["Modbus/TCP :502"]
        D10["HTTP Deep Traps :8080"]
        D11["K8s :6443 / Mongo / Elastic / SMTP / DNS"]
    end

    subgraph Pipeline ["⚡ Telemetry & Attribution Engine"]
        Intel["Threat Intel & Attribution<br/>- SHA-256 Payload Hashing<br/>- MITRE ATT&CK Mapping<br/>- Campaign Correlator<br/>- Heuristic GeoIP prefixes<br/>- Dynamic Scoring (0-100)"]
    end

    subgraph Defense ["🚀 Response & SecOps"]
        TUI["Live Terminal Dashboard<br/>(shinkiro tui)"]
        SOAR["SOAR-Lite Playbooks<br/>(block_ip / alert hooks)"]
        SIEM["SIEM & Threat Feeds<br/>(CEF, Syslog, STIX 2.1, ECS, ThreatFox)"]
        Drop["Rule exporters<br/>(nftables / iptables / sample eBPF script text)"]
    end

    Attacker --> Mux
    Mux --> D1
    Mux --> D2
    Mux --> D3
    Mux --> D4
    Mux --> D5
    Mux --> D6
    Mux --> D7
    Mux --> D8
    Mux --> D9
    Mux --> D10
    Mux --> D11

    D1 --> Intel
    D2 --> Intel
    D3 --> Intel
    D4 --> Intel
    D5 --> Intel
    D6 --> Intel
    D7 --> Intel
    D8 --> Intel
    D9 --> Intel
    D10 --> Intel
    D11 --> Intel

    Intel --> TUI
    Intel --> SOAR
    Intel --> SIEM
    SOAR -->|block_ip hook / export text| Drop
    Intel -->|Threat Score thresholds| Drop
```
</details>

---

## 15 High-Interaction Decoy Services

See the complete [Decoy Protocols & Emulation Matrix](docs/decoys/decoy-matrix.md) for protocol notes and MITRE ATT&CK taxonomy.

| Decoy Service | Default Port | Emulated Protocol & Deception Capabilities |
| :--- | :--- | :--- |
| **SSH** | `2222` | OpenSSH-style handshake, captures passwords/keys, in-memory virtual terminal (`bash`), human latency jitter, logs commands & exfiltration attempts. |
| **Telnet** | `2323` | BusyBox-style router login prompt, IAC negotiation, Mirai-style credential harvesting, interactive fake shell. |
| **MQTT** | `1883` | MQTT v3.1.1 broker, CONNECT client authentication traps, unauthorized PUBLISH/SUBSCRIBE reconnaissance. |
| **SMB / CIFS** | `4445` | NetBIOS session & SMBv2 negotiation parser, EternalBlue-style recon trap. |
| **Redis** | `6379` | RESP protocol engine. Emulates unauthenticated Redis cluster `INFO`, traps `CONFIG` dumps and Lua `EVAL` payloads. |
| **Docker Engine** | `2375` | Docker REST API (`/_ping`, `/version`, `/containers/create`). Intercepts miner-style container create attempts. |
| **HTTP Deep Traps**| `8080` | Directory-traversal / canary paths (`/.env`, `/.git`), admin panels (`wp-login.php`, Jenkins, Grafana). |
| **PostgreSQL** | `5432` | Postgres wire protocol 3.0. SSL negotiation, cleartext auth challenge, captures DB usernames & passwords. |
| **Kubernetes API** | `6443` | K8s control-plane-style endpoints (`/version`, `/api`, `/apis`). Traps anonymous recon on pods/secrets paths. |
| **AWS IMDS** | `8169` | EC2 Instance Metadata Service-style (IMDSv1 & IMDSv2) SSRF trap for IAM credential paths. |
| **MongoDB** | `27017` | BSON wire protocol `OP_MSG` emulator, `isMaster` probes and unauthenticated recon. |
| **Elasticsearch** | `9200` | Elasticsearch REST API (`/`, `/_cat/indices`, `/_cluster/health`). |
| **SMTP / ESMTP** | `2525` | Postfix-style ESMTP banner (`HELO`, `EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`). |
| **DNS Server** | `1053` | RFC 1035 UDP parser, subdomain enumeration / C2-style lookup capture. |
| **Modbus / TCP** | `502` | ICS/SCADA PLC-style emulator, MBAP frame decoder, holding registers/coils, unauthorized command traps (`T0855`). |

Runtime config uses the top-level key **`services:`** (not `decoys:`) — see [`config.yaml`](config.yaml).

---

## Quick Start

### 0. Install pre-built binary (Linux amd64 / arm64)

Release CI publishes raw binaries (not GoReleaser tarballs):

| Asset | Example |
| :--- | :--- |
| Binary | `shinkiro-linux-amd64`, `shinkiro-linux-arm64` |
| Checksums | `checksums.txt` (SHA-256) |
| Signature | `checksums.bundle` (Cosign `sign-blob`) |
| SBOM | `shinkiro-sbom.spdx.json`, `shinkiro-sbom.cdx.json` (Syft) |

```bash
# Latest release (resolves tag via GitHub Releases API — no hardcoded fallback)
curl -sSL https://raw.githubusercontent.com/Haiagari/shinkiro/main/scripts/install.sh | sh

# Pin a version
SHINKIRO_VERSION=v1.0.0 curl -sSL https://raw.githubusercontent.com/Haiagari/shinkiro/main/scripts/install.sh | sh
```

macOS / Darwin: no pre-built assets today — use **Build from Source** below.

### 1. Build from Source

```bash
git clone https://github.com/Haiagari/shinkiro.git && cd shinkiro
make build
```

### 2. Launch Live Terminal Dashboard (TUI)

```bash
./bin/shinkiro tui
```

### 3. Run Headless Daemon

```bash
./bin/shinkiro up
```

### 4. Red Team Attack Simulation

Run synthetic adversarial probes against active decoys to exercise detection and telemetry:

```bash
./bin/shinkiro simulate --host 127.0.0.1
```

### 5. Export SIEM (CEF / Syslog / STIX 2.1 / ECS)

```bash
# ArcSight Common Event Format
./bin/shinkiro cef

# RFC5424 Syslog stream
./bin/shinkiro syslog

# STIX 2.1 JSON Bundle
./bin/shinkiro stix > /tmp/shinkiro-threats.json

# Elastic Common Schema (ECS v8.x)
./bin/shinkiro ecs
```

### 6. Automated Defense & SOAR Playbooks

Shinkiro loads declarative rules from `playbooks.yaml`. The **real** schema is `rules` / `if` / `then` with actions such as `block_ip` and `alert` (see `internal/soar`):

```yaml
# Matches playbooks.yaml + internal/soar.PlaybookConfig
rules:
  - name: ssh-credential-stuffing-autoblock
    enabled: true
    if:
      decoy: ssh
      min_score: 75
      action_match: LOGIN
    then:
      - type: block_ip
      - type: alert

  - name: rapid-recon-scanning-ratelimit
    enabled: true
    if:
      decoy: "*"
      threshold: 5
      window_sec: 30
    then:
      - type: block_ip
      - type: alert
```

Export firewall / sample kernel rule **text** (you apply it; Shinkiro does not attach XDP or rewrite live BPF maps):

```bash
# Sample eBPF / XDP-oriented script text + comments (not a live loader)
./bin/shinkiro kernel

# nftables blackhole table text
./bin/shinkiro export --format nftables --threshold 80

# iptables DROP script text
./bin/shinkiro export --format iptables --threshold 80
```

### 7. Docker Compose & Kubernetes / Helm

Full steps: [`deploy/README.md`](deploy/README.md).

**Compose** (local build — preferred):

```bash
make docker-build    # tags shinkiro:local
make compose-up      # deploy/docker/docker-compose.yml
```

**Helm** chart: `deploy/helm/shinkiro`

- Image defaults: `repository: shinkiro`, `tag: local`, `pullPolicy: IfNotPresent` — **no GHCR image is published** by current release CI (binaries only).
- Container command: `/usr/local/bin/shinkiro up` (matches Dockerfile).
- ConfigMap mounts `config.yaml` + `playbooks.yaml` into `/app` (runtime key is **`services:`**, not `decoys:`).
- Data volume at `/app/data` for `data/events.jsonl`; optional seccomp JSON mount + `RuntimeDefault` profile.
- `capabilities.drop: [ALL]` with `add: [NET_BIND_SERVICE]` for Modbus `:502`.

```bash
make docker-build
kind load docker-image shinkiro:local   # or: minikube image load shinkiro:local

helm install shinkiro ./deploy/helm/shinkiro \
  --namespace security \
  --create-namespace \
  --set image.repository=shinkiro \
  --set image.tag=local \
  --set image.pullPolicy=IfNotPresent
```

### 8. MITRE ATT&CK® & ThreatFox IoC Feeds

Every scored event can carry structured intelligence:

- **MITRE ATT&CK TTP Mapping:** Tags tactics/techniques from Initial Access, Execution, Persistence, Credential Access, Lateral Movement, and ICS (`T0855`, etc.).
- **ThreatFox-style IoC helpers:** Community-oriented IoC fields with SHA-256 payload checksums, ports, and confidence ratings (see `internal/intel`).

---

## Supply Chain & Runtime Hardening

What release CI **actually** does today (`.github/workflows/release.yml`):

1. **Cosign `sign-blob`:** Keyless Sigstore signing of `checksums.txt` → `checksums.bundle`. Individual binary attestations / image signing are not claimed here.
2. **Syft SBOM:** SPDX JSON and CycloneDX JSON attached to the GitHub Release.
3. **Not SLSA Level 3:** There is no SLSA provenance generator / attestation workflow in this repo. Earlier docs that claimed “SLSA Level 3 build provenance” were incorrect.
4. **Seccomp profile file:** `deploy/security/seccomp.json` is shipped for operators to apply; it is not automatically enforced by the binary itself.

---

## Testing & Quality Assurance

```bash
# Unit tests with race detector (same target CI uses)
make test

# Protocol parser fuzzing (testing.F) — Makefile-driven subset
make fuzz

# Concurrent connection spike / chaos flood test (real test in tree)
go test -v -race ./tests/chaos

# End-to-end multi-decoy simulation package
go test -v -race ./tests/e2e

# Optional local microbenchmarks (not gated in CI; no bench.yml regression workflow)
make bench
# Real Benchmark* funcs today: BenchmarkMultiplexer_ConcurrentConnections,
# BenchmarkTelemetry_EventIngestionRate in internal/core/multiplexer_bench_test.go
```

Published ns/op tables that previously appeared in docs without matching checked-in results are **removed**. Prefer running `make bench` locally and trusting `tests/chaos` for concurrency smoke.

---

## Documentation Index

- [High-Interaction Protocol Matrix](docs/decoys/decoy-matrix.md): Decoy specifications and MITRE mapping.
- [System Architecture & Data Flow](docs/architecture/system-architecture.md): Multiplexer, rule exporters, HTTP cluster hub, PCAP package status.
- [Threat Scoring & Campaign Correlator](docs/architecture/threat-scoring.md): Scoring, velocity notes, and real playbook schema.
- [SIEM & STIX 2.1 Integration](docs/threat-intel/stix-misp-integration.md): CEF, Syslog, ECS, STIX; honest GeoIP description.
- [Performance & Scaling Notes](docs/benchmarks/performance.md): How to run real benches/chaos; no invented SLA numbers.
- [Architecture Overview & Package Map](docs/api/architecture-overview.md): Go packages and CLI surface.
- [Deploy (Compose & Helm)](deploy/README.md): Local image build, `docker compose up`, `helm install`.

---

## License

AGPL-3.0-only © 2026 Haiagari Security.
