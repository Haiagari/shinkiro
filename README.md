# 蜘気楼 Shinkiro

**Ephemeral Cyber Deception & Attacker Intelligence Mesh**  
*In-memory honeynet, protocol decoys, IoC extraction, STIX/CEF/Syslog/ECS exporters, SOAR-lite playbooks, and text exporters for nftables / iptables / sample eBPF rules — not a live kernel XDP loader.*

[![CI](https://github.com/Haiagari/shinkiro/actions/workflows/ci.yml/badge.svg)](https://github.com/Haiagari/shinkiro/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-1.0.0-6366f1?style=flat-square)](CHANGELOG.md)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat-square)](https://golang.org/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-f59e0b?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20(prebuilt)%20%7C%20macOS%20(source)-blue?style=flat-square)](#quick-start)

> **Docs hub:** [`docs/README.md`](docs/README.md) — getting started, architecture, operator guide, CLI reference, threat intel, deploy, development, honesty.  
> **Deploy modes / e2e / GHCR:** `make compose-lab` · `make compose-edge` · `make e2e` · optional `PUSH_GHCR=true` → `ghcr.io/haiagari/shinkiro`. See [`docs/deploy-modes-e2e-ghcr.md`](docs/deploy-modes-e2e-ghcr.md) and [`deploy/README.md`](deploy/README.md).

---

## What is Shinkiro

**Shinkiro (蜘気楼 — *mirage*)** is a single-binary cyber deception engine written in Go. It multiplexes lightweight, memory-jailed protocol emulators across common internet, cloud, and IoT attack surfaces.

Adversaries scanning your perimeter encounter responsive decoy services that capture credentials, probes, and exploit attempts without granting host access. Telemetry flows through an in-process **Event → Score → Correlate → Playbook → Sink** pipeline, drives SOAR-lite actions (`block_ip` / `alert`), and can emit firewall rule text — **live firewall apply is opt-in** (`--apply` / `SHINKIRO_SOAR_APPLY=1`); default is dry-run.

### Honest capabilities (code-backed)

| Area | Reality in this tree |
| :--- | :--- |
| **15 decoys** | SSH, Telnet, MQTT, SMB, Redis, Docker, HTTP, Postgres, K8s, AWS IMDS, Mongo, Elastic, SMTP, DNS, Modbus — [`docs/decoys/decoy-matrix.md`](docs/decoys/decoy-matrix.md) |
| **CLI** | `up`/`tui` (`--apply`, `--geoip-db`), `geoip`, `campaigns`, `threatfox`, `abuseipdb`, `coverage`, `simulate`, `export`, `kernel`/`ebpf` (text), `cef`/`syslog`/`stix`/`ecs`, `canary`, `cluster hub`, `version` — [`docs/cli-reference.md`](docs/cli-reference.md) |
| **Event pipeline** | `internal/pipeline` — Score (MITRE + optional MaxMind) → Correlate → Playbook → Sink |
| **SOAR `block_ip`** | Dry-run default; live exec + optional webhook only with `--apply` or `SHINKIRO_SOAR_APPLY=1` |
| **GeoIP** | Optional MaxMind GeoLite2 (`SHINKIRO_GEOLITE2_PATH` / `--geoip-db`) — **no-op when unset**; never invents coords |
| **Cluster** | Hub-and-spoke HTTP (`POST /api/v1/cluster/join|ingest`) with optional token — **not** UDP gossip |
| **Correlator v2** | Rule-based campaigns (same IP + window + hop path) — **not ML**; `shinkiro campaigns` |
| **Threat feeds** | Real HTTP ThreatFox / AbuseIPDB CLIs (API keys required) |
| **ATT&CK coverage** | `shinkiro coverage` from decoy-matrix tags (+ optional `--runtime-mapper`) |
| **PCAP** | On-demand high-score + TUI `CaptureNow` — **not** continuous mirroring |
| **Defense exporters** | `internal/defense` + `internal/ebpf.FilterManager.RenderScript()` — **no** live BPF loader |
| **Supply chain** | Linux binaries, `checksums.txt`, Cosign `sign-blob`, Syft SBOMs — **not** SLSA L3 |
| **Deploy** | Compose + Helm **lab/edge** modes; local image default; **optional** GHCR if `PUSH_GHCR=true` |
| **Prebuilt** | **Linux only** (amd64/arm64); macOS = build from source |

Full “what is not implemented” list: [`docs/honesty-limitations.md`](docs/honesty-limitations.md).

<p align="center">
  <img src="docs/diagrams/architecture-darkmode.jpg" alt="Shinkiro System Architecture" width="100%">
</p>

<details>
<summary><b>View Mermaid Source Diagram</b></summary>

```mermaid
graph TD
    subgraph Adversary ["Adversary Traffic Vectors"]
        Attacker["Adversary Probes<br/>(SSH, Telnet, Redis, Docker, Postgres, K8s, MQTT, SMB, Modbus OT)"]
    end

    subgraph Core ["Shinkiro Core Multiplexer"]
        Mux["In-Memory Multiplexer<br/>- Strict Read/Write Deadlines<br/>- Slowloris Defense<br/>- Emits to pipeline bus"]
    end

    subgraph Decoys ["Active Protocol Decoys (15)"]
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

    subgraph Pipeline ["Event → Score → Correlate → Playbook → Sink"]
        Intel["Threat Intel & Attribution<br/>- MITRE ATT&CK Mapping<br/>- Campaign Correlator v2<br/>- Optional MaxMind GeoLite2<br/>- Dynamic Scoring (0-100)<br/>- On-demand PCAP (score gate)"]
    end

    subgraph Defense ["Response & SecOps"]
        TUI["Operator TUI<br/>(select / block / pcap / simulate)"]
        SOAR["SOAR-Lite Playbooks<br/>(block_ip dry-run / --apply)"]
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
    SOAR -->|block_ip dry-run or apply| Drop
    Intel -->|Threat Score thresholds| Drop
```
</details>

---

## 15 High-Interaction Decoy Services

Complete matrix: [Decoy Protocols & Emulation Matrix](docs/decoys/decoy-matrix.md).

| Decoy Service | Default Port | Emulated Protocol & Deception Capabilities |
| :--- | :--- | :--- |
| **SSH** | `2222` | OpenSSH-style handshake, captures passwords/keys, in-memory virtual terminal (`bash`), human latency jitter |
| **Telnet** | `2323` | BusyBox-style router login, IAC negotiation, Mirai-style credential harvesting |
| **MQTT** | `1883` | MQTT v3.1.1 broker, CONNECT auth traps, unauthorized PUBLISH/SUBSCRIBE |
| **SMB / CIFS** | `4445` | NetBIOS session & SMBv2 negotiation, EternalBlue-style recon trap |
| **Redis** | `6379` | RESP engine; `INFO` / `CONFIG` / Lua `EVAL` traps |
| **Docker Engine** | `2375` | Docker REST API; miner-style container create intercept |
| **HTTP Deep Traps** | `8080` | `/.env`, `/.git`, wp-login, Jenkins, Grafana traps |
| **PostgreSQL** | `5432` | Wire protocol 3.0; SSL negotiate; cleartext auth capture |
| **Kubernetes API** | `6443` | Control-plane-style `/version`, `/api`, secrets recon traps |
| **AWS IMDS** | `8169` | IMDSv1 & v2 SSRF trap for IAM credential paths |
| **MongoDB** | `27017` | BSON `OP_MSG`; `isMaster` recon |
| **Elasticsearch** | `9200` | REST `/`, `/_cat/indices`, `/_cluster/health` |
| **SMTP / ESMTP** | `2525` | Postfix-style HELO/EHLO/MAIL/RCPT/DATA |
| **DNS Server** | `1053` | RFC 1035 UDP; subdomain / C2-style lookup capture |
| **Modbus / TCP** | `502` | ICS/SCADA PLC-style MBAP; unauthorized command traps (`T0855`) |

Runtime config uses top-level **`services:`** (not `decoys:`) — see [`config.yaml`](config.yaml).

---

## Quick Start

### 0. Install pre-built binary (Linux amd64 / arm64)

```bash
curl -sSL https://raw.githubusercontent.com/Haiagari/shinkiro/main/scripts/install.sh | sh
SHINKIRO_VERSION=v1.0.0 curl -sSL https://raw.githubusercontent.com/Haiagari/shinkiro/main/scripts/install.sh | sh
shinkiro version
```

**Pre-built binaries are Linux-only.** macOS / Darwin: build from source (`make build`). Full install notes: [`docs/getting-started.md`](docs/getting-started.md).

### 1. Build from Source

```bash
git clone https://github.com/Haiagari/shinkiro.git && cd shinkiro
make build
```

### 2. Launch TUI or headless daemon

```bash
./bin/shinkiro tui              # dry-run SOAR (default)
./bin/shinkiro tui --apply      # live firewall apply
./bin/shinkiro up               # headless
./bin/shinkiro up --geoip-db /var/lib/GeoIP/GeoLite2-City.mmdb
```

TUI keys (`?` for overlay): `↑↓` select · `Tab` panes · `b` block · `p` pcap · `s` simulate · `c` canary · `r` refresh · `q` quit.  
Guide: [`docs/operator-guide.md`](docs/operator-guide.md) · [`docs/architecture/tui-operator.md`](docs/architecture/tui-operator.md).

### 3. Simulate, canary, campaigns, feeds

```bash
./bin/shinkiro simulate --host 127.0.0.1
./bin/shinkiro canary generate --label canary-prod-seed
./bin/shinkiro campaigns --format table
./bin/shinkiro coverage
# ThreatFox / AbuseIPDB need API keys — see docs/threat-intel/threatfox-abuseipdb.md
```

### 4. SIEM exporters & firewall text

```bash
./bin/shinkiro cef
./bin/shinkiro syslog
./bin/shinkiro stix > /tmp/shinkiro-threats.json
./bin/shinkiro ecs
./bin/shinkiro export --format nftables --threshold 80
./bin/shinkiro kernel   # sample eBPF/nft script text — not a live loader
```

### 5. SOAR playbooks & on-demand PCAP

Events: **Event → Score → Correlate → Playbook → Sink**. See [`docs/architecture/event-pipeline.md`](docs/architecture/event-pipeline.md).

```yaml
# playbooks.yaml — real schema
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
```

| Mode | Enable | Behavior |
| :--- | :--- | :--- |
| Dry-run (**default**) | (nothing) | Logs `nftables`/`iptables` text; no exec |
| Live apply | `--apply` or `SHINKIRO_SOAR_APPLY=1` | Exec + optional `SHINKIRO_SOAR_BLOCK_WEBHOOK` |

PCAP: `ThreatScore >= SHINKIRO_PCAP_THRESHOLD` (default 80) → `SHINKIRO_PCAP_DIR` (default `data/pcap/`).

### 6. Docker Compose & Helm

```bash
make docker-build
make compose-lab     # or compose-edge / compose-up
make helm-lab        # prints install recipe
```

Details: [`deploy/README.md`](deploy/README.md) · [`deploy/modes/README.md`](deploy/modes/README.md).

### 7. Cluster hub (optional)

```bash
export SHINKIRO_CLUSTER_TOKEN="$(openssl rand -hex 32)"
./bin/shinkiro cluster hub --port 9090
```

Hub-and-spoke HTTP with token auth — **not** gossip. Guide: [`docs/architecture/cluster-hub.md`](docs/architecture/cluster-hub.md).

---

## Supply Chain & Runtime Hardening

What release CI **actually** does (`.github/workflows/release.yml`):

1. Cosign keyless **`sign-blob`** of `checksums.txt` → `checksums.bundle`
2. Syft SBOM: SPDX + CycloneDX on the GitHub Release
3. Optional GHCR when `PUSH_GHCR=true` → `ghcr.io/haiagari/shinkiro:<tag>` (+ `latest`)
4. **Not SLSA Level 3** — no provenance generator in this repo
5. Seccomp profile file at `deploy/security/seccomp.json` (operator-applied; not auto-enforced by the binary)

---

## Testing & Quality Assurance

```bash
make test
make fuzz
make e2e
go test -v -race ./tests/chaos
make bench   # local only; no bench.yml CI gate
```

---

## Documentation Index

Start at **[`docs/README.md`](docs/README.md)** (block navigation). Highlights:

| Doc | Topic |
| :--- | :--- |
| [Getting started](docs/getting-started.md) | Install, build, first run |
| [CLI reference](docs/cli-reference.md) | Every command / flag / env |
| [Operator guide](docs/operator-guide.md) | TUI, SOAR, PCAP, simulate |
| [Honesty & limitations](docs/honesty-limitations.md) | What is **not** implemented |
| [Event pipeline](docs/architecture/event-pipeline.md) | Stages, apply, PCAP |
| [Cluster hub](docs/architecture/cluster-hub.md) | Token, TLS, join/ingest |
| [Decoy matrix](docs/decoys/decoy-matrix.md) | 15 protocols + MITRE |
| [GeoLite2 GeoIP](docs/threat-intel/geolite2-geoip.md) | Optional MaxMind |
| [ThreatFox / AbuseIPDB](docs/threat-intel/threatfox-abuseipdb.md) | Feed CLIs |
| [Deploy](deploy/README.md) | Compose + Helm |
| [Development](docs/development.md) | e2e, fuzz, PR rules |
| [AGENTS.md](AGENTS.md) | Contributor/agent source of truth |

---

## License

AGPL-3.0-only © 2026 Haiagari Security.
