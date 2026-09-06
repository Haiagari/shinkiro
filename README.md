# 蜃気楼 Shinkiro

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

**Shinkiro (蜃気楼 — *mirage*)** is a single-binary cyber deception engine written in Go. It multiplexes lightweight, memory-jailed protocol emulators across common internet, cloud, and IoT attack surfaces.

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

See Mermaid diagram and remaining sections in docs hub. Full Quick Start, decoy table, supply chain, testing, and documentation index are maintained in-repo; this rewrite aligns README with post-roadmap honesty (hub-and-spoke cluster, SOAR dry-run, optional MaxMind, Linux-only prebuilts, eBPF exporter-only, 15 decoys).

## Quick Start

```bash
curl -sSL https://raw.githubusercontent.com/Haiagari/shinkiro/main/scripts/install.sh | sh
git clone https://github.com/Haiagari/shinkiro.git && cd shinkiro && make build
./bin/shinkiro tui
./bin/shinkiro up --apply
./bin/shinkiro simulate --host 127.0.0.1
make compose-lab
make e2e
```

**Pre-built binaries are Linux-only.** Docs: [`docs/getting-started.md`](docs/getting-started.md) · [`docs/cli-reference.md`](docs/cli-reference.md) · [`docs/operator-guide.md`](docs/operator-guide.md) · [`docs/honesty-limitations.md`](docs/honesty-limitations.md) · [`docs/README.md`](docs/README.md).

## License

AGPL-3.0-only © 2026 Haiagari Security.
