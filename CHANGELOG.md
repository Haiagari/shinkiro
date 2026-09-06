# Changelog

All notable changes to **Shinkiro** are documented in this file following [Keep a Changelog](https://keepachangelog.com/) and [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- `scripts/install.sh` now downloads real GitHub Release assets (`shinkiro-linux-amd64` / `shinkiro-linux-arm64`), verifies `checksums.txt` when present, and no longer falls back to nonexistent `v0.2.0` or GoReleaser-style `shinkiro_${VER}_${os}_${arch}.tar.gz` names.

### Documentation
- **Honesty pass:** README, AGENTS.md, architecture, benchmarks, decoy matrix, threat-intel, and threat-scoring docs aligned with implemented behavior:
  - eBPF/XDP described as rule exporters + sample C (`internal/ebpf`), not a live kernel loader / `BPF_MAP_UPDATE`.
  - GeoIP described as demo/heuristic prefixes, not MaxMind.
  - Cluster described as HTTP ingest hub, not encrypted UDP gossip.
  - PCAP writer package noted as present but **not wired** into `main` / multiplexer.
  - Supply chain described as Cosign `sign-blob` on checksums + Syft SBOM only (no SLSA Level 3 claim).
  - Invented benchmark tables / nonexistent `bench.yml` gate removed; point to real `Benchmark*` and `tests/chaos`.
  - Playbook examples match real `rules` / `if` / `then` / `block_ip` schema.
  - Config examples use `services:` (runtime key), not `decoys:`.
  - Helm one-liner notes image/path/config limitations until a dedicated deploy PR.
  - Removed static `tests-passing` badge that was not CI-linked.

## [v1.0.0] - 2026-09-05

### Added
- **Modbus/TCP Industrial Decoy (`:502`)**: ICS/SCADA PLC emulator supporting MBAP framing, holding registers, coils, and MITRE for ICS `T0855` mapping.
- **SOAR-Lite Playbook Automation Engine**: Declarative YAML playbooks (`playbooks.yaml`) with `rules` / `if` / `then` actions (`block_ip`, `alert`, `tag`).
- **Enterprise SIEM Exporters**: ArcSight CEF, RFC5424 Syslog, Elastic Common Schema (ECS v8.x), STIX 2.1, and ThreatFox-oriented feed helpers.
- **Multi-Protocol Campaign Correlator**: Cross-protocol adversary session aggregation with scoring and velocity multipliers.
- **Kubernetes Helm Chart (scaffolding)**: Chart under `deploy/helm/shinkiro` with strict securityContext fields; image registry / config wiring still limited (see Unreleased honesty note).
- **Fuzzing Suite**: Native Go fuzz tests (`testing.F`) across selected protocol parsers via `make fuzz`.
- **Supply Chain Artifacts**: Sigstore Cosign keyless **`sign-blob`** on `checksums.txt`, Anchore Syft SBOM (SPDX & CycloneDX). Does **not** include SLSA Level 3 provenance attestations.
- **Telnet IoT Botnet Decoy (`:2323`)**: BusyBox-style embedded Linux router, IAC negotiation, Mirai-style credential capture.
- **MQTT Broker Decoy (`:1883`)**: MQTT v3.1.1 protocol parser trapping unauthorized IoT client connections.
- **PCAP Writer Package**: Libpcap 2.4 format writer (`internal/pcap`) for optional forensic dumps — **not yet wired** into the live multiplexer / `cmd/shinkiro` path.
- **SMB/CIFS Decoy (`:4445`)**: NetBIOS session and SMBv2 negotiate parser for EternalBlue-style reconnaissance.
- **Decoys Matrix Documentation**: MITRE ATT&CK mapping and threat score taxonomy in `docs/decoys/decoy-matrix.md`.

## [v0.4.0] - 2026-09-05

### Note
- Tag `v0.4.0` was published with linux amd64/arm64 release binaries, checksums, SBOMs, and cosign artifacts. This changelog section records that release for Keep-a-Changelog continuity.

### Added (at tag time)
- Release assets and supply-chain artifacts for the v0.4.0 cut (binaries + checksums + Syft SBOM + Cosign checksum bundle).

## [v0.2.0] - 2026-09-04

### Added
- **AWS IMDS Decoy (`:8169`)**: EC2 Instance Metadata Service emulator (IMDSv1 & IMDSv2) for SSRF traps targeting IAM role credential paths.
- **Sample C eBPF / XDP Filter + Go Rule Exporter**: Sample program at `internal/ebpf/c/xdp_drop.c` and Go `FilterManager.RenderScript()` emitting rule text — not a userspace live loader.
- **STIX 2.1 Threat Intelligence Exporter**: `shinkiro stix` transforming observed honeypot interactions into STIX 2.1 JSON bundles.
- **Heuristic GeoIP Resolver**: Offline demo/prefix-based enrichment (`internal/intel/geoip`) — not a MaxMind database engine.
- **Distributed Cluster HTTP Hub**: Multi-node HTTP aggregation (`shinkiro cluster hub`) for edge sensors to POST events to a central ingest endpoint.

## [v0.1.0] - 2026-09-04

### Added
- Initial release of Shinkiro deception engine in Go.
- Core Multiplexer and in-memory decoys (SSH, Redis, Docker, HTTP, PostgreSQL, K8s).
- Live Bubbletea Terminal Dashboard (`shinkiro tui`).
- Dynamic firewall mitigation **text export** (`iptables`, `nftables`).
