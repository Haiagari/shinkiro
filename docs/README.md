# Shinkiro Documentation Index

**Product:** [Haiagari/shinkiro](https://github.com/Haiagari/shinkiro) — Ephemeral Cyber Deception & Attacker Intelligence Mesh  
**Base (post PR #16):** documented against `main` tip after MaxMind GeoIP, cluster hub auth, lab/edge deploy, correlator v2, TUI operator actions, and unified event pipeline.  
**Language:** English (matches codebase and prior honesty PRs).

This hub organizes operator and contributor docs by **blocks**. Prefer code under `cmd/` and `internal/` over marketing language elsewhere. See also [Honesty & Limitations](honesty-limitations.md).

---

## Block map

| Block | Start here | Contents |
| :--- | :--- | :--- |
| **Getting started** | [getting-started.md](getting-started.md) | Linux install script, build from source, first `up`/`tui`, release assets, Cosign/SBOM |
| **Architecture** | [architecture/system-architecture.md](architecture/system-architecture.md) | Multiplexer, pipeline, decoys, correlator, cluster hub, rule exporters |
| **Operator guide** | [operator-guide.md](operator-guide.md) | TUI keys, SOAR dry-run/apply, PCAP, simulate, canary |
| **Threat intel** | [threat-intel/stix-misp-integration.md](threat-intel/stix-misp-integration.md) | STIX/CEF/Syslog/ECS, ThreatFox/AbuseIPDB, optional GeoIP, ATT&CK coverage |
| **Deploy** | [../deploy/README.md](../deploy/README.md) | Compose lab/edge, Helm, GHCR optional, systemd/ansible pointers |
| **CLI reference** | [cli-reference.md](cli-reference.md) | Every command, flags, and env vars |
| **Development** | [development.md](development.md) | Make targets, e2e, fuzz, chaos, contributing |
| **Honesty** | [honesty-limitations.md](honesty-limitations.md) | What is **not** implemented (gossip, SLSA L3, live eBPF loader, …) |

---

## Architecture

| Document | Summary |
| :--- | :--- |
| [system-architecture.md](architecture/system-architecture.md) | End-to-end topology; honesty corrections |
| [event-pipeline.md](architecture/event-pipeline.md) | Event → Score → Correlate → Playbook → Sink; SOAR; PCAP |
| [cluster-hub.md](architecture/cluster-hub.md) | Hub-and-spoke HTTP; token; TLS; join/ingest |
| [campaign-correlator-v2.md](architecture/campaign-correlator-v2.md) | Rule-based campaigns, hop path, CLI |
| [threat-scoring.md](architecture/threat-scoring.md) | Scores, MITRE, playbooks schema, exporters |
| [tui-operator.md](architecture/tui-operator.md) | Dashboard keybindings and operator actions |
| [../docs/api/architecture-overview.md](api/architecture-overview.md) | Package map + CLI surface |

## Decoys

| Document | Summary |
| :--- | :--- |
| [decoy-matrix.md](decoys/decoy-matrix.md) | All **15** protocols, ports, MITRE tags, config `services:` |

## Threat intelligence

| Document | Summary |
| :--- | :--- |
| [stix-misp-integration.md](threat-intel/stix-misp-integration.md) | STIX 2.1, CEF, Syslog, ECS, MISP/OpenCTI patterns |
| [threatfox-abuseipdb.md](threat-intel/threatfox-abuseipdb.md) | Live HTTP feed CLIs + API keys |
| [geolite2-geoip.md](threat-intel/geolite2-geoip.md) | Optional MaxMind GeoLite2; works without DB |

## Deploy & modes

| Document | Summary |
| :--- | :--- |
| [../deploy/README.md](../deploy/README.md) | Compose + Helm primary paths |
| [../deploy/modes/README.md](../deploy/modes/README.md) | lab vs edge overlays |
| [deploy-modes-e2e-ghcr.md](deploy-modes-e2e-ghcr.md) | Modes + `make e2e` + optional GHCR |

## CLI & operators

| Document | Summary |
| :--- | :--- |
| [cli-reference.md](cli-reference.md) | Full command/flag/env reference |
| [cli-campaigns-feeds-coverage.md](cli-campaigns-feeds-coverage.md) | Campaigns, ThreatFox, AbuseIPDB, ATT&CK coverage |
| [operator-guide.md](operator-guide.md) | Day-2 operator loop |

## Development & quality

| Document | Summary |
| :--- | :--- |
| [development.md](development.md) | Tests, fuzz, e2e, PR expectations |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Contribution workflow |
| [../AGENTS.md](../AGENTS.md) | Agent/contributor source of truth |
| [benchmarks/performance.md](benchmarks/performance.md) | How to run real benches — no invented SLAs |

## Root pointers

- [README.md](../README.md) — product overview + Quick Start  
- [CHANGELOG.md](../CHANGELOG.md) — Keep a Changelog (Unreleased accurate)  
- [LICENSE](../LICENSE) — AGPL-3.0-only  

---

## Diagrams

- [`diagrams/architecture-darkmode.jpg`](diagrams/architecture-darkmode.jpg) / [`.svg`](diagrams/architecture-darkmode.svg) — high-level topology artwork (illustrative; code wins on details).
