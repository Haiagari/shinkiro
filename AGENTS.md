# AGENTS.md — Shinkiro Project Architecture & Guidelines

**Scope:** [Haiagari/shinkiro](https://github.com/Haiagari/shinkiro) — Ephemeral Cyber Deception & Attacker Intelligence Mesh.

Use this file as the **source of truth for agents and contributors**. Prefer code under `internal/` and `cmd/` over marketing language elsewhere. Documentation hub: [`docs/README.md`](docs/README.md). Honesty contract: [`docs/honesty-limitations.md`](docs/honesty-limitations.md).

---

## 1. Product Truth

| Dimension | Specification |
|---|---|
| Product | **Shinkiro (蜃気楼)** |
| Language | **Go 1.24+** |
| License | **AGPL-3.0-only** |
| Core Philosophy | Zero-footprint in-memory decoys, fail-closed sockets, live telemetry |
| Protocol Decoys (**15**) | SSH, Telnet, MQTT, SMB, Redis, Docker, HTTP, PostgreSQL, Kubernetes, AWS IMDS, MongoDB, Elasticsearch, SMTP, DNS, Modbus |
| Active Defense | **Text exporters** for `iptables` / `nftables` / sample eBPF scripts; SOAR-lite `block_ip` / `alert` — dry-run default, live apply only with `--apply` / `SHINKIRO_SOAR_APPLY=1` — **not** a live kernel BPF loader |
| GeoIP | Optional MaxMind GeoLite2 (`SHINKIRO_GEOLITE2_PATH` / `--geoip-db`); no-op when unset — **never invents coordinates** |
| Cluster | Hub-and-spoke HTTP hub (`internal/cluster`) with optional `SHINKIRO_CLUSTER_TOKEN` — **not** gossip / mesh / eBPF-cluster |
| Event pipeline | `internal/pipeline` — Event → Score → Correlate → Playbook → Sink (wired in `up`/`tui`) |
| Correlator | v2 rule-based (same IP + window + hop path) — **not ML**; CLI `campaigns` |
| Feeds | ThreatFox + AbuseIPDB HTTP CLIs (real keys; graceful fail if missing) |
| ATT&CK coverage | `coverage` / `attack-coverage` from decoy-matrix (+ optional runtime mapper) |
| PCAP | On-demand high-score + operator `CaptureNow` — **not** continuous mirror |
| User Interface | Bubbletea TUI (`shinkiro tui`) & headless daemon (`shinkiro up`) |
| Deploy | Compose/Helm **lab** and **edge** modes; optional GHCR if `PUSH_GHCR=true` |
| Prebuilt | **Linux amd64/arm64 only** |
| Supply chain | Cosign `sign-blob` on checksums + Syft SBOM — **not** SLSA Level 3 |

---

## 2. Directory Layout & Architecture

```text
shinkiro/
├── cmd/shinkiro/             # CLI: up, tui, simulate, export, kernel/ebpf,
│                             #      cef/syslog/stix/ecs, canary, cluster hub,
│                             #      campaigns, threatfox, abuseipdb, coverage, geoip, version
├── config.yaml               # Runtime config — top-level key is services:
├── playbooks.yaml            # SOAR-lite rules: rules / if / then / block_ip|alert
├── deploy/
│   ├── docker/               # Dockerfile + compose + lab/edge overlays
│   ├── helm/shinkiro/        # Helm chart + values-lab/edge
│   ├── modes/                # lab/ vs edge/ config+playbooks
│   ├── security/seccomp.json # Operator-applied seccomp profile
│   ├── systemd/ ansible/ prometheus/ grafana/ terraform/
├── docs/                     # Operator + architecture docs (see docs/README.md)
├── internal/
│   ├── adversary/            # Red-team simulate scenarios
│   ├── canary/               # HMAC-style canary token helpers
│   ├── cluster/              # Hub-and-spoke HTTP hub + AgentClient (not UDP gossip)
│   ├── config/               # YAML & CLI parameters (services: map)
│   ├── core/                 # Listener multiplexer, deadlines; optional Benchmark*
│   ├── decoys/               # 15 protocol emulators
│   ├── defense/              # iptables & nftables rule text generator
│   ├── ebpf/                 # Rule script renderer + sample C (NOT live loader)
│   ├── intel/                # Telemetry, scoring, MITRE, correlator v2, feeds, coverage
│   │   ├── ecs/ geoip/ siem/ stix/
│   ├── metrics/              # Prometheus metrics helper
│   ├── pcap/                 # Libpcap writer + on-demand high-score capture
│   ├── pipeline/             # Event → Score → Correlate → Playbook → Sink bus
│   ├── soar/                 # Playbook engine + block_ip dry-run/apply
│   ├── tui/                  # Bubbletea live adversary dashboard
│   └── webhook/              # Slack / Discord notification helpers
├── scripts/install.sh        # Downloads real release asset names (Linux only)
├── tests/chaos tests/e2e     # Chaos spike + all-15-decoys e2e
├── Makefile                  # build, test, lint, bench, fuzz, e2e, compose-*, helm-*
└── README.md
```

---

## 3. Mandatory Engineering Rules

- **Conventional Commits**: `feat(scope):`, `fix(scope):`, `docs(scope):`, etc.
- **Zero Attribution**: Never include `Co-Authored-By` or AI trailer lines.
- **Fail-Closed**: Any unhandled network error must cleanly terminate the socket without exposing host details.
- **Zero Host Mutation**: Decoys must execute purely in memory; never spawn host OS processes or touch real filesystem paths for attacker commands.
- **Honest docs**: Do not claim live eBPF loaders, always-on GeoIP without a configured `.mmdb`, invented coordinates, UDP gossip mesh, continuous in-pipeline PCAP mirroring, SLSA L3, ML correlator, or GHCR Helm one-liners unless the code/CI lands first. Optional MaxMind GeoLite2 when `SHINKIRO_GEOLITE2_PATH` / `--geoip-db` points at a real DB. Cluster is hub-and-spoke HTTP with optional token — empty `SHINKIRO_CLUSTER_TOKEN` is lab-only insecure. SOAR live firewall apply requires explicit `--apply` / `SHINKIRO_SOAR_APPLY=1`. Do **not** implement a live eBPF loader unless a dedicated roadmap PR says so (exporter only).
- **Comprehensive Unit Testing**: Protocol parsers should be tested via in-memory pipes (`net.Pipe()`) where practical.
- **Config key**: Runtime YAML uses `services:` — examples and matrix docs must match.
- **Playbooks**: Real schema is `rules` / `if` / `then` with `block_ip` / `alert` / `tag`.
- **Docs language**: Prefer thorough **English** docs (codebase language) unless an existing Spanish file must stay consistent.
- **Docs index**: New user-facing markdown should be linked from `docs/README.md`.

---

## 4. Documentation blocks (post #10–#16)

When rewriting docs, cover:

1. Getting started / install / release  
2. Architecture (pipeline, decoys, correlator, cluster hub)  
3. Operator guide (TUI, SOAR, PCAP, simulate/canary)  
4. Threat intel (feeds, GeoIP, STIX/MISP exporters)  
5. Deploy (compose lab/edge, Helm, GHCR)  
6. CLI reference (every command with flags)  
7. Development / e2e / contributing  
8. Honesty / limitations  

Never ship placeholder or "TODO fill later" stubs.
