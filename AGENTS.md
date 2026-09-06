# AGENTS.md — Shinkiro Project Architecture & Guidelines

**Scope:** [Haiagari/shinkiro](https://github.com/Haiagari/shinkiro) — Ephemeral Cyber Deception & Attacker Intelligence Mesh.

Use this file as the **source of truth for agents and contributors**. Prefer code under `internal/` and `cmd/` over marketing language elsewhere.

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
| GeoIP | Heuristic / demo prefix resolver (`internal/intel/geoip`) — **not** MaxMind |
| Cluster | HTTP ingest hub (`internal/cluster`) — **not** encrypted UDP gossip |
| Event pipeline | `internal/pipeline` — Event → Score → Correlate → Playbook → Sink (wired in `up`/`tui`) |
| PCAP | On-demand high-score capture (`internal/pcap.OnDemandCapture`) wired into pipeline sink — **not** continuous mirror |
| User Interface | Bubbletea TUI (`shinkiro tui`) & headless daemon (`shinkiro up`) |
| Supply chain | Cosign `sign-blob` on checksums + Syft SBOM — **not** SLSA Level 3 |

---

## 2. Directory Layout & Architecture

```text
shinkiro/
├── cmd/
│   └── shinkiro/             # CLI: up, tui, simulate, export, kernel/ebpf,
│                             #      cef/syslog/stix/ecs, canary, cluster hub, version
├── config.yaml               # Runtime config — top-level key is services:
├── playbooks.yaml            # SOAR-lite rules: rules / if / then / block_ip|alert
├── deploy/
│   ├── docker/               # Dockerfile + docker-compose (image publish gaps → deploy PR)
│   ├── helm/shinkiro/        # Helm chart (GHCR/path/config limitations → deploy PR)
│   ├── security/seccomp.json # Operator-applied seccomp profile
│   ├── systemd/              # systemd unit
│   ├── ansible/ prometheus/ grafana/ terraform/
├── internal/
│   ├── adversary/            # Red-team simulate scenarios
│   ├── canary/               # HMAC-style canary token helpers
│   ├── cluster/              # HTTP ingest hub (not UDP gossip)
│   ├── config/               # YAML & CLI parameters (services: map)
│   ├── core/                 # Listener multiplexer, deadlines; optional Benchmark*
│   ├── decoys/
│   │   ├── decoy.go          # Unified Decoy interface
│   │   ├── aws/ dns/ docker/ elastic/ http/ k8s/
│   │   ├── modbus/ mongo/ mqtt/ postgres/ redis/
│   │   ├── smb/ smtp/ ssh/ telnet/
│   ├── defense/              # iptables & nftables rule text generator
│   ├── ebpf/                 # Rule script renderer + sample C (internal/ebpf/c/xdp_drop.c)
│   ├── intel/                # Telemetry, scoring, MITRE, correlator
│   │   ├── ecs/ geoip/ siem/ stix/
│   ├── metrics/              # Prometheus metrics helper
│   ├── pcap/                 # Libpcap writer + on-demand high-score capture
│   ├── pipeline/             # Event → Score → Correlate → Playbook → Sink bus
│   ├── soar/                 # Playbook engine + block_ip dry-run/apply
│   ├── tui/                  # Bubbletea live adversary dashboard
│   └── webhook/              # Slack / Discord notification helpers
├── scripts/install.sh        # Downloads real release asset names
├── tests/chaos tests/e2e     # Chaos spike + e2e packages
├── Makefile                  # build, test, lint, bench, fuzz
└── README.md
```

---

## 3. Mandatory Engineering Rules

- **Conventional Commits**: `feat(scope):`, `fix(scope):`, `docs(scope):`, etc.
- **Zero Attribution**: Never include `Co-Authored-By` or AI trailer lines.
- **Fail-Closed**: Any unhandled network error must cleanly terminate the socket without exposing host details.
- **Zero Host Mutation**: Decoys must execute purely in memory; never spawn host OS processes or touch real filesystem paths for attacker commands.
- **Honest docs**: Do not claim live eBPF loaders, MaxMind GeoIP, UDP gossip mesh, continuous in-pipeline PCAP mirroring, SLSA L3, or GHCR Helm one-liners unless the code/CI lands first. SOAR live firewall apply requires explicit `--apply` / `SHINKIRO_SOAR_APPLY=1`.
- **Comprehensive Unit Testing**: Protocol parsers should be tested via in-memory pipes (`net.Pipe()`) where practical.
- **Config key**: Runtime YAML uses `services:` — examples and matrix docs must match.
