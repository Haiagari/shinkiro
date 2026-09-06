# Shinkiro System Architecture & Technical Specification

**Product:** Shinkiro (蜃気楼)  
**License:** AGPL-3.0-only  
**Language:** Go 1.24+ (single binary)

---

## 1. System Design Goals & Principles

1. **Zero Host Mutation:** Deceptive protocols must not execute host binaries or write attacker-controlled files for shell semantics. State stays in synthetic in-memory structures.
2. **Fail-Closed Security Posture:** Malformed frames / parser failures terminate the socket without stack traces to the client.
3. **Measurable Hot Path:** Prefer measured `go test -bench` results over undocumented SLA nanoseconds.
4. **Actionable SOC Interoperability:** CEF, Syslog, STIX 2.1, ECS exporters; MITRE tagging.
5. **Exportable Active Defense:** nftables/iptables/sample eBPF **text** + SOAR `block_ip` / `alert` — not a silent live XDP attach.

---

## 2. Component Topology & Data Flow

See `docs/architecture/system-architecture.md` and `docs/architecture/cluster-hub.md` for current diagrams.

---

## 3. Package & Module Architecture

```text
internal/
├── adversary/          # Automated red-team simulate suite
├── canary/             # Canary token helpers
├── cluster/            # Hub-and-spoke HTTP hub + token auth (NOT gossip/mesh)
├── config/             # YAML parser — runtime key services:
├── core/               # Multiplexer & connection lifecycle; Benchmark* tests
├── decoys/             # Unified Decoy interface & 15 protocol emulators
│   ├── aws/ dns/ docker/ elastic/ http/ k8s/
│   ├── modbus/ mongo/ mqtt/ postgres/ redis/
│   ├── smb/ smtp/ ssh/ telnet/
├── defense/            # iptables & nftables ruleset text generator
├── ebpf/               # Sample C + RenderScript exporter (NOT live loader)
├── intel/              # Telemetry, scoring, MITRE, correlator
│   ├── ecs/            # ECS serializer
│   ├── geoip/          # Optional MaxMind GeoLite2 (path via env/flag; no-op if unset)
│   ├── siem/           # CEF & Syslog exporters
│   └── stix/           # STIX 2.1 bundle generator
├── metrics/            # Prometheus helpers
├── pcap/               # Libpcap 2.4 writer + on-demand capture
├── pipeline/           # Event → Score → Correlate → Playbook → Sink
├── soar/               # Playbook engine (block_ip, alert, tag)
├── tui/                # Bubbletea dashboard
└── webhook/            # Slack / Discord helpers
```

---

## 4. Operational CLI Interface

```bash
shinkiro up [--config config.yaml] [--apply]
shinkiro tui [--apply]
shinkiro cef
shinkiro syslog
shinkiro ecs
shinkiro stix
shinkiro export --format nftables     # text export
shinkiro export --format iptables     # text export
shinkiro kernel                       # sample eBPF / rule script text
shinkiro canary generate --label prod-cluster-secret
shinkiro simulate --host 127.0.0.1
shinkiro cluster hub [--port 9090] [--token SECRET] [--tls-cert PATH] [--tls-key PATH]
shinkiro geoip --ip 1.2.3.4 [--geoip-db PATH]   # optional MaxMind lookup
shinkiro up [--apply] [--geoip-db PATH]
# Hub-and-spoke HTTP (not gossip/mesh). Empty SHINKIRO_CLUSTER_TOKEN = lab-only insecure.
```

---

## 5. Security & Runtime Hardening

- **Seccomp file:** `deploy/security/seccomp.json` for operators to apply.
- **Cluster token:** set `SHINKIRO_CLUSTER_TOKEN` for join/ingest auth; empty = lab-only insecure.
- **Supply chain:** Releases build with `-trimpath` / stripped ldflags; Cosign **`sign-blob`** on `checksums.txt`; Syft SPDX + CycloneDX SBOMs. **No SLSA Level 3 provenance workflow.**
- **Fuzzing:** Selected `testing.F` targets via `make fuzz`.
- **Deploy:** Dockerfile and Helm chart with lab/edge modes; optional GHCR when `PUSH_GHCR=true`.

---

## 6. Go Package Integration

Prefer copying patterns from `cmd/shinkiro/` — authoritative wiring for decoys, SOAR, metrics, cluster hub, and exporters. Public/internal APIs evolve with the binary; do not invent alternate constructor signatures in docs without checking the source.

---

## 7. Metrics & Observability (`:9100/metrics`)

Prometheus helpers live under `internal/metrics`. Treat metric names in dashboards as best-effort documentation — verify exporters in code before depending on a specific time series (including any historical `shinkiro_ebpf_drops_total` style counters that implied a live XDP path).
