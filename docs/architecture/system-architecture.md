# Shinkiro Cyber Deception & Threat Intelligence Architecture

This document describes **what the code does today** (post PRs #10–#16). Where earlier drafts claimed live kernel XDP attachment, always-on/fake GeoIP, UDP gossip/mesh, or continuous packet mirroring, those claims are corrected below.

See also:

- [`../README.md`](../README.md) — documentation hub  
- [`event-pipeline.md`](event-pipeline.md) — Event → Score → Correlate → Playbook → Sink; SOAR dry-run/apply; on-demand PCAP  
- [`cluster-hub.md`](cluster-hub.md) — hub-and-spoke HTTP cluster hub (token auth, TLS, join/ingest)  
- [`campaign-correlator-v2.md`](campaign-correlator-v2.md) — rule-based campaigns  
- [`tui-operator.md`](tui-operator.md) — operator dashboard  
- [`../threat-intel/geolite2-geoip.md`](../threat-intel/geolite2-geoip.md) — optional MaxMind GeoLite2  
- [`../diagrams/architecture-darkmode.svg`](../diagrams/architecture-darkmode.svg) — **canonical** dual-plane architecture diagram (honesty-aligned)
- [`../honesty-limitations.md`](../honesty-limitations.md) — explicit non-goals  

---

## 1. High-level data flow

```text
 Adversary ──► Multiplexer ──► 15 Decoys ──► chan Event
                                              │
                    ┌──────────────────────────┘
                    ▼
         Pipeline Bus (internal/pipeline)
           Score → Correlate → Playbook → Sink
                    │              │         │
                 MITRE+GeoIP   SOAR rules   metrics / webhook /
                 correlator v2  block_ip    on-demand PCAP /
                               dry-run|apply JSONL / TUI fan-out
```

CLI entrypoints `shinkiro up` and `shinkiro tui` (`cmd/shinkiro/up.go`) register all fifteen decoys, construct GeoIP resolver, SOAR engine + BlockApplier, PCAP hook, and the bus.

---

## 2. Deep In-Memory Multiplexer Architecture

The listener multiplexer (`internal/core/multiplexer.go`) is the primary network shock absorber:

- Strict read/write deadlines (config `idle_timeout`, default 30s) neutralize Slowloris-style holds.
- Fail-closed: malformed frames / unexpected EOF terminate the socket without internal error strings.
- PCAP: pipeline sink calls `OnDemandCapture.MaybeCapture` when `ThreatScore >=` threshold (default 80) — **threshold-gated on-demand**, not continuous socket mirroring. TUI can call `CaptureNow` for operator-triggered captures.

---

## 3. Protocol decoys (15)

Each decoy implements the unified decoy interface under `internal/decoys/<name>/`. Runtime enablement and ports come from `config.yaml` top-level **`services:`**. Matrix + MITRE: [`../decoys/decoy-matrix.md`](../decoys/decoy-matrix.md).

---

## 4. eBPF / XDP — Sample C + Rule Exporters (Not a Live Loader)

| Artifact | What it is |
| :--- | :--- |
| `internal/ebpf/c/xdp_drop.c` | Sample XDP C — must be built/loaded with external tooling |
| `FilterManager.RenderScript()` / `shinkiro kernel` | Commented eBPF-oriented or nftables/iptables script text |
| `shinkiro export --format nftables\|iptables` | Firewall rule text from scored IPs |
| `shinkiro up --apply` / `SHINKIRO_SOAR_APPLY=1` | Optional live exec of generated firewall commands (dry-run default) |

**Not implemented:** userspace XDP attach, `BPF_MAP_UPDATE`, line-rate hardware drop from `shinkiro up` alone. Do not implement a live loader in drive-by PRs.

---

## 5. Distributed Cluster — Hub-and-Spoke HTTP Hub

Multi-node support is a **hub-and-spoke HTTP hub**, not encrypted UDP gossip and not a peer mesh. Full operator notes: [`cluster-hub.md`](cluster-hub.md).

1. **Local autonomous execution:** Each sensor runs its own decoys and state.
2. **HTTP hub:** `shinkiro cluster hub` serves `/healthz`, `/readyz`, join, ingest, nodes.
3. **Auth:** `SHINKIRO_CLUSTER_TOKEN` or `--token`. Empty token = **lab-only insecure**.
4. **TLS:** optional `--tls-cert` + `--tls-key`, or terminate at a reverse proxy.
5. **Hardening:** timeouts, 1 MiB body limit, structured JSON errors, graceful shutdown.
6. **Not implemented:** Gossip, automatic peer discovery, mesh membership, eBPF-cluster, cross-node preemptive blackhole propagation.

```bash
export SHINKIRO_CLUSTER_TOKEN="$(openssl rand -hex 32)"
./bin/shinkiro cluster hub --port 9090
```

---

## 6. Production Deployment Topologies

### 6.1. Edge Perimeter Bastion (Public DMZ)

- Bind decoy ports from `services:`; export CEF/Syslog/STIX; apply nftables/iptables text or deliberate `--apply`.
- Prefer `make compose-edge` / Helm values-edge for quieter thresholds and hardened caps.

### 6.2. Internal Lateral Movement Tripwire

- Deploy inside LANs / k8s workers; SOAR `alert` / `block_ip` notify SecOps. Optional GHCR when `PUSH_GHCR=true`.

### 6.3. OT / ICS SCADA Enclave

- Modbus/TCP `:502` (or remapped ports). Kernel XDP still requires **operator-managed** loading of sample C / exported rules.

Deploy reference: [`../../deploy/README.md`](../../deploy/README.md).

---

## 7. GeoIP Enrichment (Optional MaxMind GeoLite2)

`internal/intel/geoip.Resolver` loads a local MaxMind `.mmdb` from `SHINKIRO_GEOLITE2_PATH` or `--geoip-db`.

- **Unset / missing path:** no-op enrichment; logs `GeoIP disabled` once. Product works without GeoIP.
- **City / Country / ASN DB:** fills `geo_country` / `geo_city` / `geo_asn` / `geo_org` when present — **never invents coordinates** or heuristic octet countries.
- **Private / loopback:** tagged `LOCAL` (not MaxMind attribution).
- Ops test: `shinkiro geoip --ip 1.2.3.4`.

---

## 8. Observability

- JSONL audit log (`audit_log_path`, default `data/events.jsonl`)
- Prometheus helper endpoint on `metrics_port` (default `9100`)
- Optional `SHINKIRO_WEBHOOK_URL` for critical alerts
- SIEM exporters: `cef`, `syslog`, `ecs`, `stix`
