# Shinkiro Cyber Deception & Threat Intelligence Architecture

This document describes **what the code does today**. Where earlier drafts claimed live kernel XDP attachment, always-on/fake GeoIP, UDP gossip/mesh, or continuous packet mirroring, those claims are corrected below.

See also:
- [`event-pipeline.md`](event-pipeline.md) — Event → Score → Correlate → Playbook → Sink; SOAR dry-run/apply; on-demand PCAP
- [`cluster-hub.md`](cluster-hub.md) — hub-and-spoke HTTP cluster hub (token auth, TLS, join/ingest)
- [`../threat-intel/geolite2-geoip.md`](../threat-intel/geolite2-geoip.md) — optional MaxMind GeoLite2 enrichment

---

## 3. Deep In-Memory Multiplexer Architecture

The listener multiplexer (`internal/core/multiplexer.go`) is the primary network shock absorber:

- Strict read/write deadlines (config `idle_timeout`, default 30s) neutralize Slowloris-style holds.
- Fail-closed: malformed frames / unexpected EOF terminate the socket without internal error strings.
- PCAP: pipeline sink calls `OnDemandCapture.MaybeCapture` when `ThreatScore >=` threshold (default 80) — **threshold-gated on-demand**, not continuous socket mirroring.

---

## 4. eBPF / XDP — Sample C + Rule Exporters (Not a Live Loader)

| Artifact | What it is |
| :--- | :--- |
| `internal/ebpf/c/xdp_drop.c` | Sample XDP C — must be built/loaded with external tooling |
| `FilterManager.RenderScript()` / `shinkiro kernel` | Commented eBPF-oriented or nftables/iptables script text |
| `shinkiro export --format nftables\|iptables` | Firewall rule text |
| `shinkiro up --apply` / `SHINKIRO_SOAR_APPLY=1` | Optional live exec of generated commands (dry-run default) |

**Not implemented:** userspace XDP attach, `BPF_MAP_UPDATE`, line-rate hardware drop from `shinkiro up` alone.

---

## 5. Distributed Cluster — Hub-and-Spoke HTTP Hub

Multi-node support is a **hub-and-spoke HTTP hub**, not encrypted UDP gossip and not a peer mesh. Full operator notes: [`cluster-hub.md`](cluster-hub.md).

1. **Local autonomous execution:** Each sensor runs its own decoys and state.
2. **HTTP hub:** `shinkiro cluster hub` serves:
   - `GET /healthz`, `GET /readyz` — unauthenticated liveness/readiness (`model=hub-and-spoke-http`)
   - `POST /api/v1/cluster/join` — register `{id, address}`
   - `POST /api/v1/cluster/ingest` — JSON `intel.Event` bodies
   - `GET /api/v1/cluster/nodes` — registered node map
3. **Auth:** `SHINKIRO_CLUSTER_TOKEN` or `--token`. When set, join/ingest/nodes require `Authorization: Bearer` or `X-Shinkiro-Cluster-Token`. **Empty token = lab-only insecure mode.**
4. **TLS:** optional `--tls-cert` + `--tls-key`, or terminate TLS at a reverse proxy.
5. **Hardening:** read/write/idle timeouts, 1 MiB body limit, structured JSON errors, graceful shutdown.
6. **Not implemented:** Encrypted UDP gossip, automatic peer discovery, mesh membership, eBPF-cluster, or cross-node preemptive blackhole propagation.

```bash
export SHINKIRO_CLUSTER_TOKEN="$(openssl rand -hex 32)"
./bin/shinkiro cluster hub --port 9090
# spokes: Authorization: Bearer $SHINKIRO_CLUSTER_TOKEN on join + ingest
```

---

## 6. Production Deployment Topologies

### 6.1. Edge Perimeter Bastion (Public DMZ)
- Bind decoy ports from `services:`; export CEF/Syslog/STIX; apply nftables/iptables text or deliberate `--apply`.

### 6.2. Internal Lateral Movement Tripwire
- Deploy inside LANs / k8s workers; SOAR `alert` / `block_ip` notify SecOps. Helm scaffolding + lab/edge modes; optional GHCR when `PUSH_GHCR=true`.

### 6.3. OT / ICS SCADA Enclave
- Modbus/TCP `:502` (or remapped ports). Kernel XDP still requires **operator-managed** loading of sample C / exported rules.

---

## 7. GeoIP Enrichment (Optional MaxMind GeoLite2)

`internal/intel/geoip.Resolver` loads a local MaxMind `.mmdb` from `SHINKIRO_GEOLITE2_PATH` or `--geoip-db`.

- **Unset / missing path:** no-op enrichment; logs `GeoIP disabled` once. Product works without GeoIP.
- **City / Country / ASN DB:** fills `geo_country` / `geo_city` / `geo_asn` / `geo_org` when present — **never invents coordinates** or heuristic octet countries.
- **Private / loopback:** tagged `LOCAL` (not MaxMind attribution).
- Ops test: `shinkiro geoip --ip 1.2.3.4`. Full guide: [`geolite2-geoip.md`](../threat-intel/geolite2-geoip.md).
