# Shinkiro Cyber Deception & Threat Intelligence Architecture

This document describes **what the code does today**. Where earlier drafts claimed live kernel XDP attachment, MaxMind GeoIP, UDP gossip/mesh, or continuous packet mirroring, those claims are corrected below.

See also:
- [`event-pipeline.md`](event-pipeline.md) — Event → Score → Correlate → Playbook → Sink
- [`cluster-hub.md`](cluster-hub.md) — hub-and-spoke HTTP cluster (token auth, TLS)

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
# agents: POST /api/v1/cluster/join and /ingest with Authorization: Bearer $SHINKIRO_CLUSTER_TOKEN
```

---

## Other architecture notes (unchanged honesty)

- **Multiplexer:** strict deadlines, fail-closed sockets (`internal/core`).
- **PCAP:** on-demand threshold-gated capture via pipeline sink — not continuous mirror.
- **eBPF/XDP:** sample C + `RenderScript` text exporters — not a live kernel loader / `BPF_MAP_UPDATE`.
- **GeoIP:** heuristic / demo prefixes — not MaxMind.
- **SOAR block_ip:** dry-run default; live only with `--apply` / `SHINKIRO_SOAR_APPLY=1`.

For full mermaid topology diagrams previously in this file, prefer regenerating from the live package map under `internal/` and the guides linked above rather than treating marketing diagrams as source of truth.
