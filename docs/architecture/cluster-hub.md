# Cluster Hub (Hub-and-Spoke HTTP)

Shinkiro's multi-node support is a **central HTTP hub** that remote sensors join and POST events to. It is **not** encrypted UDP gossip, **not** a peer mesh, and **not** an eBPF/kernel cluster fabric.

Package: `internal/cluster`  
CLI: `shinkiro cluster hub`

## Model

```text
  [sensor A] --HTTP POST join/ingest--> +---------+
  [sensor B] --HTTP POST join/ingest--> |  Hub    |  --> events channel (operator wires sink)
  [sensor C] --HTTP POST join/ingest--> +---------+
```

- **Hub:** one process (`shinkiro cluster hub`) listening on a port (default `:9090`).
- **Spokes / agents:** any HTTP client (curl, `cluster.AgentClient`, custom forwarder) that can POST JSON.
- **Honesty:** empty `SHINKIRO_CLUSTER_TOKEN` = **lab-only insecure mode** (no auth). Set a token for anything beyond local demos.

## Endpoints

| Method | Path | Auth when token set | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/healthz` | no | Liveness |
| `GET` | `/readyz` | no | Readiness + `auth_mode` / `tls` / `model` |
| `POST` | `/api/v1/cluster/join` | yes | Register `{ "id", "address" }` |
| `POST` | `/api/v1/cluster/ingest` | yes | Ingest JSON `intel.Event` |
| `GET` | `/api/v1/cluster/nodes` | yes | Registered node map |

Auth headers (either):

- `Authorization: Bearer <token>`
- `X-Shinkiro-Cluster-Token: <token>`

Errors are JSON: `{ "error": "...", "message": "..." }`.

Hardening built in: read/write/idle timeouts, 1 MiB body cap (`MaxBytesReader`), structured errors, graceful shutdown on context cancel.

## Run the hub

```bash
# Lab / local (INSECURE — no token)
./bin/shinkiro cluster hub --port 9090

# Production-ish: shared secret via env
export SHINKIRO_CLUSTER_TOKEN="$(openssl rand -hex 32)"
./bin/shinkiro cluster hub --port 9090

# Or flag (overrides env when non-empty)
./bin/shinkiro cluster hub --port 9090 --token "$SHINKIRO_CLUSTER_TOKEN"

# Optional native HTTPS (or terminate TLS at nginx/Caddy/envoy instead)
./bin/shinkiro cluster hub --port 9443 \
  --token "$SHINKIRO_CLUSTER_TOKEN" \
  --tls-cert /etc/shinkiro/hub.crt \
  --tls-key  /etc/shinkiro/hub.key
```

`GET /readyz` reports `auth_mode` as `token` or `insecure-lab`, and `model` as `hub-and-spoke-http`.

## Agent / spoke nodes

Sensors keep running `shinkiro up` / `tui` locally. To attach to the hub, join once then POST events:

```bash
export HUB=http://hub.example:9090
export SHINKIRO_CLUSTER_TOKEN=...   # same secret as hub

# Join
curl -sS -X POST "$HUB/api/v1/cluster/join" \
  -H "Authorization: Bearer $SHINKIRO_CLUSTER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id":"edge-nyc-1","address":"10.0.0.5:2222"}'

# Ingest an event (shape = intel.Event JSON)
curl -sS -X POST "$HUB/api/v1/cluster/ingest" \
  -H "Authorization: Bearer $SHINKIRO_CLUSTER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id":"ev-1","timestamp":"2026-09-06T18:00:00Z","decoy_name":"ssh","remote_ip":"198.51.100.10","threat_score":80}'
```

Go helper: `cluster.AgentClient{BaseURL, Token}` with `Join` / `Ingest`.

## TLS notes

1. **Native:** pass `--tls-cert` + `--tls-key` together; hub uses `ListenAndServeTLS`.
2. **Termination:** leave cert/key empty; put TLS on a reverse proxy that forwards to plain `:9090`.
3. Half-configured TLS (only one of cert/key) is rejected at startup.

## Out of scope (still)

- Gossip / SWIM / memberlist
- Automatic peer discovery
- Cross-node preemptive blackhole propagation
- Live eBPF loaders or MaxMind GeoIP
