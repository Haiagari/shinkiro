# 📖 OzyRecon: Operating Guide

OzyRecon is designed for **controlled reconnaissance and review**. This guide covers the current engine runtime, its normalized outputs, and the session trace surface.

## 🕹️ Running the Engine

### 1. The Unified Entrypoint
The `ozy.py` wrapper is the stable interface for all operations.
```bash
python ozy.py --help
```

### 2. Hunting & Adaptive Discovery
Execute an intelligent scan. The engine will choose the best profile:
```bash
python ozy.py hunt target.com
```

### 3. Intelligence API v7
OzyRecon exposes relationship-first data:
- **Relationship Graph**: `GET /intelligence/graph?target=domain.com`
- **Session Trace**: `GET /sessions/{session_id}/trace`
- **Novelty Events**: `GET /scans/{scan_id}/novelty`

---

## 🔐 Identity & Access Control (v8.1+)
OzyRecon uses a professional **Multi-Key RBAC** system.

### 1. Managing API Keys
Manage identities via the CLI:
```bash
# Create a key with specific permissions
python ozy.py keys create analyst-name --scopes sessions:read,analysis:read

# List all keys and their status
python ozy.py keys list

# Revoke a key permanently
python ozy.py keys revoke analyst-name
```
The default runtime seed lives in `config/api_keys.example.json`. On a fresh checkout, `python ozy.py` materializes `config/api_keys.json` automatically if it is missing.

### 2. Operational Scopes
- `hunt:run`: Execute active reconnaissance.
- `sessions:read`: List and view session results.
- `analysis:read`: Access AI narrative reports.
- `admin:*`: Unrestricted access.

---

## 🕹️ Running the Engine

### 1. The Unified Entrypoint
Access the API using the `X-API-KEY` header:
```bash
curl -H "X-API-KEY: ozy_live_..." http://localhost:8000/health
```
Use the `master-admin` seed for full access (`admin:*`) or the `auditor-externo` seed for read-only dashboard access (`sessions:read`) until you rotate your own keys.

### 2. Managing Scans
Start and stop scans through the API:
- **Start Hunt**: `POST /hunt` (Queued and tracked).
- **Cancel Scan**: `POST /sessions/{id}/cancel` (Immediate termination).

---

## 📊 Intelligent Context: Enterprise Baseline v8.3.2
OzyRecon v8.3.2 provides the highest level of forensic and operational data:

- **Anti-SSRF**: Full protection against internal scanning and DNS Rebinding.
- **Forensic Chain**: Every finding is digitally signed (Ed25519) with session context.
- **AI Narrative**: Narrative explanation of business risk via the `/analyze` endpoint.
- **Smart Graph**: Interactive relationship map with automatic truncation and prioritization.

---

## 🔐 Safety & OPSEC
*   **Kill Switch**: Hit `Ctrl+C` twice to immediately terminate all active probes.
*   **Identity Rotation**: OzyRecon rotates headers and timing unless configured otherwise in `config/config.yaml`.
*   **Validation policy**: low-risk exposure checks run automatically, sensitive auth/panel checks remain gated, and blocked hypotheses do not execute.
*   **Traceability**: Every run keeps a timeline in the runtime context and exposes a consolidated session trace.

---

## 🧩 Capability Matrix

| Tool | Capability | Role | If missing |
| --- | --- | --- | --- |
| `subfinder` | `asset_discovery` | required | Passive subdomain breadth shrinks |
| `dnsx` | `dns_resolution` | required | Discovery normalization keeps raw assets only |
| `httpx` | `live_detection` | required | Live-host confirmation degrades |
| `amass` | `asset_discovery` | optional | Passive breadth drops |
| `assetfinder` | `asset_discovery` | optional | Passive breadth drops |
| `nmap` | `service_discovery` | optional | Service fingerprinting drops |
| `naabu` | `port_scan` | optional | Port enumeration drops |
| `nuclei` | `template_scan` | optional | Template-based findings drop |

The verifier surfaces this matrix directly with `python ozy.py verify`.
