# 📖 OzyRecon: Operating Guide

OzyRecon is designed for controlled reconnaissance and review. This guide focuses on the live engine contract, API usage, session lifecycle, and the output surfaces operators should expect.

## 🕹️ Daily Flow

### 1. Verify the runtime

```bash
python ozy.py verify
```

### 2. Run a hunt

```bash
python ozy.py hunt target.com
```

### 3. Inspect the result

- Session trace: `GET /sessions/{session_id}/trace`
- Narrative analysis: `GET /sessions/{session_id}/analyze`
- Health metrics: `GET /health`

## 🔐 Identity & Access Control

OzyRecon uses multi-key RBAC with hashed API keys.

### Key management

```bash
python ozy.py keys create analyst-name --scopes sessions:read,analysis:read
python ozy.py keys list
python ozy.py keys revoke analyst-name
```

The default runtime seed lives in `config/api_keys.example.json`. On a fresh checkout, `python ozy.py` materializes `config/api_keys.json` automatically if it is missing.

### Operational scopes

- `hunt:run`: execute active reconnaissance
- `sessions:read`: list and view session results
- `analysis:read`: access AI narrative reports
- `admin:*`: unrestricted access

## 🔌 API Usage

Protected endpoints expect the `X-API-KEY` header:

```bash
curl -H "X-API-KEY: <your-key>" http://localhost:8000/health
```

Use the `master-admin` seed for full access (`admin:*`) or the `auditor-externo` seed for read-only dashboard access (`sessions:read`) until you rotate your own keys.

### Lifecycle operations

- `POST /hunt` starts a session and returns a `session_id`
- `POST /sessions/{session_id}/cancel` stops an active scan
- `GET /sessions/{session_id}/analyze` returns the narrative layer
- `GET /sessions/{session_id}/trace` exposes the runtime trace

## 📊 Enterprise Baseline v8.3.2

The current baseline provides:

- Anti-SSRF validation before execution
- Ed25519 signatures for findings
- Non-blocking hunts with cancel support
- Smart Graph output with `is_truncated`
- Health metrics with `scans_total`, `scans_failed`, and `active_concurrency`

## 🔐 Safety & OPSEC

- `Ctrl+C` stops the local CLI flow
- Low-risk checks run automatically
- Sensitive auth/panel checks remain gated
- Blocked hypotheses stay visible in logs and traces

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
