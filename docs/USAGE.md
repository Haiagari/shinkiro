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
- **Novelty Events**: `GET /scans/{scan_id}/novelty` (WIP)

---

## 📊 Intelligent Context: ozy.runtime.v1
OzyRecon v7 enriches every asset with business and infrastructure context:

- **Infrastructure**: ASN, ISP/Organization, Cloud Provider (AWS, GCP, Azure).
- **Semantics**: Functional roles (admin panels, APIs, transactional) and Impact Level (CRITICAL, HIGH, LOW).
- **Novelty**: Automatic detection of new assets or technology changes between runs.


---

## 🛠️ Operational Workflow

### Phase 1: Passive Recon & Discovery
OzyRecon starts by mapping relationships without touching the target directly.
1. Add target: `focus target.com`
2. Start discovery through the selected mode, usually `hunt`

### Phase 2: Hypothesis Validation
Once the **Knowledge Graph** is populated, OzyRecon will generate hypotheses in the **Decision Log**.
*   View pending decisions in the TUI.
*   Approve gated validations only after verifying the relationship chain.

### Phase 3: Evidence Collection & Reporting
All findings are signed and stored in the **Evidence** layer and exported through the normalized contract.
*   Generate reports from the current runtime outputs.
*   Export normalized intelligence through the API or export pipeline.

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
