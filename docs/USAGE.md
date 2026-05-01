# 📖 OzyRecon: Operating Guide

OzyRecon is designed for **controlled reconnaissance and review**. This guide covers the current engine runtime, its normalized outputs, and the session trace surface.

## 🕹️ Running the Engine

### 1. The Unified Entrypoint
The `ozy.py` wrapper is the stable interface for all operations.
```bash
python ozy.py --help
```

### 2. Hunting & Discovery
Execute a full discovery and intelligence mapping:
```bash
python ozy.py hunt target.com
```

### 3. Runtime Trace & Observability
For a reconstructed run, query the session trace endpoint or inspect the TUI:
```bash
GET /sessions/{session_id}/trace
```

### 4. System Verification
Check your capability matrix and binary availability:
```bash
python ozy.py verify
```
This command ensures that required tools (`subfinder`, `dnsx`, `httpx`) and optional ones are properly configured in your PATH or `tools/go/bin/`.

---

## 📊 Normalized Contract: ozy.runtime.v1
OzyRecon produces a standard JSON output for platform integration. This contract ensures that assets, services, and findings are mapped correctly across the ecosystem.

Key Export Fields:
- **assets**: Discovered subdomains with title and tech fingerprints.
- **services**: Open ports with service/version identification.
- **findings**: Security hypotheses and confirmed vulnerabilities.
- **stats**: Summary metrics of the operation.


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
