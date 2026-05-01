# 📖 OzyRecon: Operating Guide

OzyRecon is designed for **controlled reconnaissance and review**. This guide covers the current engine runtime, its normalized outputs, and the session trace surface.

## 🕹️ Running the Interfaces

### 1. The TUI (Recommended)
The terminal user interface is the easiest way to inspect the **Decision Log**, the **Knowledge Graph**, and the runtime state.
```bash
python ozy.py
```
*   Use `help` within the TUI to see available commands.
*   `focus <target>` to set the current operational objective.

### 2. The CLI (Automation)
For CI/CD or scripting, use the classic CLI:
```bash
python -m cli hunt target.com
```

### 3. Runtime Trace
For a reconstructed run, query the session trace endpoint:
```bash
GET /sessions/{session_id}/trace
```

### 4. Quick Verification
Use the built-in verifier to check bootstrap, dependency coverage, and an optional real smoke run:
```bash
python ozy.py verify
python ozy.py verify example.com
python ozy.py verify --allow-degraded --json
```

When you pass a target, the command runs:
- a lightweight `recon` smoke
- a lightweight `hunt` smoke

`--allow-degraded` is meant for CI-lite checks where missing optional tools should not fail the build.

If the required binaries are missing, the command still reports the downgrade instead of failing silently.

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
