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
