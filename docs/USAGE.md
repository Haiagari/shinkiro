# 📖 OzyRecon: Operating Guide

OzyRecon is designed for **Controlled Intelligence**. This guide covers the standard operational workflow for a Red Team engagement.

## 🕹️ Running the Interfaces

### 1. The TUI (Recommended)
The terminal user interface is the best way to visualize the **Decision Log** and the **Knowledge Graph** in real-time.
```bash
./ozy.py
```
*   Use `help` within the TUI to see available commands.
*   `focus <target>` to set your current operational objective.

### 2. The CLI (Automation)
For CI/CD or scripting, use the classic CLI:
```bash
./ozy.py --cli scan target.com --mode hunt
```

---

## 🛠️ Operational Workflow

### Phase 1: Passive Recon & Discovery
OzyRecon starts by mapping relationships without touching the target directly.
1.  Add target: `focus target.com`
2.  Start discovery: `scan target.com --mode passive`

### Phase 2: Hypothesis Validation
Once the **Knowledge Graph** is populated, OzyRecon will generate hypotheses in the **Decision Log**.
*   View pending decisions in the TUI.
*   Approve high-risk probes only after verifying the attack path.

### Phase 3: Evidence Collection & Reporting
All findings are cryptographically signed and stored in the **Evidence Vault**.
*   Generate executive report: `report target.com`
*   Export raw intelligence: `export target.com --format json`

---

## 🔐 Safety & OPSEC
*   **Kill Switch**: Hit `Ctrl+C` twice to immediately terminate all active probes.
*   **Identity Rotation**: OzyRecon automatically rotates headers and timing unless configured otherwise in `config/config.yaml`.
