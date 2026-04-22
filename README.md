# 🧠 OzyRecon v5.7 — Security Validation Platform
**From Recon to Verified Security Intelligence**

> **"OzyRecon reduces false positives and provides decision-grade security intelligence."**

<div align="center">

![OzyRecon Banner](./assets/banner.svg)

<br/>

![Stars](https://img.shields.io/github/stars/SamBleed/OzyRecon?style=for-the-badge&color=00ff88&labelColor=0a0f1a)
![Version](https://img.shields.io/badge/version-v5.7.0-00d4ff?style=for-the-badge&labelColor=0a0f1a)
![Python](https://img.shields.io/badge/Python-3.10+-ffd700?style=for-the-badge&logo=python&logoColor=ffd700&labelColor=0a0f1a)
</div>

---

### 🚀 Quick Highlights
- **DevSecOps-ready**: Seamlessly integrates into CI/CD pipelines for continuous security validation.
- **Knowledge Graph (v5.7)**: Real-time attack surface visualization using Cytoscape.js.
- **Visual Evidence (v5.7)**: Automated screenshots of confirmed findings using Playwright.
- **Advanced Auth Validation (v5.7)**: Stealthy default credential testing for exposed panels.
- **Hypothesis-driven validation**: Moves beyond linear scanning with correlation-based logic.
- **Human-in-the-loop control**: Mandatory manual authorization for sensitive probes.
- **Evidence with cryptographic integrity**: SHA256-signed proof vault for technical audit.
- **OPSEC Guard**: Pre-commit hooks and dynamic filters to prevent sensitive data leaks.

---

### 🎯 Value Proposition
**Traditional scanners generate noise.** Most tools deliver a list of unverified vulnerabilities that waste engineering time. 

**OzyRecon delivers confidence.** It is designed to reduce false positives and deliver high-confidence, validated findings backed by technical evidence.

---

### 🔄 The Validation Pipeline
OzyRecon follows a rigorous workflow to ensure surgical precision:

**Discovery** → **Hypothesis** → **Approval (Human Gate)** → **Validation** → **Evidence** → **Report**

---

### 🔴🟡🟢 Risk Classification
- **🔴 HIGH**: Direct impact (Data exposure, RCE, Critical misconfiguration).
- **🟡 MEDIUM**: Conditional impact (Requires interaction or specific pre-conditions).
- **🟢 LOW**: Informational (Hardening opportunities, best practices).

---

### 🔬 Example Validated Finding
```json
{
  "finding": "Exposed admin endpoint",
  "severity": "HIGH",
  "confidence": 0.92,
  "confidence_reason": "Correlation of multiple independent signals matched a known exposure pattern",
  "evidence_id": "ev_8a2f1c9",
  "integrity_hash": "sha256:7f83b1...",
  "recommendation": "Restrict access via authentication"
}
```

---

### ⚙️ Core Capabilities

#### 1. Assisted Offensive Validation
Move beyond automated scanning. OzyRecon correlates technical signals to generate attack hypotheses that require human authorization before execution.

#### 2. Evidence Engine (Audit-Ready)
Full traceability for every action. The system collects raw metadata, securing each piece of evidence with a SHA256 integrity hash for formal reporting.

#### 3. Adaptive Intelligence Layer
An evolving brain that learns from your decisions. It uses dynamic scoring (Reputation, Novelty, Drift) to prioritize targets.

---

### 💻 Professional CLI Experience

```bash
# 1. Start an intelligent hunt
ozy hunt -t target.com

# 2. Review generated hypotheses
ozy gate list

# 3. Approve critical points
ozy gate approve --id hyp_8a2f --reason "Sensitive endpoint"

# 4. Execute validation orchestrator
ozy validate

# 5. Generate executive report
ozy report
```

---

### 🛡️ Core Philosophy: NO EXPLOITATION
- **Zero Impact**: No destructive payloads.
- **Surgical Probes**: We confirm exposure; we don't exploit it.
- **Audit Focused**: Designed for verifiable proof for remediation teams.
- **Privacy First**: Built-in anonymization and pre-commit guards to protect researcher and target identity.

---

### ⚠️ WARNING
Use this tool only on systems you are authorized to test. Read the [DISCLAIMER.md](DISCLAIMER.md) before proceeding.

---

### 📂 Project Structure
```
OzyRecon/
├── src/
│   ├── gate/           # Human-in-the-loop control
│   ├── validation/     # Surgical probe execution
│   ├── evidence/       # Evidence vault & integrity
│   ├── workflow/       # State machine orchestration
│   ├── reporting/      # Narrative report generation
│   └── intelligence/   # Hypothesis generation & correlation
```

---

**OzyRecon: Controlled Intelligence, Verifiable Evidence.** 🚀  
*Built for security teams that demand verifiable, decision-grade intelligence.*
