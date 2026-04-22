# 🧠 OzyRecon v5.0 — Security Validation Platform
**From Recon to Verified Security Intelligence**

> **"OzyRecon reduces false positives and provides decision-grade security intelligence."**

<div align="center">

![OzyRecon Banner](./assets/banner.svg)

<br/>

![Stars](https://img.shields.io/github/stars/SamBleed/OzyRecon?style=for-the-badge&color=00ff88&labelColor=0a0f1a)
![Version](https://img.shields.io/badge/version-v5.0.0-00d4ff?style=for-the-badge&labelColor=0a0f1a)
![Python](https://img.shields.io/badge/Python-3.10+-ffd700?style=for-the-badge&logo=python&logoColor=ffd700&labelColor=0a0f1a)
</div>

---

### 🚀 Quick Highlights
- **Hypothesis-driven validation**: Moves beyond linear scanning.
- **Human-in-the-loop control**: Manual authorization for sensitive probes.
- **Evidence with cryptographic integrity**: SHA256-signed proof vault.
- **Risk-based prioritization**: Focus on business impact, not just CVSS.
- **DevSecOps-ready**: Designed to integrate into CI/CD pipelines and security workflows.

---

### 🎯 Value Proposition
**Traditional scanners generate noise.** Most tools deliver a list of unverified vulnerabilities that waste engineering time. 

**OzyRecon delivers confidence.** It focuses on validated, high-confidence findings backed by technical evidence.

---

### 🔄 The Validation Pipeline
OzyRecon follows a rigorous workflow to ensure surgical precision:

**Discovery** → **Hypothesis** → **Approval (Gate)** → **Validation** → **Evidence** → **Report**

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
│   └── intelligence/   # Correlation & hypothesis engine
```

---

**OzyRecon: Controlled Intelligence, Verifiable Evidence.** 🚀  
*Built for security professionals who value precision over noise.*
