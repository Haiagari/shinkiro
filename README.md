# 🧠 OzyRecon v5.7 — Security Validation Platform
**From Recon to Verified Security Intelligence**

> **"OzyRecon reduces false positives and provides decision-grade security intelligence."**

<div align="center">

![OzyRecon Banner](./assets/banner-ozyrecon-v5.svg)

<br/>

![Stars](https://img.shields.io/github/stars/SamBleed/OzyRecon?style=for-the-badge&color=00ff88&labelColor=0a0f1a)
![Version](https://img.shields.io/badge/version-v5.7.0-00d4ff?style=for-the-badge&labelColor=0a0f1a)
![Python](https://img.shields.io/badge/Python-3.10+-ffd700?style=for-the-badge&logo=python&logoColor=ffd700&labelColor=0a0f1a)
![Tests](https://img.shields.io/badge/tests-43%2F43%20passing-00ff88?style=for-the-badge&labelColor=0a0f1a)
</div>

---

### 🚀 Quick Highlights
- **Assisted Offensive Validation**: Moves beyond linear scanning with correlation-based logic.
- **Knowledge Graph (v5.7)**: Visualizes relationships between targets and findings to enhance decision-making.
- **Authentication Exposure Validation**: Non-intrusive checks for potential credential leaks (v5.7).
- **Visual Evidence Engine**: Automated proof capture (screenshots) with cryptographic integrity (v5.7).
- **Human-in-the-loop Control**: Mandatory manual authorization for all sensitive probes.
- **OPSEC Guard**: Built-in protection to prevent sensitive data leaks during the research process.

---

### 🎯 Value Proposition
**Traditional scanners generate noise.** Most tools deliver unverified vulnerabilities that waste engineering time. 

**OzyRecon delivers intelligence.** It is a platform designed to reduce false positives and provide decision-grade, validated findings backed by technical and visual evidence.

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
