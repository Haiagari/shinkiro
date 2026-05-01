# 🧠 OzyRecon v8.3.2 — *The Enterprise Sentinel*

> **Professional Intelligence Platform: Secure relationship-first reconnaissance with multi-key RBAC, cryptographic chain of custody, AI narrative analysis, and operational resilience.**

<div align="center">

<img src="assets/banner-ozyrecon-paradigm.png" alt="OzyRecon Banner" width="100%"/>

<br/>

[![Version](https://img.shields.io/badge/version-v8.3.2-00d4ff?style=flat-square&labelColor=0a0f1a)](CHANGELOG.md)
[![Status](https://img.shields.io/badge/status-ENTERPRISE--READY-00ff88?style=flat-square&labelColor=0a0f1a)]()
[![Contract](https://img.shields.io/badge/contract-ozy.runtime.v1-00ff88?style=flat-square&labelColor=0a0f1a)]()

</div>

---

## 🎭 v8.3.2 Core Pillars: "The Enterprise Sentinel"

OzyRecon v8.3.2 is a hardened, production-grade intelligence engine.

### 1. 🔐 Multi-Key RBAC (Identity Pro)
No more single-key risks. Implement fine-grained access control using **Hashed API Keys** and **Scopes** (`hunt:run`, `sessions:read`, `admin:*`). Manage identities via the versioned `config/api_keys.example.json` seed, which materializes `config/api_keys.json` at runtime when missing.
The runtime also bootstraps `config/config.yaml` from `config/config.example.yaml` and creates `resources/keys/evidence_key.priv` locally when those files are absent.

### 2. 🛡️ Advanced Operational Security (SSRF Pro)
Built-in protection against **DNS Rebinding** and internal scanning. The engine resolves targets and validates against private IP ranges (RFC 1918) before any probe execution.

### 3. 🧾 Forensic Chain of Custody 2.0
Every finding is **digitally signed (Ed25519)** with full context: `session_id`, `timestamp`, and `schema_version`. Detection of database tampering is instant and verifiable externally.

### 4. 🧠 AI Narrative Analyst
The motor decides, the IA explains. Integrated LLM bridge contextualizes findings into **Human-Readable Business Impact** reports and technical recommendations.

### 5. 🧱 Operational Resilience
Controlled execution with **Managed Lifecycles**:
- **Cancellation**: Abort active scans via `POST /sessions/{id}/cancel`.
- **Deduplication**: Isolated idempotency per user/config.
- **Observability**: Structured **JSONL logs with rotation** and real-time health metrics.

---

## 🏗️ Runtime Surface

OzyRecon exposes a local engine surface that can be consumed directly or through the platform bridge:

- **Local entrypoint**: [`ozy.py`](ozy.py)
- **API runtime**: [`src/core/api.py`](src/core/api.py)
- **Normalized export**: [`src/export/normalizer.py`](src/export/normalizer.py)
- **Runtime trace**: `GET /sessions/{session_id}/trace`
- **Bridge contract**: [`docs/BRIDGE_CONTRACT.md`](docs/BRIDGE_CONTRACT.md)

---

## 🧠 The Shift: Graph-First Intelligence

OzyRecon doesn’t scan targets — it builds **relationships**.

* Assets become **nodes**
* Connections become **edges**
* Weak signals become **review priorities**

<div align="center">
  <img src="assets/knowledge-graph-v5.png" alt="Knowledge Graph Visualization" width="900">
  <br>
<sub><i>Knowledge Graph correlating infrastructure into reviewable relationships.</i></sub>
</div>

---

## 🔥 Why OzyRecon is Different

### 🧩 Correlation Engine (Not Just Detection)

Findings are **validated through relationships**, not isolated signals.

→ Open port ≠ vulnerability
→ Correlated evidence = **review candidate**

---

### 📉 26x Noise Reduction

Evidence-based scoring eliminates irrelevant data.

* No correlation → ignored
* Multi-signal validation → escalated

---

### 🧑‍💻 Human-in-the-Loop Security

No blind execution.

```text
Review Candidate → PENDING_APPROVAL → Controlled Execution
```

You decide **when** and **what** runs.

---

### 🔐 Cryptographic Evidence Layer

Every finding is:

* Digitally Signed (Ed25519)
* Timestamped
* Audit-ready

Built for **compliance, trust, and forensic reproducibility**.

---

## ⚙️ Architecture Snapshot

| Layer         | Stack                            |
| ------------- | -------------------------------- |
| Core          | Python 3.11 (strict typing)      |
| Visualization | Jinja2 + D3.js                   |
| Security      | Bandit (SAST)                    |
| Storage       | Volatile + Persistent separation |
| Engine        | Graph-Based Inference            |

---

## ⚡ Quick Start

### 1. Unified Execution (Recommended)
Start the local engine runtime from this repository:

```bash
# Verify environment and dependencies
python ozy.py verify

# Run a baseline hunt
python ozy.py hunt target.com
```

### 2. Available Modes
OzyRecon operates in different modes depending on the objective:
- **hunt**: Full discovery and baseline mapping.
- **continuous**: Differential monitoring for changes.
- **research**: Deep-dive into specific assets.
- **forensic**: Post-compromise or evidence recovery.

### 3. Runtime Verification
Use the `verify` command to check the engine contract and tool availability:

```bash
python ozy.py verify
```

### 4. Engine API
OzyRecon exposes a FastAPI service for remote orchestration:

```bash
# Start the API service
python -c "from src.core.api import start_api; start_api()"
```

The API follows the **`ozy.runtime.v1`** contract.

---

## 🛠️ System Requirements

- **Python 3.11+**
- **Go Binaries** (placed in `tools/go/bin/` or in PATH):
  - subfinder, assetfinder, amass (Discovery)
  - httpx, dnsx (Resolution)
  - naabu, nmap (Services)
  - nuclei (Templates)

---

## 🛠️ System Dependencies

### WeasyPrint (PDF Generation)
To generate PDF reports, OzyRecon requires `WeasyPrint`, which depends on several system libraries for graphics and text layout:

- **Debian/Ubuntu**:
  ```bash
  sudo apt-get install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 libpangocairo-1.0-0
  ```
- **macOS (Homebrew)**:
  ```bash
  brew install pango
  ```
- **Windows**:
  Follow the instructions on the [WeasyPrint documentation](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows).

---

## 📚 Documentation

### Primary docs

* 🧾 [Phase 0 Audit](docs/planning/OZYRECON_PHASE0_AUDIT.md)
* 🧰 [Hardening Plan](docs/planning/OZYRECON_HARDENING_PLAN.md)
* 📜 [Runtime Contract](docs/RUNTIME_CONTRACT.md)

### Supporting docs

* 🧭 [Improvement Plan](docs/planning/OZYRECON_IMPROVEMENT_PLAN.md)
* 🪧 [Operational Plan](docs/planning/OZYRECON_OPERATIONAL_PLAN.md)
* 🤝 [Bridge Contract](docs/BRIDGE_CONTRACT.md)

### General docs

* 📦 [Installation](docs/INSTALL.md)
* 🧪 [Use Cases](docs/USE_CASES.md)
* 📊 [Benchmarks](docs/BENCHMARKS.md)
* 🛣️ [Roadmap](docs/ROADMAP.md)
* 🤝 [Contributing](CONTRIBUTING.md)

---

<div align="center">

**Built for operators who prefer signal, gates, and traceable output.**

</div>
