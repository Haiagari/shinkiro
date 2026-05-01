# 🧠 OzyRecon v8.3.2 — *The Enterprise Sentinel*

> **Professional intelligence platform for controlled reconnaissance, session-based hunting, cryptographic chain of custody, AI narrative analysis, and operational resilience.**
>
> Fresh clones bootstrap their mutable runtime files from tracked seeds: `config/config.example.yaml`, `config/api_keys.example.json`, and the local Ed25519 evidence key when missing.

<div align="center">

<img src="assets/banner-ozyrecon-paradigm.png" alt="OzyRecon Banner" width="100%"/>

<br/>

[![Version](https://img.shields.io/badge/version-v8.3.2-00d4ff?style=flat-square&labelColor=0a0f1a)](CHANGELOG.md)
[![Status](https://img.shields.io/badge/status-ENTERPRISE--READY-00ff88?style=flat-square&labelColor=0a0f1a)]()
[![Contract](https://img.shields.io/badge/contract-ozy.runtime.v1-00ff88?style=flat-square&labelColor=0a0f1a)]()

</div>

---

## 🎭 What v8.3.2 Gives You

OzyRecon v8.3.2 is a hardened intelligence engine. The release centers on five operational guarantees:

### 1. 🔐 Multi-Key RBAC
Fine-grained access control now uses hashed API keys and scopes.

- `admin:*` for full operator actions
- `sessions:read` for dashboard and read-only inspection
- `hunt:run` for controlled execution flows

The versioned seed lives in `config/api_keys.example.json`, which materializes `config/api_keys.json` at runtime when missing. The default seed includes a full-access `master-admin` key and a read-only `auditor-externo` key.

### 2. 🛡️ Security Gates
The engine validates targets before execution and blocks unsafe internal scanning patterns such as DNS rebinding and private-range abuse.

### 3. 🧾 Forensic Chain of Custody
Every finding is signed with Ed25519 and carries structured context such as `session_id`, timestamp, and schema version.

### 4. 🧠 Narrative Analysis
The analysis layer converts session output into business impact and technical recommendations for operators.

### 5. 🧱 Managed Lifecycles
Hunts are non-blocking, cancellable, and observable. Sessions can be cancelled, traced, and inspected without stopping the engine.

---

## 🏗️ Runtime Surface

OzyRecon exposes a local engine surface that can be consumed directly or through the platform bridge:

- **Local entrypoint**: [`ozy.py`](ozy.py)
- **CLI commands**: [`cli/`](cli)
- **API runtime**: [`src/core/api.py`](src/core/api.py)
- **Bootstrap**: [`src/core/bootstrap.py`](src/core/bootstrap.py)
- **Auth store**: [`src/auth/key_store.py`](src/auth/key_store.py)
- **Normalized export**: [`src/export/normalizer.py`](src/export/normalizer.py)
- **Runtime trace**: `GET /sessions/{session_id}/trace`
- **Bridge contract**: [`docs/BRIDGE_CONTRACT.md`](docs/BRIDGE_CONTRACT.md)

### Bootstrap & Runtime Files

On first run, the engine materializes the mutable files it needs to operate:

- `config/config.yaml` from `config/config.example.yaml`
- `config/api_keys.json` from `config/api_keys.example.json`
- `resources/keys/evidence_key.priv` as a local Ed25519 keypair seed

That keeps the repo portable without checking secrets or private keys into Git.

### Authentication & Scopes

The API expects the `X-API-KEY` header on protected routes.

```bash
curl -H "X-API-KEY: <your-key>" http://localhost:8000/health
```

Use the default `master-admin` seed for full access or `auditor-externo` for read-only dashboard access until you rotate your own keys.

### Session Lifecycle

Hunts are asynchronous and return a `session_id` immediately.

- `POST /hunt` starts a session and returns the session handle
- `POST /sessions/{session_id}/cancel` stops an active scan
- `GET /sessions/{session_id}/analyze` returns narrative findings
- `GET /sessions/{session_id}/trace` exposes the runtime trace for review

### Integrity & Graph Output

- Findings can be verified externally with the Sentinel public key and Ed25519 signatures.
- Smart Graph v8 includes `is_truncated`; when that flag is present, the UI should warn that the graph is a prioritized slice of the full data.

### Observability

`GET /health` returns runtime metrics such as:

- `scans_total`
- `scans_failed`
- `active_concurrency`

Map those values to the engine status widget or any operator dashboard that consumes the API.

---

## 🧠 Graph-First Intelligence

OzyRecon does not scan targets only to dump raw output. It builds relationships.

- Assets become nodes
- Connections become edges
- Weak signals become review priorities

<div align="center">
  <img src="assets/knowledge-graph-v5.png" alt="Knowledge Graph Visualization" width="900">
  <br/>
<sub><i>Knowledge Graph correlating infrastructure into reviewable relationships.</i></sub>
</div>

---

## 🔥 Why OzyRecon Is Different

### 🧩 Correlation Engine

Findings are validated through relationships, not isolated signals.

`open port` ≠ `vulnerability`

`correlated evidence` = `review candidate`

### 📉 Noise Reduction

Evidence-based scoring filters irrelevant data and promotes only the meaningful paths.

- No correlation → ignored
- Multi-signal validation → escalated

### 🧑‍💻 Human-in-the-Loop Security

No blind execution.

```text
Review Candidate → PENDING_APPROVAL → Controlled Execution
```

You decide when and what runs.

### 🔐 Cryptographic Evidence Layer

Every finding is:

- Digitally signed with Ed25519
- Timestamped
- Audit-ready

Built for compliance, trust, and forensic reproducibility.

---

## ⚙️ Architecture Snapshot

| Layer | Stack |
| --- | --- |
| Core | Python 3.11 (strict typing) |
| API | FastAPI |
| Visualization | Jinja2 + D3.js |
| Security | Bandit (SAST) |
| Storage | Volatile + persistent separation |
| Engine | Graph-based inference |

---

## ⚡ Quick Start

### 1. Unified Execution

Start the local engine runtime from this repository:

```bash
python ozy.py verify
python ozy.py hunt target.com
```

The first invocation also bootstraps the runtime files listed above if they are missing.

### 2. Available Modes

OzyRecon operates in different modes depending on the objective:

- **hunt**: Full discovery and baseline mapping
- **continuous**: Differential monitoring for changes
- **research**: Deep dive into specific assets
- **forensic**: Post-compromise or evidence recovery

### 3. Runtime Verification

Use `verify` to check the engine contract and tool availability:

```bash
python ozy.py verify
```

### 4. Engine API

OzyRecon exposes a FastAPI service for remote orchestration:

```bash
python -c "from src.core.api import start_api; start_api()"
```

The API follows the `ozy.runtime.v1` contract. Protected endpoints require the `X-API-KEY` header. For full access, use a key with `admin:*`; for read-only dashboard access, use `sessions:read`.

---

## 🛠️ System Requirements

- **Python 3.11+**
- **pip** and a working virtual environment are recommended for the install flow below
- **Go binaries** in `tools/go/bin/` or on `PATH`:
  - `subfinder`, `assetfinder`, `amass`
  - `httpx`, `dnsx`
  - `naabu`, `nmap`
  - `nuclei`

---

## 🛠️ System Dependencies

### WeasyPrint

To generate PDF reports, OzyRecon requires `WeasyPrint`, which depends on several system libraries for graphics and text layout:

- **Debian/Ubuntu**

```bash
sudo apt-get install libpango-1.0-0 libharfbuzz0b libpangoft2-1.0-0 libpangocairo-1.0-0
```

- **macOS**

```bash
brew install pango
```

- **Windows**

Follow the instructions in the [WeasyPrint documentation](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows).

### Optional runtime notes

- The repo ships a seed registry for API keys in `config/api_keys.example.json`.
- The mutable files are generated locally and ignored by Git.

---

## 🧱 Repository Layout

- `cli/` command-line entrypoint and command registration
- `src/` core engine, auth, API, and export logic
- `tests/` verification and regression coverage
- `config/` runtime config seeds and mutable generated config
- `resources/` shared runtime assets and key material
- `docs/` operator docs, contracts, and usage notes
- `assets/` banners and visual assets

---

## 📚 Documentation

### Primary docs

- 🧾 [Phase 0 Audit](docs/planning/OZYRECON_PHASE0_AUDIT.md)
- 🧰 [Hardening Plan](docs/planning/OZYRECON_HARDENING_PLAN.md)
- 📜 [Runtime Contract](docs/RUNTIME_CONTRACT.md)

### Supporting docs

- 🧭 [Improvement Plan](docs/planning/OZYRECON_IMPROVEMENT_PLAN.md)
- 🪧 [Operational Plan](docs/planning/OZYRECON_OPERATIONAL_PLAN.md)
- 🤝 [Bridge Contract](docs/BRIDGE_CONTRACT.md)

### General docs

- 📦 [Installation](docs/INSTALL.md)
- 🧪 [Use Cases](docs/USE_CASES.md)
- 📊 [Benchmarks](docs/BENCHMARKS.md)
- 🛣️ [Roadmap](docs/ROADMAP.md)
- 🧭 [Status](docs/STATUS.md)
- 🤝 [Contributing](CONTRIBUTING.md)
- 📖 [Usage](docs/USAGE.md)

### Runtime notes

- [`config/api_keys.example.json`](config/api_keys.example.json) is the tracked key seed
- [`config/config.example.yaml`](config/config.example.yaml) is the runtime config seed
- [`src/core/bootstrap.py`](src/core/bootstrap.py) materializes mutable runtime files on demand

---

<div align="center">

**Built for operators who prefer signal, gates, and traceable output.**

</div>
