# OzyRecon v9.0.1

> **Advanced Persistent Reconnaissance Platform**  
> Authorized reconnaissance engine for the Ozy Ecosystem.

OzyRecon is a professional-grade reconnaissance engine built with **Hexagonal Architecture (Ports & Adapters)**. It discovery assets, identifies attack surfaces, and generates cryptographically signed evidence for high-stakes security audits.

---

## 🏗️ Core Architecture (v9.0.1)

OzyRecon has been re-engineered for resilience and interoperability:

- **Domain Driven**: Pure business logic (Assets, Findings, Evidence) decoupled from infrastructure.
- **Governed**: Real-time validation against the **Ozy Policy Engine** and **Ozy API Registry**.
- **Trust Layer**: Every finding is backed by **SHA256 signed evidence**, ready for `OzyAudit`.
- **Event-Driven**: Emits domain events (`AssetDiscovered`, `FindingDetected`) via an internal Event Bus.

---

## ⚡ High-Performance Concurrency

OzyRecon handles I/O bottlenecks and intensive network operations using a hybrid concurrency model:
- **Thread Pool Orchestration**: Scanners like the `fuzzer` and `secret_finder` group massive workloads (e.g., fuzzing multiple hosts or traversing hundreds of URLs) and execute them in parallel using bounded native `ThreadPoolExecutor`s. This prevents local network stack saturation while exponentially speeding up discovery.
- **Subprocess Delegation**: Heavy lifting is strictly delegated to compiled Go binaries (`ffuf`, `subfinder`), entirely avoiding Python's Global Interpreter Lock (GIL) limitations.
- **Thread-Safe State**: Core components like the `RateLimiter` use granular locking (`threading.Lock`) to safely manage state without blocking parallel threads or the main execution flow.

---

## 🔄 The Pipeline (5 Stages)

OzyRecon v9.0.1 follows a strict, non-invasive reconnaissance workflow:

1. **Preflight Verification**: Validates binaries, environment, and connectivity.
2. **Scope & Authorization**: Enforces strict boundaries via `scope.yaml`.
3. **Adaptive Hunt**: Orchestrated discovery using Nmap, Nuclei, and Subfinder.
4. **Analysis Snapshot**: Generates structured intelligence in JSON and Markdown.
5. **Diff Intelligence**: Automates change detection between scan iterations.

---

## 📦 Outputs & Artifacts

OzyRecon v9.0.1 has replaced legacy HTML/PDF reporting with professional technical artifacts:

- `analysis.md`: Narrative executive summary.
- `analysis.json`: Normalized machine-readable data.
- `flow_summary.json`: Detailed timing and telemetry.
- `audit_[session_id].tar.gz`: **Audit-Ready Bundle** containing signed evidence and metadata for `OzyAudit`.

---

## 🚀 Quick Start

### Installation

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Run a Flow

```bash
# Add target to scope
PYTHONPATH=. python -m cli.ozy scope add target.com

# Execute the workflow
PYTHONPATH=. python -m cli.ozy flow target.com --profile safe-active
# Or use the stable entrypoint
python ozy.py flow target.com --profile safe-active
```

---

## 🛠️ Development & Tooling

- **Testing**: A strict `pytest` suite is located in `tests/`. **Always run tests inside the isolated `venv`** to avoid system package conflicts.
- **Experiments & Load Testing**: Proof of concept, performance, and concurrency stress tests are strictly organized within the `scripts/` directory (e.g. `scripts/performance/`) to avoid polluting the core test framework.

---

## 📚 Documentation

Detailed documentation is available in the `docs/` directory:

- [Runtime Contract](docs/RUNTIME_CONTRACT.md): Frozen runtime fields and API surface.
- [Bridge Contract](docs/BRIDGE_CONTRACT.md): Compatibility closure for external adapters.
- [Architecture](docs/architecture.md): Deep dive into Ports & Adapters.
- [Workflow](docs/WORKFLOW.md): Operational guide.
- [Compliance](docs/COMPLIANCE.md): Data integrity and evidence standards.

---

## ⚖️ Disclaimer

This tool is for **authorized reconnaissance only**. Use responsibly within your legal boundaries.
