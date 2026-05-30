# OzyRecon v9.0.1

> **Advanced Persistent Reconnaissance Platform**  
> Authorized reconnaissance engine for the Ozy Ecosystem.

[![Production Status](https://img.shields.io/badge/status-production--ready-green.svg)](docs/STATUS.md)
[![Tests](https://img.shields.io/badge/tests-217%20passing-brightgreen.svg)](#testing)
[![Version](https://img.shields.io/badge/version-9.0.1-blue.svg)](CHANGELOG.md)

OzyRecon is a production-ready reconnaissance engine built with **Hexagonal Architecture (Ports & Adapters)**. It discovers assets, identifies attack surfaces, and generates cryptographically signed evidence for high-stakes security audits and bug bounty programs.

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
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies and package
pip install -r requirements.txt
pip install -e .

# Verify installation
python ozy.py --version  # Should show: v9.0.1
python ozy.py doctor     # Validates all dependencies
```

### Run a Flow

```bash
# Ensure venv is activated
source venv/bin/activate

# Add target to scope
python ozy.py scope add target.com

# Execute the full reconnaissance workflow
python ozy.py flow target.com --profile safe-active

# View results
python ozy.py inventory
python ozy.py analyze target.com
```

---

## 🛠️ Development & Testing

### Running Tests

**Production Status**: 217/221 tests passing (4 skipped)

```bash
# Ensure venv is activated
source venv/bin/activate

# Run full test suite
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/core/test_tool_manager_sync.py
```

**Important**: Always run tests inside the isolated `venv` to avoid system package conflicts. The root `conftest.py` ensures proper isolation from Go module dependencies.

### Experiments & Load Testing

Proof of concept, performance, and concurrency stress tests are organized within the `scripts/` directory:
- `scripts/performance/` — Load testing and benchmarks
- `scripts/experiments/` — Proof of concept implementations

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
