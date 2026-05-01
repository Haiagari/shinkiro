# 🚀 OzyRecon Installation & Setup Guide

This guide covers the current **v8.3.2 Enterprise Baseline** and the runtime bootstrap model used by the engine.

## Prerequisites

- **Python 3.11+**
- **Git**
- A working virtual environment
- `pip`
- Optional but recommended system libraries for PDF generation if you plan to use reports

## 1. Fast Setup

The fastest path is to clone the repo and run the wrapper once:

```bash
git clone https://github.com/SamBleed/OzyRecon.git
cd OzyRecon
python ozy.py verify
```

The first run bootstraps mutable runtime files automatically.

## 2. Manual Installation

If you want explicit control over the environment:

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## 3. Runtime Bootstrap

OzyRecon keeps secrets and mutable runtime files out of Git, but still materializes them locally when needed:

- `config/config.yaml` from `config/config.example.yaml`
- `config/api_keys.json` from `config/api_keys.example.json`
- `resources/keys/evidence_key.priv` as a local Ed25519 seed

The default API key seed includes:

- `master-admin` with `admin:*`
- `auditor-externo` with `sessions:read`

## 4. Configuration

Copy the environment example if you need local integrations:

```bash
cp .env.example .env
```

Then edit only the values you actually use.

## 5. Running the Engine

Use the unified entrypoint for interactive work and verification:

```bash
python ozy.py --help
python ozy.py verify
python ozy.py hunt target.com
```

For the API runtime:

```bash
python -c "from src.core.api import start_api; start_api()"
```

## 6. API Access

Protected endpoints expect the `X-API-KEY` header. Use `admin:*` for full operator access or `sessions:read` for dashboard-only access.

## 7. Safety Notes

- The engine validates targets before execution.
- Hunts are cancellable via `POST /sessions/{session_id}/cancel`.
- Session traces and health metrics are available for audit and troubleshooting.

---

Next: review [Usage](USAGE.md) for day-to-day operations and [Runtime Contract](RUNTIME_CONTRACT.md) for the exact runtime surface.
