# 🚀 OzyRecon Installation & Setup Guide

This guide will walk you through setting up **OzyRecon v7.5** for controlled reconnaissance and review.

## Prerequisites
- **Python 3.10+** (3.11 recommended)
- **Git**
- **curl_cffi** requirements (Automatically handled by setup.sh)

## 1. Fast Setup (The Wizard)
The easiest way to install OzyRecon is using the automated setup script:
```bash
git clone https://github.com/SamBleed/OzyRecon.git
cd OzyRecon
chmod +x setup.sh
./setup.sh
```

## 2. Manual Installation
If you prefer manual control, install the project dependencies yourself:
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## 3. Configuration & API Keys
OzyRecon can consume external intelligence sources when available.
```bash
cp .env.example .env
```
Edit the `.env` file with any keys you actually use.

## 4. Running the engine
OzyRecon uses a local runtime entrypoint and a CLI wrapper:

- **Launch TUI / shell entry**: `python ozy.py`
- **Launch CLI (Automation)**: `python -m cli hunt target.com`
- **Launch wrapper script**: `./ozy`

## 5. OPSEC & Safety
By default, v7.5 uses the runtime safety policy and gate checks documented in the hardening plan.
 You can tune the policy in the runtime configuration files if needed.
The runtime also exposes a session trace endpoint for reconstruction and audit.

---
*Next: Learn how to use OzyRecon in our [Operational Scenarios](USE_CASES.md).*
