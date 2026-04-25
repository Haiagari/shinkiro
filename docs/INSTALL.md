# 🚀 OzyRecon Installation & Setup Guide

This guide will walk you through setting up **OzyRecon v6.0 (Phantom Blade)** for professional, stealth-focused security assessments.

## Prerequisites
- **Python 3.10+** (3.11 recommended)
- **Git**
- **curl_cffi** requirements (Automatically handled by setup.sh)

## 1. Fast Setup (The Wizard)
The easiest way to install OzyRecon is using our automated script which now includes **Stealth Layer** verification:
```bash
git clone https://github.com/SamBleed/OzyRecon.git
cd OzyRecon
chmod +x setup.sh
./setup.sh
```

## 2. Manual Installation
If you prefer manual control, ensure you install the `curl_cffi` dependency for TLS Fingerprinting:
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## 3. Configuration & API Keys
OzyRecon reaches its full potential when integrated with external intelligence sources.
```bash
cp .env.example .env
```
*Edit the `.env` file with your Shodan, Censys, and Hunter.io keys.*

## 4. Running the Phantom Blade
OzyRecon v6.0 uses a unified entry point for all operations:

- **Launch TUI (Interactive)**: `./ozy.py`
- **Launch CLI (Automation)**: `./ozy.py --cli scan target.com --mode hunt`

## 5. OPSEC & Stealth
By default, v6.0 uses the **Chameleon Engine**. You can tune the stealth profiles in `config/ozy.yaml` to better mimic specific browser signatures or adjust the **Autopilot** confidence threshold.

---
*Next: Learn how to use OzyRecon in our [Operational Scenarios](USE_CASES.md).*
