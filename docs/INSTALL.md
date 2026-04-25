# 🚀 OzyRecon Installation & Setup Guide

This guide will walk you through setting up OzyRecon v5.7 for professional security assessments.

## Prerequisites
- **Python 3.10+** (3.11 recommended)
- **Git**
- **Docker** (Optional, for containerized deployment)

## 1. Fast Setup (The Wizard)
The easiest way to install OzyRecon is using our automated script:
```bash
git clone https://github.com/SamBleed/OzyRecon.git
cd OzyRecon
./setup.sh
```

## 2. Manual Installation
If you prefer manual control:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## 3. Configuration & API Keys
OzyRecon reaches its full potential when integrated with external intelligence sources. Copy the template and edit it:
```bash
cp .env.example .env
```

### Required/Recommended Keys:
| Service | Purpose | Get Key At |
| :--- | :--- | :--- |
| **Shodan** | Passive asset discovery | https://shodan.io |
| **Censys** | Advanced fingerprinting | https://censys.io |
| **Hunter.io** | Intelligence correlation | https://hunter.io |
| **Telegram** | Real-time notifications | BotFather (Telegram) |

## 4. OPSEC Configuration
Edit `config/ozy.yaml` to define your scanning boundaries:
- `exclude_domains`: Add government or sensitive domains you never want to scan.
- `stealth_mode`: Enable header randomization and rate limiting.

## 5. Deployment with Docker
For a completely isolated environment:
```bash
docker-compose up -d --build
```
This will launch the **OzyRecon API**, **Worker Nodes**, and the **Database backend**.

---
*Next: Learn how to use OzyRecon in our [Operational Scenarios](USE_CASES.md).*
