# Installation Guide - OzyRecon

Follow these steps to set up your OzyRecon environment correctly.

## 1. Prerequisites

### System Tools
- **Python:** 3.10 or higher.
- **Go (Golang):** 1.20 or higher.
- **Node.js:** (Optional) for some advanced UI plugins.
- **Playwright Dependencies:** Some Linux distros require extra libraries for headless Chromium (e.g., `libgbm`, `libnss3`).

### External Toolset
OzyRecon relies on the ProjectDiscovery ecosystem. Ensure you have the following tools installed and available in your PATH:
- `subfinder`, `naabu`, `nuclei`, `httpx`, `dnsx`.
- `amass` (OWASP).

> **Tip:** You can place these binaries in `tools/go/bin/` if you don't want to clutter your system PATH.

---

## 2. Installation Steps

### Clone the Repository
```bash
git clone https://github.com/SamBleed/OzyRecon.git
cd OzyRecon
```

### Install Dependencies
We use a virtual environment to keep your system clean.
```bash
make install
```
This command will:
1. Create a `.venv` (if using the provided Makefile).
2. Install Python packages: `fastapi`, `uvicorn`, `sqlalchemy`, `pydantic`, `pyyaml`, `requests`.
3. **Set up Playwright (v5.7):** Installs the headless browser engine needed for visual evidence.

---

## 3. Configuration

### API Keys & Notification
Copy the example config and edit it with your credentials:
```bash
cp runtime/config/config.yaml.example runtime/config/config.yaml
nano runtime/config/config.yaml
```

**Required Fields:**
- `shodan_api_key`: For passive recon.
- `censys_id` & `censys_secret`: For secondary passive recon.
- `telegram_token` & `chat_id`: To receive alerts on your phone.

### Swarm Nodes (Optional)
If you plan to use multiple nodes, define them in `runtime/config/swarm_nodes.json`:
```json
{
  "nodes": [
    {"name": "vps-1", "url": "http://your-vps-ip:8000", "api_key": "secret-token"}
  ]
}
```

---

## 4. Verification

Run the built-in diagnostic tool to ensure everything is connected and ready:
```bash
python3 -m ozy doctor
```

**Expected Result:**
```text
[OK] Python version 3.10.x
[OK] Database connection established
[OK] Subfinder binary found
[OK] Nuclei templates updated
[WARN] Shodan API Key not found (Passive recon will be limited)
```

---

## 5. First Run

Establish your first baseline:
```bash
python3 -m ozy hunt -t example.com
```

Launch the dashboard:
```bash
python3 -m ozy serve
# Open http://localhost:8000/dashboard
```
