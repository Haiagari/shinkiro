<div align="center">

```
 ██████╗ ███████╗██╗   ██╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔═══██╗╚══███╔╝╚██╗ ██╔╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║   ██║  ███╔╝  ╚████╔╝     ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║   ██║ ███╔╝    ╚██╔╝      ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚██████╔╝███████╗   ██║       ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═════╝ ╚══════╝   ╚═╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

**Advanced Persistent Reconnaissance Platform**  
*Built for security professionals. Engineered for reliability.*

---

[![Status](https://img.shields.io/badge/status-production--ready-22c55e?style=flat-square)](docs/STATUS.md)
[![Tests](https://img.shields.io/badge/tests-217%20passing-22c55e?style=flat-square&logo=pytest&logoColor=white)](#development--testing)
[![Python](https://img.shields.io/badge/python-3.11+-3b82f6?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-9.0.1-6366f1?style=flat-square)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-f59e0b?style=flat-square)](LICENSE)
[![Authorized Use](https://img.shields.io/badge/use-authorized%20testing%20only-ef4444?style=flat-square)](DISCLAIMER.md)

</div>

---

## Table of Contents

- [What is OzyRecon?](#what-is-ozyrecon)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Recon Modes](#recon-modes)
- [Reconnaissance Pipeline](#reconnaissance-pipeline)
- [Installation](#installation)
- [Configuration](#configuration)
- [CLI Reference](#cli-reference)
- [Output Artifacts](#output-artifacts)
- [OPSEC & Security](#opsec--security)
- [Development & Testing](#development--testing)
- [Documentation](#documentation)
- [Legal](#legal)

---

## What is OzyRecon?

OzyRecon is a **production-ready attack surface reconnaissance framework** for security professionals. It automates the full recon pipeline — from passive subdomain discovery through active scanning, evidence signing, AI-powered analysis, and diff tracking — in a single, auditable workflow.

```
  Target                   OzyRecon Pipeline                          Output
  ──────   ────────────────────────────────────────────────────   ──────────────────
  example  ──► Preflight → Scope Gate → Hunt → Analysis → Diff ──► analysis.json
  .com         Passive / Active / AI                                 analysis.md
                                                                     audit_bundle.tar.gz
```

**Why OzyRecon instead of running tools manually:**

| Capability | OzyRecon | Ad-hoc toolchain |
|------------|----------|-----------------|
| Architecture | Hexagonal — swap any tool or DB | Tightly coupled shell scripts |
| Evidence chain | SHA256-signed audit bundles | Raw output files, no provenance |
| Scope safety | Built-in validation, blocks OOB | Manual discipline required |
| Change detection | Diff across scans, auto-flagged | Manual comparison |
| Deduplication | Normalized on ingestion | Post-processing manual step |
| AI enrichment | Gemini / Claude prioritization | None |
| Modes | 6 purpose-built recon strategies | Single-mode scripts |
| API mode | FastAPI server, schedulable | Not available |

---

## Quick Start

```bash
# 1. Clone and set up
git clone https://github.com/SamBleed/OzyRecon.git && cd OzyRecon
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Validate environment
python ozy.py doctor

# 3. Initialize config
python ozy.py init
python ozy.py scope add example.com

# 4. Run reconnaissance
python ozy.py hunt example.com

# 5. Review results
python ozy.py inventory assets example.com
python ozy.py diff example.com
python ozy.py export example.com --format json
```

---

## Architecture

OzyRecon implements **Hexagonal Architecture (Ports & Adapters)** — business logic has zero dependency on external tools, databases, or frameworks. Every external integration is an adapter behind an interface.

### Layer Diagram

![OzyRecon Hexagonal Architecture](docs/diagrams/architecture.svg)

### Layer Responsibilities

| Layer | Path | Purpose | Key Components |
|-------|------|---------|----------------|
| **CLI** | `cli/` | User interface, command parsing | Click, 22 subcommands, interactive mode |
| **Core** | `src/core/` | Infrastructure, cross-cutting concerns | Bootstrap, Config, ToolManager, RateLimiter, StealthClient |
| **Application** | `src/application/` | Use cases, orchestration | OzyOrchestratorV10, ArtifactStudio, Port interfaces |
| **Domain** | `src/domain/` | Business entities — zero external deps | Asset, Service, Finding, Evidence, Scan (all `frozen=True`) |
| **Adapters** | `src/adapters/` | External integrations | SQLiteRepository, NmapAdapter, NucleiAdapter, WebhookAdapter |

### Dependency Flow

```
Domain          ← no dependencies, pure Python dataclasses (frozen=True)
   ↑
Application     ← depends on Domain only (via Port interfaces)
   ↑
Adapters        ← implements Application Ports, depends on Domain
   ↑
Core            ← cross-cutting: config, logging, rate limiting, tool resolution
   ↑
CLI             ← composes all layers, passes IDs via DI
```

### Domain Models

```python
# src/domain/models.py — all frozen, no external deps

@dataclass(frozen=True)
class Asset:
    domain: str                   # "api.example.com"
    type: str                     # "domain" | "subdomain" | "ip"
    ip: Optional[str] = None
    is_live: bool = False
    tags: List[str] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)

@dataclass(frozen=True)
class Finding:
    title: str
    severity: str                 # critical | high | medium | low | info
    description: str
    asset_id: str
    evidence_ids: List[str] = field(default_factory=list)
    vulnerability_type: Optional[str] = None

@dataclass(frozen=True)
class Evidence:
    content: str
    source: str
    content_hash: str             # SHA256
    signature: str                # signed with project key
    timestamp: datetime = field(default_factory=datetime.utcnow)

@dataclass(frozen=True)
class Scan:
    id: str
    target: str
    status: str                   # pending | running | completed | failed
    stats: Dict[str, int] = field(default_factory=lambda: {
        "subdomains": 0, "hosts_alive": 0, "ports_found": 0, "findings": 0
    })
```

<details>
<summary><b>Port & Adapter pattern — Asset Repository example</b></summary>

```python
# Port (interface) — lives in Application Layer
# src/application/ports/asset_repository.py
class IAssetRepository(ABC):
    @abstractmethod
    def save(self, asset: Asset) -> None: ...

    @abstractmethod
    def find_by_domain(self, domain: str) -> Asset | None: ...


# Adapter (concrete) — lives in Adapters Layer
# src/adapters/storage/sqlite_repository.py
class SQLiteAssetRepository(IAssetRepository):
    def save(self, asset: Asset) -> None:
        # Maps domain model → SQLAlchemy ORM model
        ...


# Use Case — depends on interface, not SQLite
# src/application/use_cases/orchestrator_v10.py
class OzyOrchestratorV10:
    def __init__(self, repository: IAssetRepository):
        self._repository = repository  # SQLite in prod, Mock in tests


# Test — zero database setup required
class MockAssetRepository(IAssetRepository):
    def __init__(self): self.assets: dict = {}
    def save(self, asset): self.assets[asset.domain] = asset
    def find_by_domain(self, domain): return self.assets.get(domain)
```

</details>

### Concurrency Model

```
                        OzyRecon Process
                   ───────────────────────────────────
                   │                                 │
             ThreadPoolExecutor               Subprocess Pool
             (3–5 Python workers)             (Go binaries)
             ────────────────────             ─────────────────
             HTTP probing                     subfinder
             DNS resolution                   dnsx
             API enrichment                   httpx / naabu
             Fuzzing                          nuclei / katana
                   │                                 │
                   └──────── Thread-safe state ──────┘
                             RateLimiter + Jitter
                             ResultCache
                             BackpressureQueue
```

---

## Recon Modes

OzyRecon ships six purpose-built modes accessible as top-level commands. Each mode tunes the pipeline behavior for a specific operational goal.

| Mode | Command | Intent | Use Case |
|------|---------|--------|----------|
| **Hunt** | `ozy hunt <target>` | Balanced passive + active discovery | Bug bounty, general recon |
| **Continuous** | `ozy continuous <target>` | Differential monitoring with scheduler | Long-running ASM, alert on changes |
| **Research** | `ozy research <target>` | Deep passive, no active scanning | OSINT, stealth initial recon |
| **Campaign** | `ozy campaign <target>` | Multi-target batch execution | Large scope programs |
| **Forensic** | `ozy forensic <target>` | Evidence-focused with full audit trail | Incident reconstruction |
| **Servicio** | `ozy servicio <target>` | Service/API mode for platform integration | OzyPlatform bridge |

### Mode Options (all modes share these flags)

```bash
ozy <mode> <target> [OPTIONS]

  --threads INT            Parallel workers (default: from config)
  --speed slow|normal|fast Execution pace (default: normal)
  --depth INT              Subdomain recursion depth (default: 1)
  --intent passive|balanced|aggressive  Operational intent
  --steroids / --no-steroids  Enable deep discovery (default: on)
  --ghost                  Route via Tor for OPSEC
  --dry-run                Print plan without executing
  --json                   Output in JSON format
```

---

## Reconnaissance Pipeline

All modes run through the same five-phase pipeline. Each phase has a defined input contract, output, and failure behavior.

![Reconnaissance Pipeline](docs/diagrams/pipeline-flow.svg)

### Phase Overview

| # | Phase | Typical Duration | Failure Behavior |
|---|-------|-----------------|-----------------|
| 1 | **Preflight Verification** | 5–10 sec | Hard stop — blocks execution |
| 2 | **Scope & Authorization** | < 1 sec | Hard stop — target rejected |
| 3 | **Adaptive Hunt** | 5–20 min | Degraded — failed tools skipped |
| 4 | **Analysis Snapshot** | 30 sec–2 min | Partial results with warning |
| 5 | **Diff Intelligence** | 1–5 sec | Skip if no baseline exists |

---

### Phase 1 · Preflight Verification

Validates the full execution environment before any expensive or network operations.

```
Checks performed:
  ✓ Python version         >= 3.11
  ✓ Required binaries      nmap, nuclei, subfinder, httpx, katana, gowitness, dnsx, naabu
  ✓ Python packages        sqlalchemy, requests, rich, click, pyyaml, cryptography, curl_cffi
  ✓ SQLite database        Connection valid, schema migrations applied
  ✓ Network reachability   DNS for 8.8.8.8 + TCP to 1.1.1.1:443
  ✓ Scope file             config/scope.yaml exists with at least one allowed domain
  ✓ Required folders       runs/, resources/, config/, tools/go/bin/

Run manually: python ozy.py doctor
```

---

### Phase 2 · Scope & Authorization Gate

Every target passes through a strict normalization and validation chain before any scanning begins.

```
Input: "http://API.Example.COM/some/path"
         │
         ▼  normalize_lookup_target()
         │  → strip scheme, lowercase, strip trailing dot/path
         ▼
      "api.example.com"
         │
         ▼  extract root domain
         │
      "example.com"
         │
         ├── Wildcard match?     *.example.com → PASS
         ├── Exact match?        example.com   → PASS
         ├── Private IP?         10.x / 192.168.x / 127.x → REJECT (unless explicit)
         └── Forbidden patterns? internal / staging / dev  → REJECT

Output: ✅ AUTHORIZED  or  ❌ REJECTED: <reason>
```

---

### Phase 3 · Adaptive Hunt

The core discovery phase. Passive sources run first, active scanning only after scope is confirmed.

```
┌────────────────── PASSIVE DISCOVERY (2–5 min) ───────────────────┐
│                                                                    │
│  crt.sh       ──► Certificate Transparency logs                   │
│  Censys        ──► Historical SSL certificates                    │
│  CommonCrawl   ──► Archived URL mentions                          │
│  Wayback       ──► Archived pages and endpoints                   │
│  subfinder     ──► Aggregated passive subdomain enumeration       │
│  ASN / BGP     ──► IP range and network block enumeration         │
│                                                                    │
├────────────────── ACTIVE RESOLUTION (3–8 min) ────────────────────┤
│                                                                    │
│  dnsx          ──► A / AAAA / CNAME / MX / TXT with retries       │
│  httpx         ──► HTTP/HTTPS probing + tech fingerprinting        │
│  gowitness     ──► Automated screenshots for manual review         │
│  banner grab   ──► Ports 21, 22, 25, 80, 443, 3306, 5432          │
│                                                                    │
└────────────────── SERVICE ANALYSIS (5–15 min) ────────────────────┘
                                                                     │
  nmap            ──► Top 1000 ports (or custom port list)           │
  nmap -sV        ──► Service version detection                      │
  nmap --script   ──► Safe NSE scripts (auth, ssl-cert, etc.)        │
  naabu           ──► Fast port scanning across large IP ranges      │
  nuclei          ──► Template-based vulnerability scanning          │
```

---

### Phase 4 · Analysis Snapshot

Transforms raw tool output into structured, signed intelligence.

```
Raw Tool Outputs
      │
      ▼
Finding Aggregation   ─── Merge from all tools, deduplicate by fingerprint
      │
      ▼
Risk Scoring          ─── Apply config/scoring.yaml weights (tech + exposure)
      │
      ▼
Attack Surface Map    ─── Flag admin panels, outdated services, misconfigs
      │
      ▼
AI Enrichment         ─── (optional) Gemini / Claude contextualization
      │
      ▼
Evidence Signing      ─── SHA256 hash all raw outputs + sign with project key
      │
      ▼
   analysis.json  ·  analysis.md  ·  flow_summary.json  ·  audit_bundle.tar.gz
```

---

### Phase 5 · Diff Intelligence

Compares the current scan against the previous baseline stored in SQLite.

```
Previous Scan (DB)       Current Scan            Result
──────────────────────   ─────────────────────   ──────────────────────
api.example.com          api.example.com         UNCHANGED
admin.example.com        (not present)           ⚠  REMOVED
                         dev.example.com         🆕 NEW
cdn.example.com:80       cdn.example.com:8080    🔴 CHANGED (new port)

Run manually: python ozy.py diff example.com
```

---

## Installation

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Linux (Ubuntu 20.04+) / macOS 12+ | Ubuntu 22.04 LTS |
| Python | 3.11 | 3.12+ |
| RAM | 2 GB | 4 GB |
| Disk | 500 MB (binaries) | 2 GB (binaries + scan data) |
| Network | Unrestricted outbound TCP/UDP | — |

---

### Step-by-Step Setup

**1. Clone the repository**

```bash
git clone https://github.com/SamBleed/OzyRecon.git
cd OzyRecon
```

**2. Create virtual environment**

```bash
python -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate.bat     # Windows (not officially supported)
```

**3. Install Python dependencies**

```bash
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .                # editable install (recommended for dev)
```

**4. Install system binary: nmap**

```bash
# Ubuntu / Debian
sudo apt install nmap

# Arch Linux
sudo pacman -S nmap

# macOS
brew install nmap
```

> **Go binaries** (`subfinder`, `httpx`, `nuclei`, `katana`, `gowitness`, `dnsx`, `naabu`) are pre-compiled in `tools/go/bin/` — no Go toolchain required.

**5. Verify environment**

```bash
python ozy.py --version
# → OzyRecon v9.0.1

python ozy.py doctor
# → All checks passed — READY

python ozy.py init
# → Creates config/, data/, runs/

./scripts/pre-flight.sh
# → Full environment validation
```

---

### Python Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `sqlalchemy` | >= 2.0 | ORM, SQLite storage, migrations |
| `click` | >= 8.1 | CLI framework |
| `rich` | >= 13.0 | Terminal output formatting |
| `requests` | >= 2.31 | HTTP client |
| `pyyaml` | >= 6.0 | Configuration parsing |
| `curl_cffi` | >= 0.7.0 | TLS fingerprint randomization (stealth) |
| `cryptography` | >= 42.0 | Evidence signing (SHA256) |
| `fastapi` | >= 0.110.0 | API server (`ozy serve`) |
| `uvicorn` | >= 0.27.0 | ASGI runtime for API mode |
| `prompt_toolkit` | >= 3.0 | Interactive terminal mode |
| `jinja2` | >= 3.1 | Report template rendering |
| `google-generativeai` | latest | Gemini AI enrichment (optional) |

---

### Troubleshooting

<details>
<summary><b>ModuleNotFoundError: No module named 'sqlalchemy'</b></summary>

You are likely outside the virtual environment.

```bash
source venv/bin/activate
pip install -r requirements.txt
```

</details>

<details>
<summary><b>Binary not found: nmap / nuclei / subfinder</b></summary>

```bash
# For nmap — install via package manager (see above)
# For Go binaries — verify they exist:
ls tools/go/bin/

# If missing, the bootstrap script can download them:
./bootstrap-ozyrecon.sh
```

</details>

<details>
<summary><b>Permission denied: ./scripts/pre-flight.sh</b></summary>

```bash
chmod +x scripts/pre-flight.sh
./scripts/pre-flight.sh
```

</details>

<details>
<summary><b>SQLite database errors on first run</b></summary>

```bash
# Re-initialize to create the schema
python ozy.py init
python ozy.py doctor
```

</details>

---

## Configuration

OzyRecon uses three primary config files in `config/`. All are YAML.

### `config/scope.yaml` — Authorization

Defines the authorized attack surface. **Required before any scan.**

```yaml
target: example.com

allowed_domains:
  - example.com
  - "*.example.com"          # wildcard subdomain
  - test.example.org         # additional domain

forbidden_patterns:
  - internal
  - staging
  - dev

profiles_allowed:
  - passive
  - safe-active              # aggressive requires explicit listing

authorization:
  type: bug-bounty           # bug-bounty | pentest | internal
  reference: "HackerOne Program #12345"
  date: "2026-05-30"
  authorized_by: "Program Owner"
```

**Scope management via CLI:**

```bash
python ozy.py scope add example.com          # add domain to scope
python ozy.py scope list                     # view current scope
python ozy.py scope remove example.com       # remove domain
```

---

### `config/config.yaml` — Engine Settings

Copy from `config/config.example.yaml` and customize.

```yaml
# ── Performance ────────────────────────────────────
threads: 50
timeout: 10                   # seconds per HTTP request
rate_limit: 50                # requests/sec for nuclei

tools_path: "tools/go/bin"    # path to Go binaries

# ── Auto Rate Limiting ─────────────────────────────
auto_rate_limit:
  enabled: true
  max_requests_per_min: 200
  check_interval: 10          # seconds between rate checks
  error_threshold: 10         # consecutive errors before slow down
  ban_threshold: 50           # errors before kill switch
  slow_mode_threshold: 1000   # response time (ms) to trigger slow mode

# ── API Keys (optional, improve passive discovery) ─
api_keys:
  shodan:          ""
  virustotal:      ""
  censys_id:       ""
  censys_secret:   ""
  securitytrails:  ""
  github:          ""

# ── Telegram Notifications (optional) ─────────────
notifications:
  telegram_token:   "YOUR_BOT_TOKEN"
  telegram_chat_id: "YOUR_CHAT_ID"
  alert_level: "medium"       # critical | high | medium | low | all
  always_notify: true

# ── AI Enrichment (optional) ──────────────────────
ai:
  gemini_api_key: ""
  claude_api_key: ""
```

**API key management via CLI:**

```bash
python ozy.py keys add shodan "YOUR_KEY"
python ozy.py keys list
```

---

### `config/scoring.yaml` — Risk Scoring

Controls how findings are weighted. Auto-updated by the learning engine.

```yaml
confidence: 0.6
weights:
  Django:
    nuclei: 0.9
    dalfox: 0.4
  Apache:
    nuclei: 0.85
    nmap: 0.7
```

---

### `config/scheduler.yaml` — Scheduled Scans

```yaml
tasks:
  - target: example.com
    profile: safe-active
    interval_hours: 24
    enabled: true
```

**Scheduler management via CLI:**

```bash
python ozy.py schedule list
python ozy.py schedule add example.com --profile safe-active --interval 24
python ozy.py schedule remove example.com
```

---

## CLI Reference

```bash
python ozy.py [--debug] [--config PATH] [--version] <command> [args...]
```

### Recon Modes

| Command | Description | Key Options |
|---------|-------------|-------------|
| `hunt <target>` | Full passive + active recon (default mode) | `--intent`, `--depth`, `--ghost` |
| `continuous <target>` | Differential monitoring with scheduler | `--intent`, `--speed` |
| `research <target>` | Deep passive, zero active scanning | `--depth`, `--steroids` |
| `campaign <target>` | Multi-target batch execution | `--threads`, `--speed` |
| `forensic <target>` | Evidence-focused full audit trail | `--intent`, `--depth` |
| `servicio <target>` | Service mode for platform integration | `--json` |
| `flow <target>` | Full 5-phase pipeline in one command | `--profile`, `--dry-run` |

```bash
# Examples
python ozy.py hunt example.com --intent balanced --depth 2
python ozy.py hunt example.com --ghost               # route via Tor
python ozy.py flow example.com --profile safe-active --dry-run
python ozy.py continuous example.com --speed slow
```

---

### Intelligence & Analysis

| Command | Description | Key Options |
|---------|-------------|-------------|
| `analyze <host>` | Deep AI analysis of a specific asset | — |
| `diff <target>` | Compare last two scans, show changes | `--scan-id`, `--previous-scan-id`, `--format` |
| `paths <target>` | Analyze attack vectors and lateral movement | — |
| `secrets <target>` | Search JS files for hardcoded secrets | `--limit`, `--threads`, `--verify` |
| `exploits <target>` | Suggest relevant CVEs for discovered tech | `--tech` |
| `compliance-check <target>` | Validate scan results meet standards | — |

```bash
python ozy.py analyze api.example.com
python ozy.py diff example.com --format json
python ozy.py secrets example.com --limit 20 --verify
python ozy.py paths example.com
python ozy.py exploits example.com --tech Django --tech Nginx
```

---

### Inventory & Assets

| Command | Description | Key Options |
|---------|-------------|-------------|
| `inventory assets <target>` | List all discovered subdomains | `--live`, `--limit` |
| `export <target>` | Export all intelligence for a target | `--format csv\|json`, `--output` |
| `screenshot <url>` | Take screenshot of target URL | — |

```bash
python ozy.py inventory assets example.com --live --limit 100
python ozy.py export example.com --format json --output results.json
python ozy.py export example.com --format csv
python ozy.py screenshot https://example.com
```

---

### Scope & Authorization

| Command | Description |
|---------|-------------|
| `scope add <domain>` | Add domain to authorized scope |
| `scope remove <domain>` | Remove domain from scope |
| `scope list` | Show current authorized scope |

---

### System & Monitoring

| Command | Description | Key Options |
|---------|-------------|-------------|
| `doctor` | Validate full environment | — |
| `init` | Initialize config, DB, folder structure | — |
| `verify` | Strict anti-smoke verification (binaries + contracts) | — |
| `self-test` | Run internal logic tests | — |
| `watch <domain>` | Monitor CT logs for new assets in real-time | `--interval` |
| `serve` | Start FastAPI server for programmatic access | `--host`, `--port`, `--scheduler` |
| `schedule list\|add\|remove` | Manage scheduled scans | `--profile`, `--interval` |
| `keys add\|list` | Manage API keys | — |

```bash
python ozy.py watch example.com --interval 300     # check CT logs every 5 min
python ozy.py serve --host 127.0.0.1 --port 8000 --scheduler
python ozy.py verify
```

---

### API Endpoints (serve mode)

When running `ozy serve`, the following REST endpoints are available:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/targets` | List all tracked targets |
| `GET` | `/sessions` | List all scan sessions |
| `POST` | `/hunt` | Trigger a new hunt |
| `GET` | `/diff` | Compare latest scans |
| `GET` | `/schedule` | List scheduled tasks |

---

## Output Artifacts

Every scan run produces a timestamped directory under `runs/`.

### Directory Structure

```
runs/
└── example.com_20260530_120000/
    ├── analysis.json               ← machine-readable findings (normalized)
    ├── analysis.md                 ← executive summary (human-readable)
    ├── flow_summary.json           ← execution telemetry, tool runtimes
    └── audit_a1b2c3d4.tar.gz       ← cryptographically signed evidence bundle
        ├── evidence/
        │   ├── subfinder_raw.txt       (SHA256 signed)
        │   ├── httpx_output.json       (SHA256 signed)
        │   ├── nmap_scan.xml           (SHA256 signed)
        │   └── nuclei_results.json     (SHA256 signed)
        ├── metadata.json           ← timestamps, tool versions, arguments
        ├── signatures.json         ← SHA256 hash manifest of all evidence
        └── flow_summary.json       ← execution trace
```

### `analysis.json` Schema

```json
{
  "scan_id": "a1b2c3d4",
  "timestamp": "2026-05-30T12:00:00Z",
  "target": "example.com",
  "assets": [
    {
      "domain": "api.example.com",
      "ip": "203.0.113.10",
      "is_live": true,
      "http_status": 200,
      "technologies": ["nginx/1.18.0", "Express.js"],
      "services": [
        { "port": 443, "protocol": "tcp", "service_name": "https", "product": "nginx", "version": "1.18.0" }
      ],
      "findings": [
        {
          "id": "missing-csp",
          "severity": "medium",
          "title": "Missing Content-Security-Policy header",
          "evidence_hash": "sha256:abc123..."
        }
      ]
    }
  ],
  "summary": {
    "total_assets": 12,
    "hosts_alive": 8,
    "ports_found": 34,
    "findings": { "critical": 0, "high": 1, "medium": 3, "low": 5, "info": 12 }
  }
}
```

### `flow_summary.json` — Execution Telemetry

```json
{
  "scan_id": "a1b2c3d4",
  "target": "example.com",
  "profile": "safe-active",
  "phases": {
    "preflight": { "status": "ok", "duration_sec": 6 },
    "scope_gate": { "status": "authorized", "duration_sec": 0.1 },
    "hunt": { "status": "completed", "duration_sec": 742, "subdomains_found": 12 },
    "analysis": { "status": "completed", "duration_sec": 87 },
    "diff": { "status": "baseline_missing", "duration_sec": 0.2 }
  },
  "tools_executed": ["subfinder", "dnsx", "httpx", "nmap", "nuclei"],
  "total_duration_sec": 835
}
```

---

## OPSEC & Security

### Built-in OPSEC Module (`src/opsec/`)

OzyRecon includes a dedicated OPSEC layer for operational safety:

| Component | File | Function |
|-----------|------|----------|
| **StealthClient** | `src/core/stealth_client.py` | TLS fingerprint randomization via `curl_cffi` |
| **IdentityRotation** | `src/opsec/identity_rotation.py` | Rotate User-Agent, headers, and TLS parameters |
| **Jitter** | `src/opsec/jitter.py` | Randomized inter-request delays |
| **RateLimiter** | `src/opsec/rate_limiter.py` | Adaptive rate limiting with auto-backoff |
| **WAF Detector** | `src/opsec/waf_detector.py` | Detect and adjust behavior for WAF presence |
| **ProxyRotator** | `src/opsec/proxy_rotator.py` | Rotate through proxy list |
| **KillSwitch** | `src/opsec/kill_switch.py` | Halt all operations if ban threshold reached |

Activate Tor routing with `--ghost`:

```bash
python ozy.py hunt example.com --ghost
```

---

### Pre-commit OPSEC Guard

`scripts/opsec_check.py` runs as a pre-commit hook and **blocks** commits containing:

```
Blocked:
  - Real target domains (anything not example.com / test.com / example.org)
  - Public IPv4 addresses (non-RFC1918 / non-RFC5737)
  - API key patterns: AKIA*, ghp_*, sk-*, Bearer *

Allowed (safe test data):
  10.x.x.x, 192.168.x.x, 172.16–31.x.x   RFC 1918 private ranges
  192.0.2.x, 198.51.100.x, 203.0.113.x   RFC 5737 documentation ranges
  127.x.x.x                               Loopback
  example.com, test.com, example.org       IANA-reserved test domains
```

---

### Data Handling

```
Scan data        ─── Stored locally in data/ozyrecon.db + runs/
Credentials      ─── Never logged, stored in resources/keys/ (gitignored)
Network traffic  ─── No telemetry sent (all traffic goes to scan target only)
Evidence chain   ─── SHA256-signed with project key, stored in audit bundle
Audit log        ─── All tool executions recorded in flow_summary.json
```

---

## Development & Testing

### Running Tests

```bash
source venv/bin/activate

pytest                                             # full suite (217 tests)
pytest -v                                          # verbose output
pytest tests/core/test_tool_manager_sync.py       # single module
pytest -k "test_scope"                             # pattern filter
pytest -x                                          # stop on first failure
pytest --cov=src --cov-report=html                 # coverage report → htmlcov/
```

### Test Organization

```
tests/
├── core/           Core infrastructure (ToolManager, config, context, plugins)
├── adapters/       External integrations (SQLite repo, API clients)
├── intelligence/   AI analysis, scoring, evidence linking
├── validation/     Scope validation, target normalization, policy engine
├── cli/            CLI command integration tests
└── integration/    End-to-end workflow tests with DB fixture
```

> Tests run in full isolation: temporary SQLite in `/tmp`, mocked HTTP via `responses` library, filesystem sandboxed to pytest temp dirs. Always activate the venv before running.

---

### Code Quality

```bash
ruff check src/ tests/           # lint
mypy src/ --strict                # type checking (strict mode)
bandit -r src/                    # security static analysis
```

---

### Contributing

```bash
# 1. Fork and clone
git clone https://github.com/SamBleed/OzyRecon.git
cd OzyRecon
git checkout -b feature/your-feature

# 2. Install dev dependencies
pip install -r requirements.txt
pip install -e .

# 3. Make changes
#    - Follow Conventional Commits: feat:, fix:, docs:, refactor:
#    - New logic requires tests with >= 80% coverage
#    - Run opsec check before committing

# 4. Verify
pytest && ruff check src/ && mypy src/
./scripts/opsec_check.py

# 5. Push
git commit -m "feat: add custom wordlist support for fuzzer"
git push origin feature/your-feature
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for detailed workflow and standards.

---

## Documentation

| Document | Description |
|----------|-------------|
| [`docs/STATUS.md`](docs/STATUS.md) | Current production status, test metrics |
| [`docs/USAGE.md`](docs/USAGE.md) | Complete CLI reference with examples |
| [`docs/architecture.md`](docs/architecture.md) | Hexagonal architecture deep dive |
| [`docs/modes.md`](docs/modes.md) | Detailed description of all 6 recon modes |
| [`docs/WORKFLOWS.md`](docs/WORKFLOWS.md) | Real-world recon scenarios with full output |
| [`docs/INSTALL.md`](docs/INSTALL.md) | Multi-platform installation guide |
| [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) | Evidence signing and audit standards |
| [`docs/RUNTIME_CONTRACT.md`](docs/RUNTIME_CONTRACT.md) | API contract for platform integration |
| [`docs/BRIDGE_CONTRACT.md`](docs/BRIDGE_CONTRACT.md) | OzyPlatform bridge specification |
| [`docs/EXCLUSIONS.md`](docs/EXCLUSIONS.md) | Explicit non-goals (no exploit exec, no payload gen) |
| [`docs/opsec.md`](docs/opsec.md) | OPSEC module documentation |
| [`DISCLAIMER.md`](DISCLAIMER.md) | Legal boundaries and responsible use |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution workflow and code standards |
| [`CHANGELOG.md`](CHANGELOG.md) | Version history |

---

## Legal

**OzyRecon is for authorized security testing only.**

Users are solely responsible for:
- Obtaining **explicit written authorization** before scanning any target
- Complying with local laws and regulations
- Respecting bug bounty program rules of engagement

Unauthorized scanning is illegal in most jurisdictions and may result in criminal prosecution. The authors assume no liability for misuse.

See [`DISCLAIMER.md`](DISCLAIMER.md) for the full legal statement.

Licensed under the [MIT License](LICENSE).

---

<div align="center">

**Docs** · [docs/](docs/)  ·  **Issues** · [GitHub Issues](https://github.com/SamBleed/OzyRecon/issues)  ·  **Status** · [docs/STATUS.md](docs/STATUS.md)

*Built for the security community. Use responsibly.*

</div>
