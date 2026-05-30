# OzyRecon v9.0.1

> **Advanced Persistent Reconnaissance Platform**  
> Authorized reconnaissance engine for security professionals, penetration testers, and bug bounty hunters.

[![Production Status](https://img.shields.io/badge/status-production--ready-green.svg)](docs/STATUS.md)
[![Tests](https://img.shields.io/badge/tests-217%20passing-brightgreen.svg)](#development--testing)
[![Version](https://img.shields.io/badge/version-9.0.1-blue.svg)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)

---

## Overview

OzyRecon is a production-ready reconnaissance framework designed for security professionals who need reliable, auditable, and comprehensive asset discovery. Built on **Hexagonal Architecture (Ports & Adapters)**, the platform prioritizes maintainability, testability, and extensibility while maintaining high performance for real-world security assessments.

### Key Differentiators

**Architecture-First Design**: Unlike monolithic reconnaissance tools that tightly couple scanning logic with output generation, OzyRecon separates business logic (asset discovery, vulnerability detection) from infrastructure concerns (database persistence, external tool integration). This enables independent testing of core logic and seamless integration with external systems.

**Evidence-Based Reporting**: Every finding is cryptographically signed with SHA256 hashes and accompanied by raw tool output, timestamps, and execution metadata. This audit trail ensures findings are reproducible and defensible in formal security assessments.

**Workflow Automation**: The platform automates the reconnaissance pipeline from passive discovery through active scanning, eliminating manual coordination of disparate tools. Scan results are automatically deduplicated, normalized, and enriched with context from multiple sources.

**Operational Safety**: Built-in scope validation, rate limiting, and authorization checks prevent accidental scanning of out-of-scope assets. All commands require explicit scope configuration before execution.

---

## Core Architecture

OzyRecon implements a layered architecture that enforces separation of concerns and enables independent evolution of components:

### Domain Layer (`src/domain/`)

Pure business logic with zero external dependencies. Defines:

- **Entities**: `Asset`, `Finding`, `Evidence` — immutable dataclasses representing core concepts
- **Domain Events**: `AssetDiscovered`, `FindingDetected`, `ScanCompleted` — event-driven notifications
- **Value Objects**: `IPAddress`, `Domain`, `Port` — validated primitive wrappers
- **Domain Services**: `EvidenceService` — business rule enforcement

The domain layer has no knowledge of databases, HTTP clients, or external tools. This ensures business logic remains testable and portable.

### Application Layer (`src/application/`)

Orchestrates use cases by coordinating domain services and infrastructure adapters. Defines:

- **Use Cases**: `OrchestratorV10` — coordinates full reconnaissance workflows
- **Ports (Interfaces)**: `IAssetRepository`, `IToolProvider`, `IPolicyEngine` — contracts for external systems
- **Application Services**: `ArtifactStudio` — cross-cutting concerns like reporting

Use cases depend on port interfaces, not concrete implementations. This enables testing with mock adapters and runtime adapter swapping.

### Adapter Layer (`src/adapters/`)

Concrete implementations of application ports. Includes:

- **Storage Adapters**: `SQLiteAssetRepository` — persistence via SQLAlchemy
- **Tool Adapters**: `NmapAdapter`, `NucleiAdapter`, `SubfinderAdapter` — external tool integration
- **API Adapters**: `OzyRegistryAdapter`, `OzyPolicyAdapter` — external service clients
- **Event Adapters**: `WebhookAdapter` — notification delivery

Adapters translate between external system interfaces and internal domain models. They handle serialization, error recovery, and rate limiting.

### Infrastructure Layer (`src/core/`, `src/intelligence/`)

Cross-cutting concerns and supporting services:

- **Context Management**: Session lifecycle, configuration loading
- **Rate Limiting**: Adaptive rate limiting with jitter to avoid WAF detection
- **Stealth Client**: Randomized user agents, TLS fingerprint variation
- **AI Analysis**: Optional enrichment via Gemini, OpenAI, or Ollama

### Concurrency Model

OzyRecon uses a hybrid concurrency strategy to maximize throughput while avoiding resource exhaustion:

**Thread Pool Orchestration**: Python-native `ThreadPoolExecutor` with bounded worker pools (typically 3-5 workers) manages I/O-bound operations like HTTP probing and fuzzing. This prevents local network stack saturation while enabling parallel execution.

**Subprocess Delegation**: CPU-intensive and memory-intensive operations are delegated to compiled Go binaries (`subfinder`, `nmap`, `nuclei`). Each subprocess runs independently, bypassing Python's Global Interpreter Lock (GIL) and allowing true parallelism.

**Thread-Safe State Management**: Shared state like rate limiters and result caches use fine-grained locking (`threading.Lock`) at the operation level, not the object level. This minimizes contention and allows concurrent access without deadlocks.

**Backpressure Handling**: Worker pools use bounded queues with rejection policies. When the queue fills, the orchestrator pauses submission until capacity is available, preventing memory exhaustion.

---

## Reconnaissance Pipeline

OzyRecon executes reconnaissance in five phases, each with defined inputs, outputs, and failure handling:

### Phase 1: Preflight Verification

**Duration**: 5-10 seconds  
**Purpose**: Validate execution environment before expensive operations

**Checks**:
- Binary presence: Verifies `nmap`, `nuclei`, `subfinder`, `httpx`, `katana`, `gowitness`, `dnsx` in PATH or local `tools/go/bin/`
- Python dependencies: Confirms `sqlalchemy`, `requests`, `rich`, `click`, `pyyaml`, `cryptography` installed
- Database connectivity: Tests SQLite connection and schema migration state
- Network connectivity: Attempts DNS resolution of `8.8.8.8` and TCP connection to `1.1.1.1:443`
- Scope validation: Confirms at least one authorized domain in `config/scope.yaml`

**Failure Modes**:
- Missing binaries: Prints installation commands and exits with code 1
- Database corruption: Offers schema reset or backup restoration
- Network failure: Warns but allows execution (passive discovery may still work)
- Empty scope: Blocks execution with instructions to add domains

### Phase 2: Scope & Authorization

**Duration**: < 1 second  
**Purpose**: Enforce scanning boundaries and prevent out-of-scope activity

**Operations**:
- Loads `config/scope.yaml` containing authorized domains and forbidden patterns
- Normalizes target input (strips protocols, trailing dots, paths)
- Extracts root domain and validates against allowed list
- Checks for wildcard matches (`*.example.com`)
- Rejects private IP ranges (10.x, 192.168.x, 127.x) unless explicitly allowed
- Rejects link-local and multicast addresses
- Applies forbidden pattern filters (`internal`, `staging`, `dev`, etc.)

**Output**: Boolean authorization decision with rejection reason if denied

### Phase 3: Adaptive Hunt

**Duration**: 5-20 minutes (depends on target size)  
**Purpose**: Discover all in-scope assets via passive and active techniques

**Passive Discovery** (2-5 minutes):
- **Certificate Transparency**: Queries `crt.sh` and `Censys` for historical certificates
- **DNS Records**: Enumerates A, AAAA, CNAME, MX, TXT records
- **Public Archives**: Searches `CommonCrawl`, `Wayback Machine` for historical mentions
- **ASN Enumeration**: Identifies IP ranges via `whois` and `BGP` data
- **Subfinder Aggregation**: Runs `subfinder` with all free sources enabled

**Active Resolution** (3-8 minutes):
- **DNS Resolution**: Resolves discovered subdomains via `dnsx` with retries
- **HTTP Probing**: Tests HTTP/HTTPS connectivity via `httpx` with custom headers
- **Technology Detection**: Fingerprints web servers, frameworks, CDNs via response headers
- **Screenshot Capture**: Takes visual snapshots via `gowitness` for manual review
- **Service Banner Grabbing**: Connects to common ports (21, 22, 25, 80, 443, 3306, 5432) for version detection

**Service Analysis** (5-15 minutes):
- **Port Scanning**: Runs `nmap` with top 1000 ports (or custom port list from profile)
- **Service Enumeration**: Detects service versions via `nmap -sV` on discovered ports
- **OS Detection**: Attempts OS fingerprinting via TCP/IP stack analysis (optional, requires elevated privileges)
- **NSE Scripts**: Executes safe `nmap` scripts for additional intelligence (auth methods, SSL certs, etc.)

**Deduplication**: All discovered assets are normalized (lowercased, trailing dots stripped) and deduplicated by domain name before storage.

### Phase 4: Analysis Snapshot

**Duration**: 30 seconds - 2 minutes  
**Purpose**: Generate structured intelligence from raw scan data

**Operations**:
- **Finding Aggregation**: Merges results from multiple tools, prioritizes by severity
- **Risk Scoring**: Applies scoring rules from `config/scoring.yaml` based on service type, exposure, and configuration
- **Attack Surface Mapping**: Identifies likely attack vectors (exposed admin panels, outdated services, misconfigurations)
- **AI Enrichment** (optional): Sends anonymized findings to LLM for contextualization and prioritization
- **Evidence Signing**: Computes SHA256 hashes of raw tool outputs and stores in `evidence/` directory

**Outputs**:
- `analysis.json`: Machine-readable findings with standardized schema
- `analysis.md`: Human-readable executive summary with risk breakdown
- `flow_summary.json`: Execution telemetry (tool runtime, error count, asset count)

### Phase 5: Diff Intelligence

**Duration**: 1-5 seconds  
**Purpose**: Detect changes between scan iterations

**Operations**:
- Loads previous scan results from database
- Compares current assets against historical assets by domain name
- Identifies new assets (newly discovered subdomains)
- Identifies removed assets (no longer resolving)
- Identifies changed assets (HTTP status changes, service version updates)
- Flags high-impact changes (newly exposed services, authentication changes)

**Output**: Diff report highlighting actionable changes since last scan

---

## Output Artifacts

### Analysis Files

**`analysis.json`** — Normalized machine-readable output:
```json
{
  "scan_id": "a1b2c3d4",
  "timestamp": "2026-05-30T12:00:00Z",
  "target": "example.com",
  "assets": [
    {
      "domain": "api.example.com",
      "ip": "203.0.113.10",
      "http_status": 200,
      "technologies": ["nginx/1.18.0", "Express.js"],
      "ports": [22, 80, 443],
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
    "live_services": 8,
    "findings": {"critical": 0, "high": 1, "medium": 3, "low": 5}
  }
}
```

**`analysis.md`** — Executive summary for manual review:
```markdown
# Reconnaissance Report: example.com
Generated: 2026-05-30 12:00:00 UTC

## Executive Summary
Discovered 12 subdomains, 8 with active HTTP services.
Identified 1 high-severity finding requiring immediate attention.

## High-Priority Findings
1. [HIGH] Authentication bypass on admin.example.com
   - Impact: Administrative access without credentials
   - Evidence: HTTP 200 on /admin/users without session cookie
   
## Attack Surface
- api.example.com: REST API with 15 endpoints discovered
- cdn.example.com: Cloudflare CDN with origin IP exposed
- staging.example.com: Misconfigured with production credentials

## Recommendations
1. Restrict access to admin.example.com via IP whitelist
2. Remove staging.example.com from public DNS
3. Implement rate limiting on api.example.com
```

**`flow_summary.json`** — Execution telemetry for debugging:
```json
{
  "execution_time_seconds": 847,
  "phases": {
    "passive_discovery": {"runtime": 142, "errors": 0, "assets_discovered": 12},
    "active_resolution": {"runtime": 203, "errors": 2, "assets_resolved": 10},
    "service_analysis": {"runtime": 482, "errors": 0, "ports_scanned": 12000},
    "vulnerability_detection": {"runtime": 20, "errors": 0, "findings": 9}
  },
  "tool_executions": [
    {"tool": "subfinder", "runtime": 87, "exit_code": 0, "output_lines": 145},
    {"tool": "httpx", "runtime": 34, "exit_code": 0, "requests": 12},
    {"tool": "nmap", "runtime": 482, "exit_code": 0, "hosts_scanned": 10}
  ]
}
```

### Audit Bundles

**`audit_[session_id].tar.gz`** — Cryptographically signed evidence archive:

Structure:
```
audit_a1b2c3d4.tar.gz
├── evidence/
│   ├── subfinder_output.txt (SHA256 signed)
│   ├── httpx_output.json (SHA256 signed)
│   ├── nmap_scan.xml (SHA256 signed)
│   └── nuclei_results.json (SHA256 signed)
├── metadata.json (timestamps, tool versions, command arguments)
├── signatures.json (SHA256 hashes of all evidence files)
└── flow_summary.json (execution trace)
```

**Purpose**: Provides tamper-evident evidence for compliance audits, penetration test reports, and bug bounty submissions. Signatures can be independently verified to prove findings were generated by OzyRecon without modification.

---

## Installation

### System Requirements

- **Operating System**: Linux (Ubuntu 20.04+, Arch, Debian), macOS 12+
- **Python**: 3.11 or higher (3.14 tested and supported)
- **Memory**: 2GB minimum, 4GB recommended for large targets
- **Disk Space**: 500MB for binaries, 1GB+ for scan data
- **Network**: Unrestricted outbound TCP/UDP access for scanning

### Dependencies

**Python Packages** (installed via `requirements.txt`):
- `sqlalchemy>=2.0` — Database ORM and migrations
- `requests>=2.31` — HTTP client library
- `rich>=13.0` — Terminal output formatting
- `click>=8.1` — CLI framework
- `pyyaml>=6.0` — Configuration parsing
- `curl_cffi>=0.7.0` — TLS fingerprint randomization
- `cryptography>=42.0` — Evidence signing
- `jinja2>=3.1` — Template rendering
- `weasyprint>=62.0` — PDF generation (legacy, optional)

**Go Binaries** (pre-compiled, included in `tools/go/bin/`):
- `subfinder` — Passive subdomain enumeration
- `httpx` — HTTP probing and technology detection
- `nuclei` — Vulnerability scanning via templates
- `nmap` — Port scanning and service detection (system-wide install required)
- `katana` — Web crawling and endpoint discovery
- `gowitness` — Automated screenshot capture
- `dnsx` — DNS resolution with retry logic

### Step-by-Step Setup

**1. Clone Repository**

```bash
git clone https://github.com/yourusername/OzyRecon.git
cd OzyRecon
```

**2. Create Virtual Environment**

Always use a virtual environment to avoid system package conflicts:

```bash
python -m venv venv
source venv/bin/activate  # On Linux/macOS
# venv\Scripts\activate   # On Windows
```

**3. Install Python Dependencies**

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**4. Install Package in Editable Mode**

This allows you to modify source code without reinstalling:

```bash
pip install -e .
```

**5. Verify Installation**

```bash
python ozy.py --version
# Expected output: OzyRecon v9.0.1

python ozy.py doctor
# Expected output: READY - All checks passed
```

**6. Initialize Configuration**

```bash
python ozy.py init
```

This creates:
- `config/scope.yaml` — Target authorization configuration
- `config/scheduler.yaml` — Scheduled scan configuration
- `data/ozyrecon.db` — SQLite database for asset storage

**7. Run Pre-Flight Check**

```bash
./scripts/pre-flight.sh
```

This validates all dependencies, network connectivity, and disk space.

### Troubleshooting Installation

**Import Error: No module named 'sqlalchemy'**

Cause: Dependencies not installed or wrong Python interpreter

Fix:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

**Binary Not Found: nmap**

Cause: System-wide nmap not installed

Fix:
```bash
# Ubuntu/Debian
sudo apt install nmap

# Arch Linux
sudo pacman -S nmap

# macOS
brew install nmap
```

**Permission Denied: ./scripts/pre-flight.sh**

Cause: Script not executable

Fix:
```bash
chmod +x scripts/pre-flight.sh
```

---

## Quick Start

### Basic Reconnaissance Workflow

**Step 1: Add Target to Scope**

```bash
python ozy.py scope add example.com
```

This adds `example.com` and `*.example.com` to authorized scope. Repeat for multiple root domains.

**Step 2: Run Full Reconnaissance**

```bash
python ozy.py flow example.com --profile safe-active
```

Profile options:
- `passive`: No active scanning, only passive discovery (safest, fastest)
- `safe-active`: Standard reconnaissance with non-invasive techniques (recommended for bug bounties)
- `aggressive`: Deep scanning with all techniques (requires explicit authorization)

**Step 3: View Discovered Assets**

```bash
python ozy.py inventory
```

Lists all discovered subdomains with HTTP status, technologies, and open ports.

**Step 4: Analyze Specific Host**

```bash
python ozy.py analyze api.example.com
```

Provides detailed analysis of a single host including attack surface, findings, and recommendations.

**Step 5: Export Results**

```bash
python ozy.py export example.com
```

Generates `exports/example.com_YYYY-MM-DD.json` with all findings.

### Advanced Workflows

See [docs/WORKFLOWS.md](docs/WORKFLOWS.md) for detailed scenarios including:
- Re-scanning after target changes with diff detection
- Scheduled monitoring for continuous reconnaissance
- Deep analysis of single hosts with fuzzing and secret scanning
- Compliance evidence generation with audit bundles

---

## Development & Testing

### Running Tests

OzyRecon uses `pytest` for unit and integration testing:

```bash
# Activate virtual environment
source venv/bin/activate

# Run full test suite (217 tests, ~2.5 minutes)
pytest

# Run with verbose output
pytest -v

# Run specific test module
pytest tests/core/test_tool_manager_sync.py

# Run tests matching pattern
pytest -k "test_scope"

# Stop on first failure
pytest -x

# Show test coverage
pytest --cov=src --cov-report=html
```

**Test Organization**:
- `tests/core/` — Core infrastructure (tool manager, context, plugins)
- `tests/adapters/` — External system integrations (database, API clients)
- `tests/intelligence/` — AI analysis, scoring, evidence linking
- `tests/validation/` — Scope validation, policy enforcement
- `tests/integration/` — End-to-end workflow tests

**Test Isolation**:

Tests run in isolated environments with mocked external dependencies. The root `conftest.py` configures:
- Temporary SQLite databases for each test
- Mocked HTTP responses for external APIs
- Filesystem isolation via temporary directories
- Path exclusion for Go module dependencies

Always run tests inside the virtual environment to avoid system package conflicts.

### Code Quality Tools

**Linting**:
```bash
ruff check src/ tests/
```

**Type Checking**:
```bash
mypy src/ --strict
```

**Security Scanning**:
```bash
bandit -r src/
```

### Performance Testing

Load testing and stress tests are isolated in `scripts/performance/`:

```bash
# Concurrency stress test (spawns 100 parallel scans)
./scripts/performance/v76_concurrency_stress.py

# Load test (simulates 1000 assets)
./scripts/performance/v77_load_test.sh
```

### Experimental Features

Proof-of-concept implementations live in `scripts/experiments/`:

```bash
# Evidence chain verification
python scripts/experiments/v75_evidence_proof.py

# AI analysis validation
python scripts/experiments/v81_ai_proof.py
```

These are not production code but demonstrate future capabilities.

---

## Architecture Deep Dive

### Hexagonal Architecture Implementation

OzyRecon strictly enforces dependency rules:

**Dependency Flow**:
```
Domain (core business logic)
  ↑ depends on nothing
Application (use cases)
  ↑ depends on domain only (via interfaces/ports)
Adapters (external integrations)
  ↑ depends on application ports + domain
Infrastructure (cross-cutting concerns)
  ↑ depends on all layers
```

**Benefits**:
- **Testability**: Domain logic tests require no mocks (pure functions)
- **Portability**: Swap database from SQLite to PostgreSQL by replacing adapter
- **Maintainability**: Business rule changes don't touch infrastructure code
- **Parallel Development**: Teams can work on adapters independently

**Example: Asset Repository**

Port definition (`src/application/ports/asset_repository.py`):
```python
from abc import ABC, abstractmethod
from src.domain.models import Asset

class IAssetRepository(ABC):
    @abstractmethod
    def save(self, asset: Asset) -> None:
        """Persist asset to storage."""
        pass
    
    @abstractmethod
    def find_by_domain(self, domain: str) -> Asset | None:
        """Retrieve asset by domain name."""
        pass
```

SQLite adapter (`src/adapters/storage/sqlite_repository.py`):
```python
from src.application.ports.asset_repository import IAssetRepository
from src.domain.models import Asset
from sqlalchemy.orm import Session

class SQLiteAssetRepository(IAssetRepository):
    def __init__(self, session: Session):
        self._session = session
    
    def save(self, asset: Asset) -> None:
        # Map domain model to SQLAlchemy model
        db_asset = AssetTable(
            domain=asset.domain,
            ip=asset.ip,
            http_status=asset.http_status
        )
        self._session.add(db_asset)
        self._session.commit()
    
    def find_by_domain(self, domain: str) -> Asset | None:
        db_asset = self._session.query(AssetTable).filter_by(domain=domain).first()
        if not db_asset:
            return None
        # Map SQLAlchemy model back to domain model
        return Asset(
            domain=db_asset.domain,
            ip=db_asset.ip,
            http_status=db_asset.http_status
        )
```

Application use case (`src/application/use_cases/orchestrator_v10.py`):
```python
from src.application.ports.asset_repository import IAssetRepository
from src.domain.models import Asset

class OrchestratorV10:
    def __init__(self, repository: IAssetRepository):
        # Depends on interface, not concrete implementation
        self._repository = repository
    
    def save_discovered_asset(self, domain: str, ip: str) -> None:
        asset = Asset(domain=domain, ip=ip, http_status=200)
        self._repository.save(asset)
```

Testing with mock adapter:
```python
class MockAssetRepository(IAssetRepository):
    def __init__(self):
        self.assets = {}
    
    def save(self, asset: Asset) -> None:
        self.assets[asset.domain] = asset
    
    def find_by_domain(self, domain: str) -> Asset | None:
        return self.assets.get(domain)

def test_orchestrator_saves_asset():
    repo = MockAssetRepository()
    orchestrator = OrchestratorV10(repository=repo)
    orchestrator.save_discovered_asset("api.example.com", "203.0.113.10")
    assert "api.example.com" in repo.assets
```

---

## Documentation

### Core Documentation

- **[STATUS.md](docs/STATUS.md)**: Current project status, version, and test metrics
- **[PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md)**: Deployment guide, verification checklist, troubleshooting
- **[WORKFLOWS.md](docs/WORKFLOWS.md)**: Six real-world reconnaissance scenarios with commands and expected outputs
- **[INSTALL.md](docs/INSTALL.md)**: Detailed installation instructions for multiple platforms
- **[USAGE.md](docs/USAGE.md)**: Complete CLI reference with examples

### Architecture Documentation

- **[architecture.md](docs/architecture.md)**: Hexagonal architecture deep dive, component diagrams
- **[RUNTIME_CONTRACT.md](docs/RUNTIME_CONTRACT.md)**: Frozen API surface, backward compatibility guarantees
- **[BRIDGE_CONTRACT.md](docs/BRIDGE_CONTRACT.md)**: External adapter integration guide

### Policy Documentation

- **[COMPLIANCE.md](docs/COMPLIANCE.md)**: Data integrity standards, evidence signing procedures
- **[EXCLUSIONS.md](docs/EXCLUSIONS.md)**: Explicit non-goals (payload generation, exploit execution)
- **[CONTRIBUTING.md](CONTRIBUTING.md)**: Development workflow, code standards, PR process
- **[DISCLAIMER.md](DISCLAIMER.md)**: Legal boundaries and responsible use

### Operational Documentation

- **[WORKFLOW.md](docs/WORKFLOW.md)**: Internal process documentation
- **[modes.md](docs/modes.md)**: Scanning profiles and configuration options
- **[ROADMAP.md](docs/ROADMAP.md)**: Future features and planned enhancements

---

## Contributing

OzyRecon welcomes contributions from security researchers and developers. Before submitting changes:

1. **Read CONTRIBUTING.md**: Understand the development workflow and code standards
2. **Run Pre-Commit Checks**: Execute `./scripts/opsec_check.py` to avoid leaking sensitive data
3. **Write Tests**: All new features require unit tests with ≥80% coverage
4. **Update Documentation**: Keep docs synchronized with code changes
5. **Follow Conventional Commits**: Use `feat:`, `fix:`, `docs:`, `refactor:` prefixes

### Development Setup

```bash
# Fork repository and clone
git clone https://github.com/yourusername/OzyRecon.git
cd OzyRecon

# Create feature branch
git checkout -b feature/your-feature-name

# Install development dependencies
pip install -r requirements-dev.txt

# Make changes and test
pytest
ruff check src/
mypy src/

# Commit with conventional format
git commit -m "feat: add support for custom wordlists in fuzzer"

# Push and create pull request
git push origin feature/your-feature-name
```

---

## Security Considerations

### OPSEC Protection

OzyRecon includes a pre-commit hook (`scripts/opsec_check.py`) that prevents accidental commits of sensitive data:

**Blocked Patterns**:
- Real target domains (except example.com, test.com)
- Public IP addresses (excludes RFC 1918 private ranges, RFC 5737 documentation ranges)
- API keys and secrets (detects common patterns like `AKIA...`, `ghp_...`)

**Allowed Test Data**:
- RFC 1918 private ranges: 10.x.x.x, 192.168.x.x, 172.16-31.x.x
- RFC 5737 documentation ranges: 192.0.2.x, 198.51.100.x, 203.0.113.x
- Link-local: 169.254.x.x
- Loopback: 127.x.x.x
- Reserved domains: example.com, test.com, example.org

To bypass the hook temporarily (use with caution):
```bash
git commit --no-verify -m "message"
```

### Scope Validation

All commands validate target domains against `config/scope.yaml` before execution:

```yaml
target: example.com
allowed_domains:
  - example.com
  - "*.example.com"
  - test.example.org
forbidden_patterns:
  - internal
  - staging
  - dev
profiles_allowed:
  - passive
  - safe-active
authorization:
  type: bug-bounty
  reference: "HackerOne Program #12345"
  date: "2026-05-30"
  authorized_by: "Program Owner"
```

Attempting to scan out-of-scope targets results in immediate rejection with error message.

### Rate Limiting

OzyRecon implements adaptive rate limiting to avoid WAF detection:

- Default: 200 requests per minute with jitter (5-10% randomization)
- Configurable per profile in `config/profiles.yaml`
- Automatic backoff on HTTP 429 responses
- Randomized delays between requests (prevents pattern detection)

### Data Handling

- **Scan Data**: Stored locally in `data/ozyrecon.db` (SQLite) and `runs/` directory
- **Credentials**: Never logged or stored in plain text
- **Network Traffic**: No data transmitted to external servers except target infrastructure
- **Audit Logs**: All tool executions logged with timestamps in `flow_summary.json`

---

## License

Copyright 2024-2026 OzyRecon Development Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

## Disclaimer

**OzyRecon is designed for authorized security testing only.**

Users are solely responsible for:
- Obtaining explicit written authorization before scanning any target
- Complying with local laws and regulations regarding computer security testing
- Respecting bug bounty program scope and rules of engagement
- Operating within ethical hacking guidelines

The authors and contributors of OzyRecon assume no liability for misuse of this software. Unauthorized scanning of computer systems is illegal in most jurisdictions and may result in criminal prosecution.

**Always obtain written permission before testing any system you do not own.**

---

## Support

**Documentation**: [docs/](docs/)  
**Issues**: [GitHub Issues](https://github.com/yourusername/OzyRecon/issues)  
**Discussions**: [GitHub Discussions](https://github.com/yourusername/OzyRecon/discussions)

For private security disclosures, email: security@ozyrecon.io
