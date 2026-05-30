# OzyRecon Usage Guide

**Version**: 9.0.1  
**Last Updated**: 2026-05-30

This document provides comprehensive CLI reference for all OzyRecon commands, options, and operational patterns.

---

## Table of Contents

1. [Command Overview](#command-overview)
2. [Core Commands](#core-commands)
3. [Reconnaissance Commands](#reconnaissance-commands)
4. [Analysis Commands](#analysis-commands)
5. [Management Commands](#management-commands)
6. [Advanced Usage](#advanced-usage)
7. [Output Formats](#output-formats)
8. [Error Handling](#error-handling)

---

## Command Overview

OzyRecon provides 19 CLI commands organized by function:

**Initialization & Validation**:
- `init` — Initialize OzyRecon environment
- `doctor` — Validate dependencies and configuration
- `verify` — Run anti-smoke verification suite

**Scope Management**:
- `scope add` — Add domains to authorized scope
- `scope remove` — Remove domains from scope
- `scope list` — Display current scope configuration
- `scope import` — Bulk import from file

**Reconnaissance Workflows**:
- `flow` — Full reconnaissance pipeline
- `hunt` — Targeted asset discovery
- `continuous` — Long-running monitoring mode
- `campaign` — Multi-target coordinated scan
- `research` — Intelligence gathering mode
- `forensic` — Evidence collection mode

**Analysis**:
- `analyze` — Deep analysis of specific host
- `inventory` — List all discovered assets
- `diff` — Compare scans for changes
- `paths` — Directory/endpoint enumeration
- `secrets` — JavaScript secret scanning
- `exploits` — CVE suggestion engine

**Export & Reporting**:
- `export` — Generate structured exports
- `screenshot` — Capture visual evidence

**Infrastructure**:
- `schedule` — Manage recurring scans
- `serve` — Start API server
- `keys` — Manage API credentials

**Compliance**:
- `compliance-check` — Validate scan results against standards
- `audit` — Generate audit-ready evidence bundles

---

## Core Commands

### init

**Purpose**: Initialize OzyRecon environment with default configuration and database schema.

**Syntax**:
```bash
python ozy.py init [OPTIONS]
```

**Options**:
- `--force` — Overwrite existing configuration files
- `--db-path PATH` — Custom database location (default: `data/ozyrecon.db`)

**Behavior**:
1. Creates `data/` directory if missing
2. Initializes SQLite database with schema
3. Creates `config/scope.yaml` template
4. Creates `config/scheduler.yaml` template
5. Validates Go binary presence in `tools/go/bin/`

**Example**:
```bash
python ozy.py init

# Output:
# Initializing OzyRecon v9.0.1...
# Created database: data/ozyrecon.db
# Created config: config/scope.yaml
# Created config: config/scheduler.yaml
# Detected binaries: subfinder, httpx, nuclei, nmap, katana, gowitness
# Initialization complete.
```

**When to Use**: First-time setup or after clean installation.

---

### doctor

**Purpose**: Comprehensive environment validation to diagnose configuration issues.

**Syntax**:
```bash
python ozy.py doctor [OPTIONS]
```

**Options**:
- `--verbose` — Show detailed diagnostic information
- `--check COMPONENT` — Validate specific component only

**Validation Checks**:
1. **Python Environment**:
   - Python version (requires >=3.11)
   - Virtual environment activation status
   - Installed packages and versions

2. **Directory Structure**:
   - `runs/` — Scan output directory
   - `resources/rules/` — Nuclei templates
   - `resources/keys/` — API credentials
   - `config/` — Configuration files
   - `tools/go/bin/` — Go binaries

3. **Go Tools**:
   - `subfinder` — Passive subdomain enumeration
   - `dnsx` — DNS resolution
   - `httpx` — HTTP probing
   - `nuclei` — Vulnerability scanning
   - `amass` — OSINT aggregation
   - `katana` — Web crawling
   - `gowitness` — Screenshot capture
   - `nmap` — Port scanning (system-wide)

4. **Python Dependencies**:
   - `sqlalchemy` — Database ORM
   - `requests` — HTTP client
   - `rich` — Terminal formatting
   - `click` — CLI framework
   - `curl_cffi` — TLS randomization
   - `weasyprint` — PDF generation

5. **API Keys** (optional):
   - Checks for presence but does not validate

6. **Database**:
   - SQLite connection
   - Schema integrity
   - Migration status

**Example**:
```bash
python ozy.py doctor

# Output:
# OzyRecon Doctor - Environment Validation
# 
# Python:
#   Python 3.14.5 — OK
# 
# Folders:
#   runs/ — OK
#   resources/rules/ — OK
#   config/ — OK
#   tools/go/bin/ — OK
# 
# Go Tools:
#   subfinder — OK (/home/user/OzyRecon/tools/go/bin/subfinder)
#   httpx — OK (/home/user/.local/bin/httpx)
#   nuclei — OK (/home/user/OzyRecon/tools/go/bin/nuclei)
#   nmap — OK (/usr/bin/nmap)
# 
# Python Dependencies:
#   sqlalchemy — OK (2.0.49)
#   requests — OK (2.33.1)
#   rich — OK (15.0.0)
# 
# Database:
#   SQLite connection — OK
# 
# Status: READY - All checks passed
```

**Troubleshooting**:

**Missing Binary Error**:
```
Go Tools:
  subfinder — MISSING
```
Solution: Install missing tool or check PATH configuration.

**Database Error**:
```
Database:
  SQLite connection — FAILED (unable to open database file)
```
Solution: Run `python ozy.py init` to recreate database.

**When to Use**: Before starting reconnaissance, after configuration changes, when debugging issues.

---

### verify

**Purpose**: Execute internal logic tests to validate core functionality without network access.

**Syntax**:
```bash
python ozy.py verify [OPTIONS]
```

**Options**:
- `--smoke` — Quick smoke test (30 seconds)
- `--full` — Full test suite (2 minutes)

**Test Categories**:
1. **Scope Guard**: Validates domain filtering logic
2. **Scan Profiles**: Confirms profile configuration integrity
3. **Evidence Linking**: Tests cryptographic signing
4. **Target Normalization**: Validates input sanitization

**Example**:
```bash
python ozy.py verify --smoke

# Output:
# Running smoke tests...
# 
# Scope Guard:
#   root_domain_is_in_scope — PASS
#   subdomain_is_in_scope — PASS
#   external_domain_out_of_scope — PASS
# 
# Scan Profiles:
#   passive_profile_exists — PASS
#   safe_active_profile_exists — PASS
# 
# All tests passed (8/8)
```

**When to Use**: After code changes, before production deployment, when debugging unexpected behavior.

---

## Reconnaissance Commands

### flow

**Purpose**: Execute the full five-phase reconnaissance pipeline from passive discovery through vulnerability detection.

**Syntax**:
```bash
python ozy.py flow TARGET [OPTIONS]
```

**Required Arguments**:
- `TARGET` — Domain name (e.g., `example.com`)

**Options**:
- `--profile PROFILE` — Scanning profile (`passive`, `safe-active`, `aggressive`)
- `--skip-nmap` — Disable port scanning phase
- `--skip-nuclei` — Disable vulnerability detection phase
- `--timeout SECONDS` — Global timeout for entire workflow (default: 3600)
- `--rate-limit N` — Maximum requests per minute (default: 200)
- `--output-dir DIR` — Custom output directory (default: `runs/TARGET/`)
- `--session-id ID` — Custom session identifier
- `--json` — Output machine-readable JSON only

**Pipeline Phases**:

**Phase 1: Preflight Verification** (5-10 seconds)
- Validates binaries, environment, network connectivity
- Checks target authorization in `config/scope.yaml`
- Initializes session directory and logging

**Phase 2: Passive Discovery** (1-5 minutes)
- Certificate Transparency log queries
- DNS record enumeration (A, AAAA, CNAME, MX, TXT)
- Public archive searches (Wayback Machine, CommonCrawl)
- `subfinder` execution with all passive sources
- ASN-based IP range identification

**Phase 3: Active Resolution** (2-10 minutes)
- DNS resolution via `dnsx` with retry logic
- HTTP/HTTPS probing via `httpx`
- Technology detection (web servers, frameworks, CDNs)
- Screenshot capture via `gowitness`
- Service banner grabbing on common ports

**Phase 4: Service Analysis** (5-20 minutes)
- Port scanning via `nmap` (top 1000 ports by default)
- Service version detection (`-sV`)
- OS fingerprinting (optional, requires root)
- Safe NSE scripts for additional intelligence

**Phase 5: Vulnerability Detection** (5-15 minutes)
- `nuclei` template execution
- CVE matching based on detected service versions
- Misconfiguration detection
- AI-powered risk analysis (optional)

**Output Artifacts**:
- `runs/TARGET/analysis.json` — Machine-readable findings
- `runs/TARGET/analysis.md` — Human-readable summary
- `runs/TARGET/flow_summary.json` — Execution telemetry
- `runs/TARGET/evidence/` — Raw tool outputs (signed)
- `data/ozyrecon.db` — Persistent asset storage

**Example — Safe Active Scan**:
```bash
python ozy.py flow example.com --profile safe-active

# Output:
# Starting reconnaissance flow for example.com...
# Profile: safe-active
# 
# [1/5] Preflight Verification
#   Validating binaries... OK
#   Checking authorization... OK (example.com in scope)
#   Network connectivity... OK
# 
# [2/5] Passive Discovery
#   Subfinder (passive sources)... 12 subdomains discovered
#   Certificate Transparency... 8 additional subdomains
#   DNS enumeration... 15 total unique assets
# 
# [3/5] Active Resolution
#   DNS resolution (dnsx)... 12/15 resolved
#   HTTP probing (httpx)... 8/12 live
#   Technology detection... nginx (6), Apache (2)
# 
# [4/5] Service Analysis
#   Port scanning (nmap)... 8 hosts, 24 open ports
#   Service detection... 18 services identified
# 
# [5/5] Vulnerability Detection
#   Nuclei templates... 3 findings (1 medium, 2 low)
# 
# Reconnaissance complete (847 seconds)
# Results: runs/example.com/analysis.json
```

**Example — Passive Only**:
```bash
python ozy.py flow example.com --profile passive

# Output:
# Starting reconnaissance flow for example.com...
# Profile: passive (no active scanning)
# 
# [1/5] Preflight Verification
#   Validating binaries... OK
#   Checking authorization... OK
# 
# [2/5] Passive Discovery
#   Subfinder... 12 subdomains discovered
#   Certificate Transparency... 8 additional subdomains
#   Public archives... 3 additional assets
#   Total unique assets: 23
# 
# [3/5] Active Resolution — SKIPPED (passive mode)
# [4/5] Service Analysis — SKIPPED (passive mode)
# [5/5] Vulnerability Detection — SKIPPED (passive mode)
# 
# Reconnaissance complete (142 seconds)
# Results: runs/example.com/analysis.json
```

**Profiles Explained**:

| Profile | Active Scanning | Port Scanning | Vuln Detection | Use Case |
|---------|----------------|---------------|----------------|----------|
| `passive` | No | No | No | Initial recon, maximum stealth |
| `safe-active` | Yes | Top 1000 | Yes | Bug bounty standard |
| `aggressive` | Yes | Full 65535 | Yes | Authorized pentests only |

**When to Use**:
- New target: Initial discovery and mapping
- Regular monitoring: Detect infrastructure changes
- Pre-testing: Map attack surface before manual testing

**Error Handling**:

**Out of Scope Error**:
```
Error: Target 'internal.example.com' not authorized in config/scope.yaml
Add domain: python ozy.py scope add internal.example.com
```

**Network Timeout**:
```
Warning: Subfinder timed out after 300 seconds
Continuing with partial results...
```

---

### hunt

**Purpose**: Targeted asset discovery focused on specific host or subdomain pattern.

**Syntax**:
```bash
python ozy.py hunt TARGET [OPTIONS]
```

**Required Arguments**:
- `TARGET` — Domain pattern (e.g., `*.api.example.com`)

**Options**:
- `--depth N` — Recursion depth for subdomain enumeration (default: 3)
- `--wordlist PATH` — Custom wordlist for bruteforce discovery
- `--dns-servers IPS` — Comma-separated DNS resolvers

**Example**:
```bash
python ozy.py hunt *.api.example.com --depth 3

# Output:
# Hunting subdomains for *.api.example.com...
# 
# Discovered:
#   api.example.com
#   v1.api.example.com
#   v2.api.example.com
#   staging.api.example.com
#   internal.api.example.com (private IP — skipped)
# 
# Total: 4 in-scope assets
```

**When to Use**: Focused enumeration of API endpoints, regional subdomains, or specific service tiers.

---

## Analysis Commands

### analyze

**Purpose**: Deep analysis of a single host including full port scan, service enumeration, and vulnerability detection.

**Syntax**:
```bash
python ozy.py analyze HOST [OPTIONS]
```

**Required Arguments**:
- `HOST` — Fully qualified domain name or IP address

**Options**:
- `--ports RANGE` — Custom port range (e.g., `1-10000`, `80,443,8080`)
- `--scripts SCRIPTS` — Comma-separated Nmap NSE scripts
- `--timeout SECONDS` — Per-host timeout (default: 600)

**Analysis Components**:
1. **Full Port Scan**: All 65535 ports (or custom range)
2. **Service Detection**: Version and banner grabbing
3. **Technology Stack**: Framework and library identification
4. **Vulnerability Matching**: CVE correlation via service versions
5. **Attack Surface Mapping**: Entry points and potential vectors

**Example**:
```bash
python ozy.py analyze api.example.com

# Output:
# Analyzing api.example.com...
# 
# Host Information:
#   IP Address: 203.0.113.10
#   HTTP Status: 200 OK
#   Technologies: nginx/1.18.0, Express.js 4.17.1, MongoDB
# 
# Open Ports:
#   22/tcp — SSH (OpenSSH 8.2p1)
#   80/tcp — HTTP (nginx 1.18.0)
#   443/tcp — HTTPS (nginx 1.18.0 + TLS 1.3)
#   3000/tcp — HTTP (Node.js Express)
# 
# Security Findings:
#   [MEDIUM] Missing Content-Security-Policy header
#   [LOW] Server version disclosure in HTTP headers
#   [INFO] TLS 1.2 enabled (TLS 1.3 preferred)
# 
# Attack Surface:
#   API Endpoints:
#     GET /v1/users — User enumeration
#     POST /v1/auth — Authentication endpoint
#     GET /health — Service health check
#   
#   Potential Vectors:
#     - Authentication bypass (test /v1/auth with empty credentials)
#     - IDOR on /v1/users (test sequential user IDs)
#     - Rate limiting (test burst requests)
# 
# Recommendations:
#   1. Implement CSP header to prevent XSS
#   2. Remove server version from HTTP headers
#   3. Disable TLS 1.2, enforce TLS 1.3 only
#   4. Add rate limiting to authentication endpoints
```

**When to Use**: After initial discovery, when prioritizing high-value targets, before manual exploitation.

---

### inventory

**Purpose**: List all discovered assets across all targets with summary statistics.

**Syntax**:
```bash
python ozy.py inventory [OPTIONS]
```

**Options**:
- `--target TARGET` — Filter by specific target
- `--status STATUS` — Filter by HTTP status (e.g., `200`, `403`, `500`)
- `--technology TECH` — Filter by detected technology
- `--json` — Output as JSON
- `--csv PATH` — Export to CSV file

**Example**:
```bash
python ozy.py inventory

# Output:
# Asset Inventory
# 
# example.com:
#   Total Assets: 12
#   Live Services: 8
#   HTTP 200: 6
#   HTTP 403: 2
#   HTTP 404: 1
#   No Response: 3
# 
# Technologies:
#   nginx: 6 assets
#   Apache: 2 assets
#   Cloudflare: 4 assets
# 
# Findings:
#   Critical: 0
#   High: 1
#   Medium: 3
#   Low: 5
# 
# Recent Scans:
#   2026-05-30 12:00 — example.com (safe-active)
#   2026-05-29 18:30 — example.com (passive)
```

**Example — JSON Output**:
```bash
python ozy.py inventory --json > assets.json

# Output:
# {
#   "targets": [
#     {
#       "domain": "example.com",
#       "total_assets": 12,
#       "live_services": 8,
#       "assets": [
#         {
#           "domain": "api.example.com",
#           "ip": "203.0.113.10",
#           "http_status": 200,
#           "technologies": ["nginx", "Express.js"]
#         }
#       ]
#     }
#   ]
# }
```

**When to Use**: Reviewing reconnaissance results, generating reports, tracking asset inventory over time.

---

### diff

**Purpose**: Compare current scan results with historical data to detect infrastructure changes.

**Syntax**:
```bash
python ozy.py diff TARGET [OPTIONS]
```

**Required Arguments**:
- `TARGET` — Domain to compare

**Options**:
- `--baseline SESSION_ID` — Compare against specific historical scan
- `--days N` — Compare against scan from N days ago
- `--json` — Output machine-readable diff

**Detected Changes**:
1. **New Assets**: Newly discovered subdomains
2. **Removed Assets**: Previously discovered, now unresponsive
3. **Changed Assets**: HTTP status changes, technology updates, port changes
4. **New Findings**: Newly detected vulnerabilities
5. **Fixed Findings**: Previously detected issues now resolved

**Example**:
```bash
python ozy.py diff example.com

# Output:
# Diff Report: example.com
# Comparing: 2026-05-30 12:00 vs 2026-05-29 12:00
# 
# New Assets (2):
#   + cdn.example.com (HTTP 200, Cloudflare)
#   + beta.example.com (HTTP 200, nginx)
# 
# Removed Assets (1):
#   - staging.example.com (no longer resolves)
# 
# Changed Assets (1):
#   ~ admin.example.com
#     HTTP Status: 403 → 200 (authentication removed!)
#     Ports: [80, 443] → [22, 80, 443] (SSH exposed)
# 
# New Findings (2):
#   + [HIGH] Authentication bypass on admin.example.com
#   + [MEDIUM] SSH root login enabled on admin.example.com
# 
# Fixed Findings (1):
#   - [MEDIUM] Missing HSTS header on api.example.com (now present)
# 
# Summary:
#   Total Changes: 4
#   Risk Level: HIGH (authentication removed on admin panel)
#   Action Required: Immediate investigation of admin.example.com
```

**When to Use**: After target deployments, regular monitoring intervals, before retesting known vulnerabilities.

---

## Management Commands

### scope add

**Purpose**: Add domains to authorized reconnaissance scope.

**Syntax**:
```bash
python ozy.py scope add DOMAIN [DOMAIN...] [OPTIONS]
```

**Required Arguments**:
- `DOMAIN` — One or more domains or wildcard patterns

**Options**:
- `--wildcard` — Automatically include wildcard (e.g., `*.example.com`)

**Example**:
```bash
python ozy.py scope add example.com

# Output:
# Added to scope:
#   - example.com
#   - *.example.com (wildcard)
# 
# Current scope: 1 root domain, 1 wildcard pattern
```

**Multiple Domains**:
```bash
python ozy.py scope add example.com example.org example.net

# Output:
# Added to scope:
#   - example.com, *.example.com
#   - example.org, *.example.org
#   - example.net, *.example.net
# 
# Current scope: 3 root domains, 3 wildcard patterns
```

**When to Use**: Before starting reconnaissance, when scope changes in bug bounty program.

---

### scope import

**Purpose**: Bulk import domains from text file.

**Syntax**:
```bash
python ozy.py scope import FILE [OPTIONS]
```

**Required Arguments**:
- `FILE` — Path to text file (one domain per line)

**File Format**:
```
example.com
api.example.com
*.internal.example.com
example.org
```

**Example**:
```bash
python ozy.py scope import targets.txt

# Output:
# Importing from targets.txt...
# Added 4 domains:
#   - example.com
#   - api.example.com
#   - *.internal.example.com
#   - example.org
# 
# Current scope: 4 root domains, 2 wildcard patterns
```

**When to Use**: Large scope imports, scope updates from bug bounty platforms.

---

## Advanced Usage

### Custom Profiles

Create custom scanning profiles in `config/profiles.yaml`:

```yaml
custom-fast:
  tools:
    - subfinder
    - httpx
  timeout: 300
  rate_limit: 500
  description: "Fast passive discovery only"

custom-deep:
  tools:
    - subfinder
    - amass
    - httpx
    - nmap
    - nuclei
    - katana
  timeout: 7200
  nmap_ports: "1-65535"
  rate_limit: 100
  description: "Comprehensive deep scan"
```

Usage:
```bash
python ozy.py flow example.com --profile custom-fast
```

---

### API Server Mode

Start OzyRecon as HTTP API server:

```bash
python ozy.py serve --host 127.0.0.1 --port 8000

# Output:
# OzyRecon API Server
# Listening on http://127.0.0.1:8000
# 
# Endpoints:
#   GET  /health
#   POST /hunt
#   GET  /sessions/{id}/trace
#   GET  /sessions/{id}/analyze
```

**API Usage**:
```bash
# Health check
curl http://127.0.0.1:8000/health

# Start hunt
curl -X POST http://127.0.0.1:8000/hunt \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "profile": "safe-active"}'
```

---

## Output Formats

### JSON Output

Most commands support `--json` flag for machine-readable output:

```bash
python ozy.py inventory --json | jq '.targets[0].assets[0]'

# Output:
# {
#   "domain": "api.example.com",
#   "ip": "203.0.113.10",
#   "http_status": 200,
#   "technologies": ["nginx", "Express.js"],
#   "ports": [22, 80, 443],
#   "findings": [
#     {"severity": "medium", "title": "Missing CSP"}
#   ]
# }
```

---

## Error Handling

### Common Errors

**Scope Validation Failure**:
```
Error: Target 'unknown.com' not authorized
Solution: python ozy.py scope add unknown.com
```

**Missing Binary**:
```
Error: Required binary 'nmap' not found in PATH
Solution: sudo apt install nmap
```

**Database Locked**:
```
Error: Database locked (another scan in progress)
Solution: Wait for previous scan to complete or kill process
```

**Network Timeout**:
```
Warning: DNS resolution timed out for subdomain.example.com
Action: Continuing with partial results
```

---

## Best Practices

1. **Always use venv**: `source venv/bin/activate` before commands
2. **Run pre-flight before long scans**: `./scripts/pre-flight.sh`
3. **Start with passive**: `--profile passive` for initial discovery
4. **Review scope before aggressive scans**: `python ozy.py scope list`
5. **Export results regularly**: `python ozy.py export TARGET`
6. **Monitor diff reports**: `python ozy.py diff TARGET` after changes
7. **Use JSON for automation**: `--json` flag for scripting

---

**Last Updated**: 2026-05-30  
**Version**: 9.0.1  
**Maintainer**: OzyRecon Development Team
