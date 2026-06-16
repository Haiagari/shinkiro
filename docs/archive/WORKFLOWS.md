# OzyRecon Workflows — Practical Bug Bounty Scenarios

**Version**: 9.0.1  
**Audience**: Bug bounty hunters and security researchers

This guide covers real-world reconnaissance workflows with exact commands, expected outputs, and timing estimates.

---

## Prerequisites

Before starting any workflow:

```bash
# Run pre-flight check
./scripts/pre-flight.sh

# Expected output:
# ✅ All systems go! Ready for reconnaissance.
```

All commands assume you're in the OzyRecon project root with venv activated.

---

## Scenario 1: New Target — Initial Discovery

**Use Case**: You just joined a bug bounty program with a primary domain. Zero prior intelligence.

**Time Estimate**: 15-30 minutes (depending on target size)

**Profile**: `safe-active` (non-invasive active scanning)

### Step 1: Add Target to Scope

```bash
python ozy.py scope add target.com
```

**Expected Output**:
```
✅ Domain 'target.com' added to scope
Current allowed domains: target.com, *.target.com
```

### Step 2: Run Full Reconnaissance Flow

```bash
python ozy.py flow target.com --profile safe-active
```

**What Happens**:
1. **Preflight** (5-10s): Validates binaries, scope, network
2. **Passive Discovery** (1-3 min): Subfinder, certificate transparency
3. **Active Resolution** (2-5 min): DNS resolution, HTTP probing
4. **Service Analysis** (5-10 min): Nmap port scanning on live hosts
5. **Vulnerability Detection** (5-15 min): Nuclei templates
6. **AI Analysis** (30s): Summarizes findings and suggests attack vectors

**Expected Artifacts**:
- `runs/target.com/analysis.json` — Machine-readable results
- `runs/target.com/analysis.md` — Human-readable summary
- `runs/target.com/flow_summary.json` — Timing and telemetry
- `data/ozyrecon.db` — SQLite database with all assets

### Step 3: Review Discovered Assets

```bash
python ozy.py inventory
```

**Expected Output**:
```
Discovered Assets for target.com:
  - api.target.com (HTTP 200, nginx)
  - admin.target.com (HTTP 403, Apache/2.4)
  - dev.target.com (HTTP 500, Node.js)
  - staging.target.com (HTTP 401, Basic Auth)
  
Total: 4 subdomains, 3 live services
```

### Step 4: Deep Dive on Interesting Host

```bash
python ozy.py analyze api.target.com
```

**Expected Output**:
```
Analysis for api.target.com:
  Technologies: nginx, Express.js, MongoDB
  Open Ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)
  Findings:
    - [MEDIUM] Missing security headers (CSP, HSTS)
    - [LOW] Server version disclosure (nginx/1.18.0)
  
Attack Surface:
  - API endpoints discovered: /v1/users, /v1/auth, /health
  - Potential vectors: auth bypass, IDOR, rate limiting
```

### Step 5: Export for Reporting

```bash
python ozy.py export target.com
```

**Expected Output**:
```
✅ Exported to exports/target.com_2026-05-30.json
   - 4 assets
   - 2 medium findings
   - 1 low finding
```

---

## Scenario 2: Re-Scan After Changes

**Use Case**: Target deployed updates. You want to detect NEW assets, changed services, or fixed vulnerabilities.

**Time Estimate**: 10-20 minutes

**Profile**: `safe-active`

### Step 1: Run Incremental Flow

```bash
python ozy.py flow target.com --profile safe-active
```

This automatically detects existing scan data and runs a fresh scan.

### Step 2: Compare with Previous Scan

```bash
python ozy.py diff target.com
```

**Expected Output**:
```
Diff Report for target.com:

New Assets:
  + cdn.target.com (HTTP 200, Cloudflare)
  + beta.target.com (HTTP 200, nginx)

Changed Assets:
  ~ admin.target.com: HTTP 403 → HTTP 200 (authentication removed!)

Removed Assets:
  - staging.target.com (no longer resolves)

New Findings:
  + [HIGH] Authentication bypass on admin.target.com
  
Fixed Findings:
  - [MEDIUM] Missing HSTS header on api.target.com (now present)

Summary: 2 new assets, 1 critical change detected
```

### Step 3: Investigate Critical Change

```bash
python ozy.py analyze admin.target.com
```

Review the newly accessible admin panel for potential issues.

---

## Scenario 3: Scope Expansion (Wildcards)

**Use Case**: Bug bounty program allows `*.target.com` but you want to track multiple root domains.

**Time Estimate**: Variable (proportional to scope size)

**Profile**: `passive` (safest for broad discovery)

### Step 1: Add Multiple Domains

```bash
python ozy.py scope add target.com
python ozy.py scope add target.io
python ozy.py scope add targetapp.com
```

### Step 2: Run Passive Discovery Only

```bash
python ozy.py flow target.com --profile passive
python ozy.py flow target.io --profile passive
python ozy.py flow targetapp.com --profile passive
```

**What Happens**:
- Only passive techniques (no active scanning)
- Certificate transparency, DNS records, public archives
- Minimal footprint on target infrastructure

### Step 3: Review All Discovered Assets

```bash
python ozy.py inventory
```

**Expected Output**:
```
Discovered Assets across all targets:
  target.com: 12 subdomains
  target.io: 5 subdomains
  targetapp.com: 8 subdomains
  
Total: 25 assets discovered via passive recon
```

### Step 4: Export Combined Results

```bash
python ozy.py export --all
```

Exports a consolidated JSON with all targets.

---

## Scenario 4: Deep Analysis of Single Host

**Use Case**: You found an interesting subdomain (`internal.target.com`) and want to enumerate deeply before testing.

**Time Estimate**: 5-10 minutes

**Profile**: `safe-active` or `aggressive` (if authorized)

### Step 1: Focused Service Scan

```bash
python ozy.py analyze internal.target.com
```

**What Happens**:
- Full Nmap port scan (top 1000 ports by default)
- Service version detection
- Nuclei vulnerability checks
- AI-powered attack surface analysis

### Step 2: Directory Fuzzing (if needed)

```bash
# Note: This requires manual invocation, not in automated flow
python ozy.py paths internal.target.com
```

**Expected Output**:
```
Discovered Paths on internal.target.com:
  - /admin (HTTP 200)
  - /api/v1 (HTTP 404)
  - /backup (HTTP 403)
  - /config (HTTP 500)
  
Interesting Findings:
  - /backup directory accessible but forbidden (potential info disclosure)
  - /config returns 500 (possible error-based info leak)
```

### Step 3: Secret Scanning in JS Files

```bash
python ozy.py secrets internal.target.com
```

**Expected Output**:
```
Secrets Found in internal.target.com:
  - API_KEY: AIzaSyC... (Google API key in /static/app.js)
  - AWS_ACCESS_KEY: AKIA... (in /vendor/config.js)
  
⚠️ These credentials should be reported immediately!
```

### Step 4: Screenshot for Evidence

```bash
python ozy.py screenshot internal.target.com
```

**Expected Output**:
```
✅ Screenshot saved: screenshots/internal.target.com_2026-05-30.png
```

Use this for bug bounty reports as proof of discovery.

---

## Scenario 5: Scheduled Monitoring

**Use Case**: You want OzyRecon to automatically re-scan targets daily and alert you to changes.

**Time Estimate**: 2 minutes setup, then automated

**Profile**: `safe-active` (automated scans should be non-invasive)

### Step 1: Add Scheduled Scan

```bash
python ozy.py schedule add target.com --interval daily --profile safe-active
```

**Expected Output**:
```
✅ Scheduled scan for target.com:
   Interval: daily (every 24 hours)
   Profile: safe-active
   Next run: 2026-05-31 02:00:00 UTC
```

### Step 2: View Scheduled Scans

```bash
python ozy.py schedule list
```

**Expected Output**:
```
Scheduled Scans:
  1. target.com (daily, safe-active) — Next: 2026-05-31 02:00:00
  2. target.io (weekly, passive) — Next: 2026-06-06 02:00:00
```

### Step 3: Check for Changes (Manual)

After scheduled scan runs:

```bash
python ozy.py diff target.com
```

This shows what changed since the previous scan.

---

## Scenario 6: Compliance and Evidence Generation

**Use Case**: You need audit-ready evidence for a pentest report or compliance documentation.

**Time Estimate**: 5 minutes

**Profile**: Any (depends on engagement scope)

### Step 1: Run Flow with Audit Bundle

```bash
python ozy.py flow target.com --profile safe-active
```

Automatically generates audit artifacts.

### Step 2: Export Audit Bundle

```bash
# Audit bundle is auto-created in runs/target.com/
ls runs/target.com/audit_*.tar.gz
```

**Expected Output**:
```
runs/target.com/audit_a1b2c3d4.tar.gz
```

### Step 3: Verify Bundle Contents

```bash
tar -tzf runs/target.com/audit_a1b2c3d4.tar.gz
```

**Expected Contents**:
```
evidence/
evidence/subdomains.json (SHA256 signed)
evidence/httpx_results.json (SHA256 signed)
evidence/nmap_scan.xml (SHA256 signed)
metadata.json (timestamps, tool versions, command line)
flow_summary.json (execution trace)
```

### Step 4: Validate Signatures

```bash
python ozy.py verify-audit runs/target.com/audit_a1b2c3d4.tar.gz
```

**Expected Output**:
```
✅ All evidence signatures valid
✅ Metadata integrity verified
✅ Audit bundle ready for submission
```

---

## Tips & Best Practices

### Choosing the Right Profile

| Profile | Use Case | Footprint | Speed |
|---------|----------|-----------|-------|
| `passive` | Initial recon, broad scope, stealth | Minimal | Fast |
| `safe-active` | Standard bug bounty workflow | Low | Medium |
| `aggressive` | Deep pentests with explicit authorization | High | Slow |

### When to Re-Scan

- After target deploys updates (weekly for active programs)
- When new scope is added to bug bounty program
- Before submitting a report (confirm finding still exists)
- After a finding is marked "fixed" (verify remediation)

### Performance Tuning

**Large Targets** (100+ subdomains):
```bash
# Use passive first to map assets
python ozy.py flow target.com --profile passive

# Then active scan high-priority assets only
python ozy.py analyze high-value-subdomain.target.com
```

**Rate Limiting**:
- OzyRecon respects rate limits (default: 200 req/min)
- Configured in `config/profiles.yaml`
- Adjust per target to avoid WAF blocks

### Avoiding Detection

1. **Use passive profile** for initial discovery
2. **Rotate user agents** (automatic in stealth mode)
3. **Add delays** via `--rate-limit` flag (future feature)
4. **Check robots.txt** before aggressive scanning

---

## Troubleshooting

### "Scope validation failed"

**Cause**: Target not in `config/scope.yaml`

**Fix**:
```bash
python ozy.py scope add target.com
```

### "No assets discovered"

**Possible Causes**:
1. Target has no subdomains (rare)
2. Network connectivity issue
3. Target uses strict WAF/rate limiting

**Debugging**:
```bash
# Test network
python ozy.py doctor

# Try passive only
python ozy.py flow target.com --profile passive

# Check logs
cat runs/target.com/flow_summary.json
```

### "Scan taking too long"

**Possible Causes**:
1. Target has 100+ subdomains
2. Nmap scanning slow networks

**Mitigation**:
```bash
# Use fast profile (future feature)
python ozy.py flow target.com --profile fast

# Or skip service detection
python ozy.py flow target.com --skip-nmap
```

---

## Appendix: Command Reference

| Command | Purpose | Time |
|---------|---------|------|
| `scope add DOMAIN` | Add target to authorized scope | 1s |
| `scope list` | View current scope | 1s |
| `flow TARGET --profile PROFILE` | Full reconnaissance workflow | 10-30min |
| `inventory` | List all discovered assets | 1s |
| `analyze HOST` | Deep analysis of single host | 5-10min |
| `diff TARGET` | Compare current vs previous scan | 5s |
| `export TARGET` | Generate JSON export | 5s |
| `secrets HOST` | Scan JS files for hardcoded secrets | 2-5min |
| `screenshot HOST` | Capture visual evidence | 10s |
| `schedule add TARGET` | Schedule recurring scan | 1s |
| `doctor` | Validate environment and dependencies | 10s |

---

**Last Updated**: 2026-05-30  
**Version**: 9.0.1  
**Maintainer**: OzyRecon Development Team
