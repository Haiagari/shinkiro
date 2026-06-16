# Production Readiness — OzyRecon v9.1.0

**Status**: ✅ Production-Ready (2026-06-16)

## Overview

OzyRecon v9.1.0 adds 6 new discovery modules, professional reporting with CVSS v3.1, attack surface diagram, and PDF export.

## What's New in 9.1.0

- **JS Endpoint Extraction**: descarga JS de hosts vivos, extrae rutas/api ocultas
- **Subdomain Permutations**: 9 reglas (prefijos, sufijos, cloud, servicios) + resolución DNS
- **Parameter Discovery**: 764 parámetros, clasifica reflective/functional/stateless
- **S3 Bucket Scanner**: 267 combinaciones, detecta buckets públicos
- **Google Dorking**: 30 dorks en 7 categorías con rate limiting
- **11k wordlist**: dnsx brute-force con 11.081 subdominios (antes: 20)
- **CVSS v3.1 corregido**: ahora calcula CRITICAL/HIGH correctamente
- **Reportes profesionales**: markdown + PDF con diagramas, severities, business impact
- **Attack Surface Diagram**: draw.io con severity coloring

## Verification Checklist

### ✅ Core Functionality
- [x] All CLI commands operational
- [x] All Go binary dependencies detected
- [x] 6 new discovery modules integrados en `ozy hunt --steroids`
- [x] Python dependencies installed and compatible
- [x] Database connection functional (SQLite)
- [x] API keys optional

### ✅ Test Suite
- [x] pytest runs without ImportError
- [x] 217/221 tests passing (98.2%)
- [x] Test isolation configured

### ✅ Version Management
- [x] Single source of truth: `pyproject.toml` version = "9.1.0"
- [x] CLI `--version` displays v9.1.0

## Environment Setup

### Prerequisites

- Python 3.11+ (tested on 3.14.5)
- Go binaries in `tools/go/bin/` (auto-detected by `doctor` command)
- Virtual environment (mandatory for dependency isolation)

### Installation

```bash
# Clone repository
git clone <repo-url>
cd OzyRecon

# Create and activate venv
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install package in editable mode
pip install -e .

# Verify installation
python ozy.py --version  # Should show: v9.0.1
python ozy.py doctor     # All checks should pass
```

### Running Tests

```bash
# Activate venv first
source venv/bin/activate

# Run full suite
pytest

# Expected output:
# 217 passed, 4 skipped in ~2m35s
```

## Known Limitations

### Non-Implemented Features

The following features are documented in design docs but NOT implemented in v9.0.1:

- **OzyAudit Integration**: Mentioned in architecture docs; stub exists but not production-ready
- **OzyRegistryAdapter / OzyPolicyAdapter**: Governance adapters referenced but not fully wired
- **Backend API**: `backend/` package referenced in `pyproject.toml` but directory is empty

These are intentionally excluded and marked as "Future" in documentation.

### Skipped Tests (4)

- `tests/test_runtime_end_to_end.py::test_end_to_end_flow_produces_normalized_artifacts_and_traces` — Integration test, requires live network
- `tests/test_src_architecture.py::test_src_structure_follows_hexagonal_layers` — Structural validation, skipped in fast mode
- `tests/validation/test_automation_validator.py::test_automation_validator_blocks_gate_required_without_approval` — Requires manual approval fixture
- `tests/validation/test_automation_validator.py::test_automation_validator_allows_gate_required_after_approval` — Requires manual approval fixture

## Bug Bounty Workflow

### Basic Reconnaissance Flow

```bash
# Activate venv
source venv/bin/activate

# Add target to authorized scope
python ozy.py scope add target.com

# Run full reconnaissance
python ozy.py flow target.com --profile safe-active

# View discovered assets
python ozy.py inventory

# Analyze specific host
python ozy.py analyze sub.target.com

# Export results
python ozy.py export target.com
```

### Available Profiles

- `safe-active` — Non-invasive active scanning (recommended for bug bounties)
- `passive` — Only passive discovery (safest)
- `aggressive` — Full active scanning (requires explicit authorization)

## Production Maintenance

### Version Updates

To update the version:

1. Edit `pyproject.toml` → `version = "X.Y.Z"`
2. Reinstall package: `pip install -e .`
3. Verify: `python ozy.py --version`
4. Update `CHANGELOG.md` with new version section
5. Update `docs/STATUS.md` with new version
6. Commit all version changes atomically

### Adding Dependencies

```bash
# Add to requirements.txt
echo "new-package>=1.0.0" >> requirements.txt

# Install
pip install -r requirements.txt

# Add to pyproject.toml dependencies
# Then reinstall
pip install -e .
```

### Running in Production

**Always use venv**:
```bash
source venv/bin/activate
python ozy.py <command>
```

**Never run with system Python** — this will cause dependency conflicts.

## Troubleshooting

### pytest ImportError: opentelemetry

**Cause**: pytest discovering Go module files with external dependencies.

**Solution**: Already fixed in v9.0.1 via `conftest.py`. If issue persists:
```bash
# Verify conftest.py exists
ls -la conftest.py

# Verify pyproject.toml has norecursedirs
grep -A5 "tool.pytest" pyproject.toml
```

### CLI shows wrong version

**Cause**: Package not reinstalled after version change.

**Solution**:
```bash
source venv/bin/activate
pip install -e .
python ozy.py --version  # Should show correct version
```

### Tests fail with module not found

**Cause**: Running tests outside venv or dependencies not installed.

**Solution**:
```bash
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
pytest
```

## Release History

### v9.0.1 (2026-05-30) — Production Readiness Release

**Changes**:
- Unified version management to 9.0.1 across all components
- Fixed pytest test isolation (conftest.py)
- Removed unimplemented feature references from documentation
- Git cleanup (untracked 183 Go module cache files)
- Standardized venv-based development workflow

**Commit**: `f0faa0d`  
**Test Status**: 217/221 passing (98.2%)  
**Production Status**: ✅ Ready

## Support

For issues or questions:
1. Check `python ozy.py doctor` output
2. Verify venv is activated
3. Review `docs/USAGE.md` for command examples
4. Check `CHANGELOG.md` for known issues

---

**Last Updated**: 2026-05-30  
**Maintainer**: OzyRecon Development Team  
**License**: See LICENSE file
