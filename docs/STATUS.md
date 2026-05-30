# Status

- Version: `9.0.1` (Production-Ready)
- Runtime: audit-ready ASM pipeline
- CLI: staged output enabled across core commands
- Test Suite: 217/221 tests passing (4 skipped)

## Production Status

✅ **Ready for Bug Bounty Use**

- All core reconnaissance workflows operational
- Complete test coverage with passing suite
- Version unified across all components
- Documentation aligned with implemented features
- Clean git state with production commit: `f0faa0d`

## Current state

- scope validation is enforced
- FLOW and AUDIT modes are operational
- diff tracking is live
- collaboration manifests are written per session
- AI analysis supports multiple providers with fallback
- payload generation is excluded by design
- pytest test isolation configured (conftest.py)
- venv-based development workflow standardized

## Key docs

- `README.md`
- `docs/USAGE.md`
- `docs/architecture.md`
- `docs/EXCLUSIONS.md`
- `docs/RUNTIME_CONTRACT.md`
