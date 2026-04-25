# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [6.0.0-alpha] - 2026-04-24
### Added
- **Phantom Blade Architecture**: Total paradigm shift to Advanced Persistent Reconnaissance.
- **Chameleon Engine**: Stealth layer using `curl_cffi` for TLS Fingerprinting impersonation (Chrome, Safari, Firefox).
- **Logic Analyzer**: Brain-derived attack paths based on Knowledge Graph relationships.
- **Surgical Prober**: Evidence-based validation engine for zero-noise findings.
- **Autopilot Mode**: Automated approval for high-confidence (0.95+) hypotheses.
- **Unified Entry Point**: New `./ozy.py` script for centralized CLI/TUI management.

### Changed
- Refactored HTTP client to use `curl_cffi` by default for all operations.
- Updated `setup.sh` with v6 stealth verification.
- Improved `README.md` with relationship-driven intelligence focus.

## [5.7.0] - 2026-04-24
### Added
- **Knowledge Graph v2**: Full visualization of infrastructure relationships using D3.js.
- **Evidence Vault**: Cryptographic signing of findings using SHA256 hashes for audit trails.
- **OPSEC Pre-commit Hook**: Automatic detection of sensitive domains/keys before commits.
- **Human-Gate API**: REST endpoints to manage manual approvals for sensitive probes.
- **FastAPI Integration**: High-performance API layer for remote management.

### Changed
- Refactored core architecture: Migrated from monolithic structure to domain-driven `src/` layout.
- Enhanced Intelligence Layer: Improved correlation between subdomain discovery and service exposure.

### Fixed
- API bug where `/targets` returned 500 on empty databases.
- Memory leak in the scoring engine during long-running hunts.
- Inconsistent version reporting in CLI vs API.

## [5.0.0] - 2026-02-15
### Added
- Initial Human-in-the-loop (HITL) implementation.
- Automated hypothesis generation engine.
- SQLite backend for persistent state management.

## [1.0.0] - 2025-10-01
### Added
- Basic subdomain enumeration.
- Port scanning integration.
- Initial project scaffold.
