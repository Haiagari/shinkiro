# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [8.3.2] - 2026-05-01
### Added
- **Enterprise Operational Baseline**: Finalized stable production release.
- **Forensic Bundle 2.0**: Signatures now include `schema_version`, `session_id`, and `timestamp` for anti-replay protection.
- **Smart Graph Truncation**: Nodes prioritize high-risk findings when exceeding limits; includes `is_truncated` flag and metadata.
- **Log Rotation**: Automatic size-based rotation for JSONL and legacy logs (100MB max).

## [8.2.0] - 2026-05-01
### Added
- **Operational Hardening**: Advanced SSRF protection with Anti-DNS Rebinding (Pre-scan resolution).
- **Scan Lifecycle Control**: Managed cancellation via `POST /sessions/{id}/cancel`.
- **Automatic Storage TTL**: Background task for cleaning session data older than 7 days.
- **Enterprise Observability**: Structured JSONL logging for SIEM integration.

## [8.1.0] - 2026-05-01
### Added
- **Advanced API Key Auth**: Transition to hashed keys (SHA-256) and multi-key registry.
- **RBAC (Scopes)**: Granular permissions for endpoints (`hunt:run`, `sessions:read`, `admin:*`).
- **AI Analyst Layer**: Narrative impact reports and technical recommendations using LLM bridge.
- **Request Deduplication**: Private idempotency per user to prevent redundant scans.

## [7.5.0] - 2026-05-01
### Added
- **Elite Intelligence Layer**: Formalized inference rules using YAML-based `semantic_rules.yaml`.
- **Inference Trace (Explainability)**: Full audit-ready trace for every semantic classification.
- **Digital Evidence Integrity**: Implementation of Ed25519 digital signatures for finding validation.
- **Enterprise SIEM Integration**: Native exporters for Common Event Format (CEF) and structured JSON.
- **Actionable Graphs**: Decision-guidance visualization in Knowledge Graph (Critical Paths).

## [7.0.0-alpha.1] - 2026-04-30
### Added
- **Intelligent Engine v7**: Contextual recon with ASN, Org, and Cloud enrichment.
- **Snapshot Memory**: Historical diffing and novelty detection across scan sessions.
- **Takeover Hunter**: Automated DNS lineage tracking and Nuclei-based takeover validation.
- **Chameleon v2**: Refined stealth with identity rotation and shell quoting protection.

## [6.0.0-alpha.2] - 2026-04-27
### Added
- **Dynamic Report Generation (Phase 6)**: New reporting engine based on Jinja2 and WeasyPrint.
- **ozy report command**: CLI subcommand to generate comprehensive HTML and PDF reports.
- **Multi-format Support**: Capability to export reports as HTML, PDF, or both.
- **Template System**: Modular .j2 templates in `resources/reports/templates/` for easy customization.
- **Asset Scoring Integration**: Reports now include Top 5 Critical Assets from the Scoring Engine.
- **Attack Path Visualization**: Integration with Logic Analyzer to display potential attack vectors.

### Removed
- Legacy string-replacement based reporting engine in `src/reporting/engine.py`.
- Old static HTML template `resources/reports/template_v2.html`.

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
