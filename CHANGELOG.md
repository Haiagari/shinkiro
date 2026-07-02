# Changelog

## [10.0.0] (AI Security Pivot) - 2026-07-02

### Changed
- **Massive Architectural Pivot**: OzyRecon has transitioned from an Offensive Infrastructure Recon tool to an AI Security Guardrail (Firewall for LLMs).
- **Core Engine**: Replaced linear scanning engines with an asynchronous EventBus designed to intercept and validate incoming prompts.

### Added
- **Judge LLM Validator**: Added evaluation layers using a Judge LLM to detect prompt injections, jailbreaks, and malicious intents.
- **Safe Forwarding**: Added safe forwarding mechanisms that automatically route clean prompts to Target APIs while blocking malicious ones.
- **Audit Logging**: Added comprehensive tracking and metrics for blocked versus permitted requests.

### Removed
- **Legacy Recon Tools**: Completely removed network scanning legacy tools including `nmap`, `subfinder`, `nuclei`, `httpx`, `naabu`, etc.
- **Offensive Discovery Phases**: Removed all recon phases (DNS brute-force, JS endpoint extraction, S3 scanning, Dorking, etc.).
- **Recon Modes**: Removed hunt, continuous, research, campaign, and forensic modes.

## [9.1.0] - 2026-06-16

### Fixed
- **CVSS v3.1 calculator**: fixed base score calculation — was missing impact multipliers (6.42 for S:U, 7.52 for S:C) and `_roundup` used `round()` instead of `ceil()`. Findings that always returned MEDIUM now correctly score CRITICAL/HIGH.
- **PDF table separator**: `md_simple_to_html` only detected exact `-`/`---` separators, now accepts any length (`^:?-+:?$`).

### Added
- **6 new discovery modules**: JS endpoint extraction, subdomain permutations (9 rules), parameter discovery (764 params), S3 bucket scanner (267 combinations), Google dorking (30 dorks), 11k subdomain wordlist. All wired into `ozy hunt --steroids`.
- **Attack Surface Overview**: replaces flat 390+ asset table (with empty `-` columns) with risk-categorized groups (Web, API, Admin, Internal, Infrastructure) + narrative.
- **Business Impact section**: each finding now includes contextualized business impact.
- **Attack Surface Diagram**: draw.io diagram at `docs/diagrams/attack-surface.{drawio,svg,png}` with severity coloring.
- **Screenshot integration**: inline image support in markdown and PDF reports.
- **Severity badges**: CSS with colored badges (red CRITICAL, orange HIGH, yellow MEDIUM, blue LOW) in PDF export.
- **Inline formatting in PDF**: `_render_text()` combines markdown→HTML + severity badges + bold/code/links.
- **`reports/generated/`**: standard output directory for new reports.
- **Clean `__init__.py`**: public exports from `src.reporting`.

### Changed
- **`reports/` organized**: old reports moved to `archive/`, evidence organized under `evidence/http/` and `evidence/screenshots/`.
- **`ProfessionalReport` constructor**: accepts optional `screenshots_dir` and `diagram_path`.
- **PDF CSS**: complete redesign with zebra striping, severity badges, image support, page breaks.
- **Findings classification**: GLPI and admin tools now separate findings with their own CVSS and evidence.
- **DNS brute-force**: wordlist upgraded from 20 entries to 11,081.

### Removed
- `scripts/test_report_gen.py` (obsolete, used old inline HTML generation)

## [9.0.2] - 2026-06-15

### Fixed
- **Nmap timeouts**: replaced sequential nmap with parallel naabu + selective nmap; timeout reduced from 120s to 30s
- **Flow session_id**: correct UUID generation and persistence in DB, removed "legacy-session"
- **Amass timeouts**: timeout reduced from 180s to 30s, retry removed, error non-fatal
- **Duplicate exploits command**: removed second CLI registration

### Refactored
- **Autodiscovery CLI**: `register_runtime_commands()` simplified from 22 try/except (~150 lines) to pkgutil autodiscovery (~25 lines)
- **Unified DB queries**: `DBQueries` as single source; `db_queries.py` delegated (227→44 lines); `SQLiteAssetRepository` delegated (78→20 lines)
- **BaseMode split**: `ModeRunner`, `SessionManager`, `EnvelopeBuilder` extracted; `BaseMode.run()` from 335→184 lines
- **Intelligence organized**: 30 flat files moved to 8 subdirectories (core, scoring, learning, enrichment, analysis, autonomy, pipeline, export)
- **Placeholders removed**: `validation/web.py`, `validation/cms.py`, `validation/config.py`, `backend/` (empty)

### Added
- **Real EventBus**: `src/events/` with `DomainEvent`, `AssetDiscovered`, `FindingDetected`, `ScanCompleted` + `EventBus` singleton
- **AsyncExecutor**: parallel tool execution with ThreadPoolExecutor in discovery and crawler
- **Plugin system**: abstract `Plugin`, `PluginLoader`, `dispatch_hook`, example plugin
- **PostgreSQL support**: configurable via `OZY_DATABASE_URL` env var (SQLite remains default)
- **Redis task queue**: distributed tasks via `OZY_REDIS_URL` (YAML as fallback)
- **Log rotation**: audit log auto-rotates at 50 MB, up to 5 backups
- **96 new tests**: DiffEngine, OPSEC (jitter, kill_switch, rate_limiter), validators, notifier, normalizer
- **Aggressive .gitignore**: caches, test data, screenshots, config/api_keys.json
- **Root cleanup**: 24 test/data files removed (`load_*.json`, `json*.txt`, `run*.json`)

### Security
- **Sensitive data**: `reports/reales/`, `storage/evidence/screenshots/`, `config/api_keys.json` added to .gitignore

## [9.0.1] - 2026-05-30

### Added
- Staged CLI progress across core and niche commands
- AI provider registry with mock, Gemini, OpenAI, and Ollama paths
- Plugin hooks in ToolManager
- Collaboration manifests per session
- Quiet/minimal export mode
- Root `conftest.py` for pytest test isolation

### Changed
- Documentation rewritten around current ASM workflow
- ThreadPoolExecutor concurrency in fuzzer and secret scanner
- Enforced venv-based development workflow

### Fixed
- Unified version management using `pyproject.toml`
- Removed unimplemented feature references from documentation
- Aligned all version references to 9.0.1 across codebase
