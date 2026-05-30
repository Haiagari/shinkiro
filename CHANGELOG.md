# Changelog

## [Unreleased]

## [9.0.1] - 2026-05-30

### Added
- staged CLI progress across core and niche commands
- AI provider registry with mock, Gemini, OpenAI, and Ollama paths
- plugin hooks in ToolManager
- collaboration manifests per session
- quiet/minimal export mode
- **Development Tooling**: Created a dedicated `scripts/` directory structure (`scripts/performance/` and `scripts/experiments/`) to isolate proof of concept scripts and load testing tools from the core application, ensuring the testing framework remains clean.
- root `conftest.py` for pytest test isolation

### Changed
- documentation rewritten around the current ASM workflow
- **Architecture (Concurrency Optimization)**: Completely overhauled the execution model in `src/scanners/web/fuzzer.py`. It now utilizes a native Python `ThreadPoolExecutor` with a bounded worker pool (`max_workers=3`). This allows `ffuf` to run massive wordlists and host scans in parallel, exponentially reducing I/O wait times while preventing local network stack saturation and maintaining thread safety via Python's GIL.
- **Architecture (Secret Scanner Upgrade)**: Finalized the orphan `ThreadPoolExecutor` logic in `src/intelligence/secret_finder.py` by implementing the `scan_urls_concurrently()` method. The scanner can now process massive lists of URLs asynchronously without blocking the orchestrator's main thread.
- **Testing & Environment Standards**: Enforced strict environment isolation. The `pytest` test suite and application execution must now explicitly run inside the local virtual environment (`venv`). This resolves critical dependency conflicts (e.g., `opentelemetry` system-level collisions) and standardizes the project's onboarding process.

### Fixed
- unified version management using `pyproject.toml` as single source of truth with `importlib.metadata` fallback
- removed unimplemented feature references from documentation (OzyRegistryAdapter, OzyPolicyAdapter, REPORT mode, SERVICE mode)
- aligned all version references to 9.0.1 across codebase and documentation

### Added
- audit-ready flow, diff, schedule, and serve commands
