# V9 Recon Removal Specification

## Purpose

Slice 1: delete the v9 recon stack (~17k LOC), extract the AIProvider pattern, and restore a green test baseline. Pure removal — no new product behavior.

## Requirements

### Requirement: V9-1 — v9 recon modules removed

The listed v9 modules MUST be deleted from the tree: `src/discovery/`, `src/modes/`, `src/intelligence/` (after extraction), `src/core/providers/`, `src/opsec/`, `src/scheduler/`, `src/scope/`, `src/export/`, `src/reporting/`, `src/validation/`, `src/workflow/`, `src/events/` (v9 bus), `src/scanners/`, `src/storage/db_queries.py`+`queries.py`+`diff.py`, recon runtime modules in `src/core/`, `src/agent/config_writer.py`, `src/security/target_validator.py`, and dead `cli/commands/` (analyze, audit, compliance_check, diff, doctor, exploits, export, flow, init, inventory, paths, schedule, scope, screenshot, secrets, verify, watch).

#### Scenario: Modules absent

- GIVEN the tree after slice 1
- WHEN the listed paths are checked
- THEN they do not exist and no surviving code imports them

### Requirement: V9-2 — Broken Asset chain resolved

Modules leaking into the deleted `Asset` model MUST be removed or re-pointed to v10: `src/adapters/storage/sqlite_repository.py`, `src/application/ports/asset_repository.py`, `src/application/ports/tool_provider.py`, `webhook_adapter.py`, `ozy_policy_adapter.py`, `gate/manager.py`.

#### Scenario: No Asset import

- GIVEN the surviving tree
- WHEN searching for `from src.domain.models import Asset` and v9 storage imports
- THEN no matches remain

### Requirement: V9-3 — Green test baseline

The pytest suite MUST collect with 0 errors and all remaining tests MUST pass; async tests MUST carry `@pytest.mark.asyncio` (strict mode — no `asyncio_mode` auto-enable); gates are pytest + ruff (no pytest-cov).

#### Scenario: Suite green

- GIVEN slice 1 applied
- WHEN `pytest` runs
- THEN exit code 0 with 0 collection errors

#### Scenario: Async test marked

- GIVEN any async test in the surviving suite
- WHEN inspected
- THEN it is decorated with `@pytest.mark.asyncio`

### Requirement: V9-4 — AIProvider extracted

The AIProvider ABC + registry (Mock/Gemini/OpenAI/Ollama) MUST be extracted from `src/intelligence/ai_analyzer.py` to `src/adapters/llms/provider_base.py` BEFORE the intelligence deletion, and MUST be importable and tested.

#### Scenario: Provider base importable

- GIVEN the extracted module
- WHEN `from src.adapters.llms.provider_base import AIProvider` runs
- THEN it succeeds and a Mock provider can be instantiated

### Requirement: V9-5 — CLI dead commands removed

The mode loader MUST be removed from `cli/ozy.py`; `cli/commands/keys.py`, `serve.py`, `self_test.py` are kept; all other commands are deleted.

#### Scenario: Mode loader gone

- GIVEN the CLI after slice 1
- WHEN the shell loads
- THEN no dynamic mode registration occurs and only kept commands are registered

### Requirement: V9-6 — Dependency hygiene

`pyproject.toml` MUST be the single source of truth for runtime deps used by the surviving tree (httpx, cryptography, fastapi, click, rich, python-telegram-bot, pydantic, sqlalchemy); deps used only by deleted v9 code MUST be dropped or documented.

#### Scenario: Declared deps install

- GIVEN the unified pyproject
- WHEN installed in a clean venv
- THEN the proxy and CLI import successfully
