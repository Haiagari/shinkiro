```yaml
schema: gentle-ai.verify-result/v1
evidence_revision: sha256:d72bd6392235c5c6bb1b46e80b061eed7ceccc473fc8146c83fdd2ef7fafe6d9
verdict: fail
blockers: 0
critical_findings: 1
requirements: 6/6
scenarios: 7/7
test_command: venv/bin/python3 -m pytest -q
test_exit_code: 0
test_output_hash: sha256:60d94f3f5a2a86eb92dd72fa3a999c45f01aaf554787fcfe80b7a4f365df704f
build_command: venv/bin/python3 -m pytest --co -q
build_exit_code: 0
build_output_hash: sha256:edbd0302ee7b4896ae1083fbd9f19a4eb7b099ec8ba3b8b2adcebfdf4b020dae
```

## Verification Report

**Change**: guardrail-pivot
**Slice**: 1 — v9 deletion + AIProvider extraction + green baseline + dep hygiene
**Version**: v9-recon-removal spec (6 req / 7 scenarios, counted from on-disk spec)
**Mode**: Strict TDD
**Base**: tag `v9-recon-last` (7f6e02f) — branch `sdd/guardrail-pivot/slice-1`, 5 commits

### Completeness
| Metric | Value |
|--------|-------|
| Tasks total (slice 1) | 6 (T1.1–T1.6) |
| Tasks complete | 6 |
| Tasks incomplete | 0 |
| Commits on branch | 5 (5752c94, e02a57c, 347d3ed, d83a375, e3e16d0) |
| Diff vs tag | 298 files, +234 / −32,813 |

### Build & Tests Execution
**Build (collection gate)**: ✅ Passed — `venv/bin/python3 -m pytest --co -q` → `17 tests collected in 0.24s`, exit 0 (hash `edbd0302…`)

**Tests**: ✅ 17 passed / 0 failed / 0 errors / 0 skipped (exit 0, hash `60d94f3f…`)
```text
17 passed, 15 warnings in 0.51s
```
Warnings are `datetime.utcnow()` DeprecationWarnings — non-blocking.

**Lint**: ✅ `ruff check src/ tests/` (ruff 0.15.12) → `All checks passed!`, exit 0 (hash `82b3e6a6…`)

**Smoke**: ✅ `from src.adapters.llms.provider_base import AIProvider, MockProvider` → `ok`, MockProvider instantiable.

### Spec Compliance Matrix
| Requirement | Scenario | Test / Evidence | Result |
|-------------|----------|-----------------|--------|
| V9-1 — v9 modules removed | Modules absent | Path check: `src/workflow`, `src/scanners`, `src/agent` absent; all other v9 dirs (`discovery`, `intelligence`, `modes`, `opsec`, `scheduler`, `scope`, `export`, `reporting`, `validation`, `events`, `core/providers`) contain **0 files**, untracked in git (fresh clone absent). `grep` for imports of any deleted module in `src/`+`tests/` → 0 matches. | ✅ COMPLIANT (empty-dir residue on disk → WARNING-4) |
| V9-2 — Asset chain resolved | No Asset import | `grep -rn "from src.domain.models import Asset"` src/ tests/ → 0 matches; broad deleted-module reference grep → 0 matches; `sqlite_repository.py`, `asset_repository.py`, `tool_provider.py`, `webhook_adapter.py`, `ozy_policy_adapter.py`, `adapters/registry/`, `gate/` all deleted. | ✅ COMPLIANT |
| V9-3 — Green baseline | Suite green | `pytest -q` exit 0, 17 passed, 0 collection errors; `pytest --co -q` → 17 collected, 0 errors; no pytest-cov in pyproject. | ✅ COMPLIANT |
| V9-3 — Green baseline | Async test marked | `test_application_orchestrator.py`: 2 async tests / 2 `@pytest.mark.asyncio`; `test_judge_adapter.py`: 2 async / 2 marks; no `asyncio_mode = "auto"` in pyproject. | ✅ COMPLIANT |
| V9-4 — AIProvider extracted | Provider base importable | `src/adapters/llms/provider_base.py` exists (104 LOC): `AIProvider` ABC + Mock/Gemini/OpenAI/Ollama registry, `__all__` exported; import smoke passes; `tests/adapters/llms/test_provider_base.py` (3 tests: ABC abstract, Mock instantiable + generates content, registry members subclass ABC) — all pass. | ✅ COMPLIANT |
| V9-5 — CLI dead commands removed | Mode loader gone | `cli/ozy.py` diff shows `register_mode_commands` (pkgutil over `src/modes/`, BaseMode/HuntMode/ContinuousMode/CampaignMode wrappers) deleted; dead command files deleted; `cli/commands/` = only `__init__.py`, `keys.py`, `serve.py`, `self_test.py`; runtime `python -m cli --help` registers exactly `keys, self-test, serve`. | ✅ COMPLIANT |
| V9-6 — Dependency hygiene | Declared deps install | `requirements.txt` absent; `pyproject.toml` single source (`sqlalchemy, requests, rich, click, pyyaml, cryptography, fastapi, uvicorn, httpx, python-telegram-bot`); console script `promptwall = "cli.ozy:main"` (no `ozy` entry); dev deps pytest/pytest-asyncio/ruff. Venv imports proxy shell + CLI + provider_base successfully. | ✅ COMPLIANT (dep declaration gaps → WARNING-2/3) |

**Compliance summary**: 7/7 scenarios compliant (0 UNTESTED, 0 FAILING)

### Correctness (Static Evidence)
| Requirement | Status | Notes |
|------------|--------|-------|
| V9-1 deletion map | ✅ Implemented | 32,813 deletions match design DELETE list; `runtime_paths.py` + `application/ports/event_bus.py` kept deliberately (kept code imports them — apply note #2598; not recon runtime) |
| V9-2 Asset chain | ✅ Implemented | All six listed modules removed; 0 references |
| V9-3 gates | ✅ Implemented | pytest + ruff, no pytest-cov, strict asyncio |
| V9-4 provider_base | ✅ Implemented | Extracted 1:1 from `ai_analyzer.py` pattern (ABC + 4 providers) |
| V9-5 CLI | ✅ Implemented | Mode loader gone; kept commands only |
| V9-6 deps | ⚠️ Partial | pyproject unified + requirements.txt gone + script renamed; pydantic not declared (transitive via fastapi); openai/google-generativeai used by kept provider_base but not declared (guarded lazy imports degrade gracefully) |

### Coherence (Design)
| Decision | Followed? | Notes |
|----------|-----------|-------|
| Delete v9 tree per DELETE list | ✅ Yes | All paths in design's delete list removed (0 tracked files) |
| KEEP map intact | ✅ Yes | `utils/crypto.py`, `auth/`, `storage/database.py`, `core/config.py`+`bootstrap.py`, `plugins/`, `notifications/`, `judge_adapter.py`, CLI shell, FastAPI shell all present |
| AIProvider extraction to `adapters/llms/provider_base.py` | ✅ Yes | Before intelligence deletion, per commit 5752c94 |
| Tag `v9-recon-last` pre-slice | ✅ Yes | Tag at 7f6e02f (parent of first slice commit) |
| Entry-point rename in slice 1 (T1.5) | ✅ Yes | Tasks placed rename in slice 1 (design mentioned slice 5 for CLI-1; tasks hierarchy wins) |

### TDD Compliance
| Check | Result | Details |
|-------|--------|---------|
| TDD Evidence reported | ❌ | Apply-progress (#2598, topic sdd/guardrail-pivot/apply-progress) documents per-commit mapping + gates in prose but **no formal TDD Cycle Evidence table** (RED/GREEN/TRIANGULATE/SAFETY NET/REFACTOR) |
| All tasks have tests | ✅ | T1.1: `test_provider_base.py` (3 tests); deletion tasks verified by path-absence + suite green (structure of deletion tasks) |
| RED confirmed (tests exist) | ✅ | 3/3 test files verified on disk |
| GREEN confirmed (tests pass) | ✅ | 17/17 pass on execution |
| Triangulation adequate | ✅ | V9-4 scenario covered by 3 distinct assertions (abstractness, instantiation+behavior, registry completeness); deletion scenarios covered by absence checks + grep |
| Safety Net for modified files | ✅ | Kept files ran green suite pre/post (17 pass); only authored file is provider_base.py + its test |
| Assertion quality | ✅ | No tautologies, no ghost loops, no smoke-only tests; all assertions exercise production code |
| Test layer distribution | ✅ | Unit: 17 tests / 7 files (Python; no JS/browser layer applies) |

**TDD Compliance**: 6/7 checks passed (missing table = CRITICAL-1, protocol-format only)

### Issues Found
**CRITICAL**
1. **Apply-progress lacks the formal TDD Cycle Evidence table** (strict-tdd-verify.md Step 5a). Observation #2598 documents TDD evidence in prose (per-commit task mapping, gates, async-marker check) but not the RED/GREEN/TRIANGULATE/SAFETY NET/REFACTOR table the protocol requires. Independent verification confirms all substantive evidence exists and passes (test files on disk, 17/17 green, real assertions). Remediation = amend the apply report with the table; zero code impact.

**WARNING**
1. **Uncommitted working-tree changes on the slice branch**: `src/core/config.py` modified (dead `import os` removed; default key `ozy-secret-key`→`promptwall-secret-key`) — outside the 5 commits; also session files (`opencode.json`, `.atl/skill-registry.md`, `opencode.json.backup-*`) modified/untracked (environment noise). Config.py edit should be committed with slice 1 or reverted/stashed before PR.
2. **pydantic not declared in pyproject.toml** though spec V9-6 lists it among the single-source runtime deps. No direct `import pydantic` in kept `src/`+`cli/`; satisfied transitively via fastapi, so functional impact nil — declare explicitly to match the spec list.
3. **openai / google-generativeai not declared but used by kept code**: `provider_base.py` lazily imports both (guarded `try/except` — Gemini/OpenAI providers degrade to `None` without them). Not declared in pyproject and not documented in-repo (apply memory #2598 notes the decision). Per V9-6 "deps used by surviving tree must be declared or documented" → declare as optional extras or document the degradation in pyproject/README.
4. **Empty v9 directory shells remain in the working tree**: `src/discovery/`, `src/intelligence/`, `src/modes/`, `src/opsec/`, `src/scheduler/`, `src/scope/`, `src/export/`, `src/reporting/`, `src/validation/`, `src/events/`, `src/core/providers/`, `src/adapters/targets/`, `src/security/` exist with 0 files (untracked; absent in a fresh clone). Strictly the V9-1 scenario says paths "do not exist" — functionally satisfied, cosmetic residue on disk (`git clean -fd` / `rmdir`).
5. **Scenario-count drift in planning artifacts**: tasks.md header and Engram #2595 state "6 reqs / 9 scenarios"; the authoritative on-disk spec has 7 scenarios (V9-3 carries 2). Counts corrected in this report (6/7); update tasks.md header when convenient.

**SUGGESTION**
1. `cli/ozy.py` still registers commands via pkgutil autodiscovery (`_autodiscover_commands`). Functionally compliant (only the 3 kept commands exist and register) but the V9-5 scenario wording "no dynamic registration" is satisfied more literally by explicit `cli.add_command(keys/serve/self_test)`.
2. Leftover recon branding: banner "Advanced Persistent Reconnaissance", "CLI Elite Edition", usage string "ozy <command>", docstring "Usage: ozy" — cosmetic; slice 5 rebrand handles it.
3. `ruff target-version = "py310"` while `requires-python = ">=3.11"` — align to py311.
4. pyproject description/keywords still recon-flavored ("reconnaissance", "scanning", "attack surface evaluation").
5. 15 `datetime.utcnow()` DeprecationWarnings in kept code — migrate to `datetime.now(datetime.UTC)` opportunistically.

### Verdict
FAIL (not archive-ready) — single CRITICAL is protocol-format only (TDD Cycle Evidence table missing from apply report); all 6 requirements / 7 scenarios COMPLIANT, all runtime gates green (17 passed, 0 errors; ruff clean; provider_base importable). After the apply report is amended with the table (and the small WARNING cleanups: commit/stash config.py, declare pydantic + optional provider deps, rmdir empty shells), the slice is PR-ready.
