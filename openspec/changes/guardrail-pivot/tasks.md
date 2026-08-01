# Tasks: Guardrail Pivot (PromptWall)

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | ~20,000 total (Slice 1 ≈ 17.3k, almost all deletions; Slices 2-6 ≈ 3.1k authored additions) |
| User review budget | 800 lines/slice (session preflight) |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 (deletion) → PR 2 → PR 3 → PR 4 → PR 5 → PR 6a → PR 6b |
| Delivery strategy | auto-forecast |
| Chain strategy | stacked-to-main |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: stacked-to-main
400-line budget risk: High

Rationale: Slices 2-6 all exceed 400 lines each (~490-750); Slice 1 is a ~17.3k-line pure deletion diff. PR 1 requires `size:exception` (deletion-only diff, verified by path-absence + green suite, revertible via `git revert`; cannot be meaningfully split). Slice 6 packs 10 reqs (AUDIT-1..4 + FEEDBACK-1..5 + LLM-PROXY-8) → split into PR 6a (signed audit) + PR 6b (feedback + alerts). Chain strategy NOT set in preflight → orchestrator confirms **stacked-to-main** with user before apply.

### Suggested Work Units

| Unit | Goal | Likely PR | Focused test command | Runtime harness | Rollback boundary |
|------|------|-----------|----------------------|-----------------|-------------------|
| 1 | v9 deletion + AIProvider extraction + green baseline + dep hygiene (V9-1..6) | PR 1 (size:exception) | `pytest --co` (0 errors) + `ruff check src tests` + `grep -r "from src.domain.models import Asset" src/` | `python -c "from src.adapters.llms.provider_base import AIProvider; from src.adapters.llms.provider_base import MockProvider; print(MockProvider())"` in clean venv | `git revert <slice1-commit>` restores v9; tag `v9-recon-last` before start |
| 2 | Proxy skeleton: KeyStore auth + per-key rate limit + 422/401/403/429 + audit JSONL shape, MockProvider judge (LLM-PROXY-1,2,3) | PR 2 | `pytest tests/test_proxy_skeleton.py -q` | `promptwall serve --port 8080` + `curl -X POST /v1/chat/completions` with temp KeyStore key | Revert api.py rewrite + new test file; no DB migration |
| 3 | Real judge (httpx, verdict parse, retries, fail-closed) + upstream passthrough + buffer-then-judge SSE (JUDGE-1..5, LLM-PROXY-4,6,7) | PR 3 | `pytest tests/adapters/llms/test_openai_compatible_judge.py tests/test_proxy_streaming.py -q` | httpx MockTransport unit tests; live `curl -N` against mock upstream only | Revert judge adapter + streaming block in api.py; independent of PR 2 revert |
| 4 | Policy engine: deterministic rules, precedence, sets, atomic reload; judge short-circuit (POLICY-1..7, LLM-PROXY-5) | PR 4 | `pytest tests/adapters/policy/ tests/test_policy_block.py -q` | `promptwall rules list` / `rules reload` against `config/policies/default.yaml` | Revert policy engine + loader + config/policies; allow/block wiring revertible alone |
| 5 | CLI (`promptwall serve\|rules\|keys\|audit\|self-test`, `ozy` gone) + GET /v1/audit (CLI-1..6, AUDIT-5) | PR 5 | `pytest tests/test_cli_guardrail.py tests/test_audit_read.py -q` | `promptwall --help`; `promptwall keys create --name app-a --scope chat` | Revert cli/ + audit endpoint; entry-point rename in pyproject isolated |
| 6 | Signed audit: Ed25519 + canonical payload + tamper detection + rotation + LLM-PROXY-8 every-decision entry | PR 6a | `pytest tests/test_signed_audit.py -q` | `promptwall audit` after a proxied request; verify signatures | Revert signed_audit.py + audit emission; JSONL files removable, no migration |
| 7 | Feedback loop (POST /v1/feedback 202/404/422/401) + alerts (Alert row, dispatch_hook, Telegram) | PR 6b | `pytest tests/test_feedback.py tests/test_alerts.py -q` | POST /v1/feedback with audit-scope key; mocked Telegram client | Revert feedback endpoint + alert wiring; Alert table created fresh by init_db |

## Slice 1 — v9 Deletion + AIProvider Extraction + Green Baseline (V9-1..6, 6 reqs / 9 scenarios)

- [ ] **T1.1** (V9-4) Create `src/adapters/llms/provider_base.py`: AIProvider ABC + Mock/Gemini/OpenAI/Ollama registry extracted from `src/intelligence/ai_analyzer.py:16-96`. RED first: test asserts import + MockProvider instantiable. Files: `src/adapters/llms/provider_base.py`, `tests/adapters/llms/test_provider_base.py`. DoD: `from src.adapters.llms.provider_base import AIProvider` succeeds.
- [ ] **T1.2** (V9-1) Delete v9 src tree in rm-batches: `src/{discovery,intelligence,modes,opsec,scheduler,scope,export,reporting,validation,workflow,events,scanners}`, `src/core/{providers,runtime_*}` + recon core modules, `src/agent/config_writer.py`, `src/security/target_validator.py`, `src/storage/{db_queries,queries,diff}.py`. Run `pytest --co` after EVERY batch; stop on collection errors. Files: v9 tree. DoD: paths absent, suite still collects.
- [ ] **T1.3** (V9-2) Remove Asset-chain leaks: delete `src/adapters/storage/sqlite_repository.py`, `src/application/ports/asset_repository.py` + `tool_provider.py`, `src/adapters/policy/ozy_policy_adapter.py`, `src/adapters/events/webhook_adapter.py`, `src/adapters/registry/`, `src/gate/`. Files: above. DoD: `grep -r "from src.domain.models import Asset" src/` → 0 matches.
- [ ] **T1.4** (V9-5) Delete dead `cli/commands/` (analyze, audit, compliance_check, diff, doctor, exploits, export, flow, init, inventory, paths, schedule, scope, screenshot, secrets, verify, watch); remove mode loader from `cli/ozy.py` (keep keys.py, serve.py, self_test.py). Files: `cli/ozy.py`, `cli/commands/`. DoD: no dynamic mode registration, kept commands registered.
- [ ] **T1.5** (V9-6) Unify deps: `pyproject.toml` single source of truth (httpx, cryptography, fastapi, click, rich, python-telegram-bot, pydantic, sqlalchemy); drop v9-only deps or document; delete `requirements.txt`; script `ozy` → `promptwall`. Files: `pyproject.toml`, `requirements.txt` (delete). DoD: clean-venv `pip install -e .` + proxy/CLI import.
- [ ] **T1.6** (V9-3) Delete v9 tests (intelligence/discovery/modes/opsec/reporting/export/scope/validation/storage/core-recon/integration/notifications v9, test_contracts, test_api_integration, test_observability, test_runtime_end_to_end, test_src_architecture, test_v57_features, test_hardening_guardrails). Verify every async test carries `@pytest.mark.asyncio`. Files: `tests/`. DoD: `pytest` exit 0, 0 collection errors; `ruff check` clean; no pytest-cov.

## Slice 2 — Proxy Skeleton: Auth + Rate Limit + Audit Shape (LLM-PROXY-1,2,3; 3 reqs / 6 scenarios)

- [ ] **T2.1** RED: integration tests for `POST /v1/chat/completions` via httpx AsyncClient + temp KeyStore + MockProvider: 422 malformed body (no upstream), 401 missing/invalid/disabled key, 403 insufficient_scope, 429 + Retry-After, within-limit pass. Files: `tests/test_proxy_skeleton.py`. DoD: tests fail (route absent).
- [ ] **T2.2** Add `src/domain/reason_codes.py` (ReasonCode enum: 12 codes incl. policy_block, judge_unavailable, rate_limit_exceeded, upstream_failure); extend `src/domain/models.py` (IncomingPrompt, UpstreamResponse, Verdict, PolicyDecision; drop Asset refs) + `src/domain/events.py` (PromptForwarded, DecisionRecorded); redefine `src/core/contracts.py` (IJudgeLLM→Verdict, drop IAttackerLLM). Files: above + `tests/domain/test_reason_codes.py`. DoD: enum + models importable, frozen dataclasses.
- [ ] **T2.3** Rewrite `src/core/api.py`: `/v1/chat/completions` route — pydantic parse → KeyStore.verify_key → per-key RateLimiter → decision service → audit JSONL append; `_MASTER_KEYS` (33-38) removed; `/health`. Files: `src/core/api.py`, `src/core/config.py` (guardrail section). DoD: T2.1 tests green.
- [ ] **T2.4** Create `src/application/guardrail_service.py` (`GuardrailDecisionService.decide(prompt, key)` skeleton: policy(allow-all placeholder) → MockProvider judge → Decision); emit JSONL audit entry (unsigned shape, signed in slice 6). Files: `src/application/guardrail_service.py`, `src/storage/models.py` (PromptEvent). DoD: decision recorded; audit entry written for every outcome.

## Slice 3 — Real Judge + Passthrough + Streaming (JUDGE-1..5, LLM-PROXY-4,6,7; 8 reqs / 14 scenarios)

- [ ] **T3.1** RED: judge unit tests with httpx MockTransport: POSTs to `{base_url}/chat/completions` with model; valid verdict parse; malformed/missing-field → fail-closed; retry-then-success (retries=2); persistent failure → judge_unavailable. Files: `tests/adapters/llms/test_openai_compatible_judge.py`. DoD: fail before implementation.
- [ ] **T3.2** Create `src/adapters/llms/openai_compatible_judge.py`: httpx POST, structured verdict parse (`{verdict, reason, confidence}`), timeout_seconds + retries from config, fail-closed on any error. Files: file above. DoD: T3.1 green; JUDGE-1..5 covered.
- [ ] **T3.3** RED: passthrough + streaming tests: upstream success relays OpenAI-shaped response; 5xx/unreachable → 502 generic (no internals); stream=true blocked → 403 before first SSE chunk; allowed → SSE chunks in OpenAI format. Files: `tests/test_proxy_streaming.py`. DoD: fail before implementation.
- [ ] **T3.4** Wire upstream passthrough (upstream key from env, never client key) + buffer-then-judge SSE relay into `src/core/api.py`; config keys `guardrail.judge/upstream` with startup validation (missing base_url/model fails loudly, JUDGE-1). Files: `src/core/api.py`, `src/core/config.py`. DoD: T3.3 green; fail-closed default.

## Slice 4 — Policy Engine (POLICY-1..7, LLM-PROXY-5; 8 reqs / 13 scenarios)

- [ ] **T4.1** RED: pure unit tests: declared order first-match-wins; allow-before-block overrides; named sets (default only); judge-spy asserts ZERO judge calls on rule block; block → 403 policy_block + rule_id. Files: `tests/adapters/policy/test_policy_engine.py`. DoD: fail before implementation.
- [ ] **T4.2** Create `src/adapters/policy/policy_engine.py` (Rule: id/kind regex|keyword/pattern/action/reason_code; PolicySet immutable) + `src/adapters/policy/yaml_policy_loader.py` (valid load; invalid YAML → startup fails clearly, no partial policy) + `config/policies/default.yaml` starter rules (injection, jailbreak, PII regex). Files: above. DoD: T4.1 green; POLICY-1..5 covered.
- [ ] **T4.3** RED: reload tests: valid reload swaps active set; invalid reload keeps previous set + error reported; SIGHUP path. Files: `tests/adapters/policy/test_policy_reload.py`. DoD: fail before implementation.
- [ ] **T4.4** Atomic reload (`PolicyStore.reload()` + SIGHUP handler) + wire policy BEFORE judge in `GuardrailDecisionService` (short-circuit, no judge call). Files: `src/adapters/policy/policy_engine.py`, `src/application/guardrail_service.py`. DoD: T4.3 green; POLICY-6,7 + LLM-PROXY-5 covered.

## Slice 5 — CLI + REST Surface (CLI-1..6, AUDIT-5; 7 reqs / 11 scenarios)

- [ ] **T5.1** RED: click CliRunner tests: `promptwall --help` exit 0 lists serve/rules/keys/audit/self-test; `ozy --help` command-not-found; keys create → `promptwall_*` plaintext once + hash-only stored; keys list/revoke; rules list/reload; audit verify flags tampered; self-test exit 0 / non-zero names failing check. Files: `tests/test_cli_guardrail.py`. DoD: fail before implementation.
- [ ] **T5.2** Rename console script `ozy`→`promptwall` in `pyproject.toml`; rewrite `cli/commands/serve.py` (uvicorn proxy), `keys.py` (scopes + rate limits), `self_test.py` (signing roundtrip, policy load, config validity, health); create `cli/commands/rules.py` (list|reload). Files: above + `cli/ozy.py`. DoD: T5.1 green; CLI-1..6 covered.
- [ ] **T5.3** RED: `GET /v1/audit` tests: paginated entries with audit-scope key; 403 without audit scope. Files: `tests/test_audit_read.py`. DoD: fail before implementation.
- [ ] **T5.4** Add `GET /v1/audit` paginated endpoint + audit-scope enforcement in `src/core/api.py` (KeyStore scopes: chat/audit/feedback). Files: `src/core/api.py`. DoD: T5.3 green; AUDIT-5 covered.

## Slice 6a — Signed Audit (AUDIT-1..4, LLM-PROXY-8; 5 reqs / 8 scenarios)

- [ ] **T6.1** RED: signed audit tests: Ed25519 sign/verify roundtrip over canonical JSON (EvidenceSigner); tampered entry fails verify; entry carries prompt_hash but NOT prompt text (privacy); 50MB rotation keeps 5 backups. Files: `tests/test_signed_audit.py`. DoD: fail before implementation.
- [ ] **T6.2** Create `src/adapters/audit/signed_audit.py`: EvidenceSigner over canonical decision payload (decision + metadata + prompt_hash) + AuditLogger JSONL append (50MB×5 rotation, reused from `src/auth/`). Files: file above. DoD: T6.1 green; AUDIT-1..4 covered.
- [ ] **T6.3** Wire signed emission into `GuardrailDecisionService` — every decision (blocked/forwarded/error) appends signed entry. Files: `src/application/guardrail_service.py`. DoD: LLM-PROXY-8 covered; proxy flow writes verifiable entries.

## Slice 6b — Feedback Loop + Alerts (FEEDBACK-1..5; 5 reqs / 8 scenarios)

- [ ] **T6.4** RED: feedback tests: valid report → 202 stored; unknown decision_id → 404 machine-readable; invalid type → 422; no valid key → 401; listed reports show timestamps, rules untouched; FP report for rule r-pii-01 usable after documented reload. Files: `tests/test_feedback.py`. DoD: fail before implementation.
- [ ] **T6.5** Add `POST /v1/feedback` endpoint (KeyStore feedback scope) + `FeedbackReport` storage (PromptEvent/Alert/FeedbackReport in `src/storage/models.py`) + list surface. Files: `src/core/api.py`, `src/storage/models.py`. DoD: T6.4 green; FEEDBACK-1..5 covered.
- [ ] **T6.6** RED: alert tests: blocked prompt creates Alert row; `dispatch_hook("prompt_blocked"|"alert")` fires; Telegram notifier invoked (mocked client). Files: `tests/test_alerts.py`. DoD: fail before implementation.
- [ ] **T6.7** Alerts wiring: `AlertRaised` event + `dispatch_hook` on block + `src/notifications/telegram` notifier (python-telegram-bot). Files: `src/domain/events.py`, `src/application/guardrail_service.py`, `src/notifications/`. DoD: T6.6 green.

## Dependencies

- Hard order: Slice 1 → Slice 2 → {Slice 3 ‖ Slice 4} → Slice 5 → Slice 6a → Slice 6b.
- Slices 3 and 4 are independent after Slice 2 (both test with default/allow-all policy; design confirms neither blocks the other) — parallelizable ONLY in isolated worktrees with orchestrator approval; same-branch runs stay sequential.
- Within slices: RED task before every GREEN task (strict TDD); tests ship in the same commit as the behavior (work-unit-commits).
- PR merge order must follow slice order (stacked-to-main); every PR leaves `pytest` + `ruff` green.

## Risks

| Risk | Mitigation |
|------|-----------|
| 1. Deletion cascade breaks surviving modules | Tag `v9-recon-last` pre-slice-1; `pytest --co` after EVERY rm-batch; revert boundary = single git revert (pure removal) |
| 2. Slice 6 scope creep (10 reqs) exceeds review budget | Pre-split into 6a/6b PRs (~350/~300 lines each), each self-contained with own tests + revert |
| 3. Judge LLM flakiness (malformed verdict / timeout / cost) | Strict schema parse + retries + fail-closed (judge_unavailable ≠ policy_block); policy rules short-circuit judge; buffer-then-judge bounds latency; MockTransport tests avoid live calls |
