# Proposal: Guardrail Pivot — PromptWall becomes an AI Guardrail

## Intent

Turn PromptWall into a real AI guardrail for internal security teams protecting their own LLM integrations. The repo is BROKEN (20 pytest collection errors from the `Asset` import chain, #2590) and the v9 recon stack (~17k LOC) is dead weight the 10.0.0 CHANGELOG already claims removed. We resolve the breakage by DELETION, not by fixing imports. v1 product: OpenAI-compatible proxy (`POST /v1/chat/completions`) + keep in-app `AIOrchestrator`; detection scope = prompt injection, jailbreaks, PII/data exfiltration via deterministic rules + judge LLM; block + fail-closed; buffer-then-judge streaming; feedback loop for rule adjustment. CLI + REST API only, NO web dashboard. This supersedes the `ai-red-teaming` change (offensive attacker-judge loop); only its defensive Phase-4 concept and model/event shapes survive in the v10 scaffold.

## Scope

### In Scope
- **DELETE v9 recon** (~17k LOC): `src/discovery/`, `src/modes/`, `src/intelligence/` (AFTER extraction), `src/core/providers/`, `src/opsec/`, `src/scheduler/`, `src/scope/`, `src/export/`, `src/reporting/`, `src/validation/`, `src/workflow/`, `src/events/` (v9 bus), `src/scanners/`, `src/storage/db_queries.py`+`queries.py`+`diff.py`, recon runtime modules in `src/core/`, `src/agent/config_writer.py`, `src/security/target_validator.py`, dead `cli/commands/` (analyze, audit, compliance_check, diff, doctor, exploits, export, flow, init, inventory, paths, schedule, scope, screenshot, secrets, verify, watch).
- **EXTRACT before delete**: AIProvider pattern from `src/intelligence/ai_analyzer.py` (ABC + Mock/Gemini/OpenAI/Ollama registry) → `src/adapters/llms/provider_base.py` as judge base.
- **KEEP**: `src/utils/crypto.py` (Ed25519 EvidenceSigner), `src/auth/` (KeyStore, AuditLogger JSONL, rate_limit, dependencies), `src/storage/database.py` (SQLAlchemy 2.0 engine + WAL), `src/core/config.py` + `src/core/bootstrap.py`, `src/plugins/`, `src/notifications/`, CLI shell (`cli/ozy.py` + `cli/shared.py` minus mode loader), FastAPI shell (`src/core/api.py`).
- **BUILD**: proxy endpoint, real judge adapter, policy engine, signed audit, feedback loop (below).

### First-Slice Boundaries (slice 1)
- Only deletion + AIProvider extraction + green test baseline. No new product behavior.
- Delete all tests referencing v9 (intelligence/discovery/modes/opsec/reporting/export/scope/validation/storage/core-recon/integration/notifications v9, test_contracts, test_api_integration, test_observability, test_runtime_end_to_end, test_src_architecture, test_v57_features, test_hardening_guardrails).
- Fix `src/adapters/storage/sqlite_repository.py`, `src/application/ports/asset_repository.py` + `tool_provider.py`, `webhook_adapter.py`, `ozy_policy_adapter.py`, `gate/manager.py` leaks by removal or re-point to v10.

### Out of Scope (v1 non-goals)
- Multi-tenant per client (scopes per key exist in KeyStore; per-client tenancy later).
- Web dashboard.
- Harmful-content / policy custom rules.
- v9 recon features of any kind.
- Attack/offensive red-team features from `ai-red-teaming`.

## Capabilities

> Contract for sdd-spec. No `openspec/specs/` exists yet — all are NEW capabilities.

- `llm-proxy`: OpenAI-compatible `POST /v1/chat/completions` — KeyStore auth (Bearer API key, hashed, scopes, per-key rate limit), request/response passthrough to upstream, buffer-then-judge SSE streaming, 403 + machine-readable reason code on block, fail-closed on judge error.
- `judge-llm`: OpenAI-compatible judge adapter — configurable `base_url` (Gemini/OpenAI/Ollama all expose it), structured JSON verdict (safe/blocked + reason + confidence), timeouts/retries, fail-closed.
- `policy-engine`: deterministic rules (injection patterns, jailbreak keywords, PII/exfiltration regex) evaluated BEFORE the judge LLM; precedence + policy sets; feedback-loop adjusts rule weights/patterns.
- `guardrail-audit`: every prompt/decision signed with Ed25519 EvidenceSigner (canonical JSON), JSONL via AuditLogger (50MB rotation), audit read endpoints.
- `feedback-loop`: endpoint to report false positives/negatives per decision; feeds rule tuning (v1: store + expose, no auto-retrain).
- `guardrail-cli`: `promptwall serve|rules|keys|audit|self-test` on the kept Click+Rich shell.

## Approach

Six TDD slices, each green before the next (strict TDD, pytest, strict mode):
1. **Massive v9 deletion + AIProvider extraction** → fixes the broken suite by removal; baseline green.
2. **Proxy endpoint** (`/v1/chat/completions`): KeyStore auth + rate-limit + audit + fail-closed skeleton with MockProvider judge.
3. **Real judge LLM**: OpenAI-compatible adapter, structured verdict parsing, fail-closed on error/timeout.
4. **Policy engine**: deterministic rules before judge; rules → block decisions recorded in audit.
5. **CLI + REST surface**: `serve/rules/keys/audit` commands, `/v1/rules`, `/v1/audit`, `/health`; replace hardcoded `_MASTER_KEYS` in `src/core/api.py` with KeyStore.
6. **Signed audit + alerts + feedback loop**: Ed25519 signatures on audit entries, plugin hooks (`on_prompt_blocked`, `on_alert`) + Telegram notifications, feedback endpoint.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `src/discovery, modes, intelligence, opsec, scheduler, scope, export, reporting, validation, workflow, events, scanners, core/providers, core/runtime_*, agent/config_writer, security/target_validator` | Removed | ~17k LOC v9 recon deleted |
| `src/intelligence/ai_analyzer.py` | Extracted → Removed | AIProvider ABC+registry → `src/adapters/llms/provider_base.py` |
| `src/adapters/llms/judge_adapter.py`, `attacker_adapter.py`, `targets/api_adapter.py` | Rewritten | Stub tests replaced; attacker/targets deleted |
| `src/adapters/storage/sqlite_repository.py`, `src/application/ports/*` | Fixed/Removed | Asset-chain leaks deleted with v9 |
| `src/auth/` (KeyStore, AuditLogger, rate_limit, dependencies) | Kept → Modified | Auth for proxy + audit; master keys removed from `src/core/api.py` (33-38) |
| `src/core/api.py`, `src/core/config.py`, `src/core/bootstrap.py` | Modified | Proxy routes, judge/policy config, weak default key removed |
| `src/utils/crypto.py`, `src/plugins/`, `src/notifications/` | Kept → Extended | EvidenceSigner for audit; hooks/alerts |
| `cli/ozy.py`, `cli/shared.py`, `cli/commands/keys.py`, `serve.py`, `self_test.py` | Modified | Mode loader removed; guardrail commands |
| `src/domain/models.py`, `src/domain/events.py` | Extended | PolicyDecision, Alert, AuditEntry; PromptForwarded, DecisionRecorded, AlertRaised |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Deletion cascade breaks surviving modules | Med | Slice 1 runs the whole suite after every rm batch; keep v9 on a tag before starting |
| Judge LLM verdicts flaky (structured JSON malformed) | Med | Strict parse + retries + fail-closed; validation of verdict schema |
| Proxy streaming adds latency (buffer-then-judge) | Med | Buffer only until judge verdict; configurable; document tradeoff |
| Fail-closed blocks legitimate traffic on judge outage | Med | Explicit, tested; reason codes distinguish `judge_unavailable` from `policy_block` |
| PII exfiltration detection noisy (false positives) | Med | Deterministic rules conservative first; feedback loop tunes |
| Judge model cost/latency (LLM per prompt) | Low | Rules short-circuit most traffic; judge only on uncertain/deterministic-pass cases |
| `ai-red-teaming` artifact confusion | Low | Explicit supersede note in change doc; directory left untouched |
| Open questions (defaults): judge model (default: OpenAI-compatible, base_url configurable — no bundled key); sync judge (default: in-request synchronous, async bus later); audit signing scope (default: decisions+metadata, NOT full prompt content — privacy); policy format (default: YAML files under config/, DB later); entry point rename `ozy`→`promptwall` (default: yes in slice 5); streaming default (buffer-then-judge per PRD) | — | Resolve in spec phase; defaults above are the fallback |

## Rollback Plan

- Deletion slices (1): `git revert` the slice commit restores v9; no data migration involved (pure removal).
- Feature slices (2-6): each is a self-contained chained PR with its own revert; audit/proxy config lives in code+config files, no DB schema dependency in v1 (audit JSONL, keys JSON).
- Tag `v9-recon-last` on the pre-pivot commit before slice 1 for guaranteed restore point.
- Fail-closed default means a bad proxy deploy blocks traffic (safe failure); flip a config flag to test mode to inspect.

## Dependencies

- `openai` SDK (or raw httpx — decide in spec) for OpenAI-compatible judge; `httpx` already installed.
- Green pytest baseline restored at end of slice 1 (currently 20 collection errors).
- Dependency hygiene decision: unify `pyproject.toml` vs `requirements.txt` (google-generativeai/httpx/aiohttp/telegram installed but not in pyproject) — slice 1.
- Keep `python-telegram-bot` for alert channel (already in requirements).

## Success Criteria

- [ ] Slice 1: `pytest` collects and passes with 0 errors; v9 LOC removed from tree; AIProvider usable from `src/adapters/llms/`.
- [ ] `POST /v1/chat/completions` with valid KeyStore key forwards benign prompt to upstream and returns its response.
- [ ] Injection/jailbreak prompt → HTTP 403 with stable reason code; no upstream bytes emitted.
- [ ] Judge error/timeout → fail-closed 403 (`judge_unavailable`), documented and tested.
- [ ] PII/exfiltration pattern blocked by policy engine without judge round-trip.
- [ ] Every decision recorded in audit JSONL with verifiable Ed25519 signature; `promptwall audit` verifies signatures.
- [ ] Feedback endpoint accepts FP/FN reports and rule updates take effect without restart (or documented reload).
- [ ] Hardcoded `_MASTER_KEYS` gone; only KeyStore-issued keys accepted.
- [ ] Streaming request with blocked prompt returns 403 before first content chunk (buffer-then-judge proven by test).
