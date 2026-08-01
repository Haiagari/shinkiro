```yaml
schema: gentle-ai.verify-result/v1
evidence_revision: sha256:8e6ef73a743fff4eebceebb26bc32854649ca59e5b95fd61b3bdefbd98057263
verdict: fail
blockers: 0
critical_findings: 1
requirements: 3/3
scenarios: 7/7
test_command: venv/bin/python3 -m pytest -q
test_exit_code: 0
test_output_hash: sha256:cb5874045429e8f5c29397bd36ed78c7c1303cb2999b1126e734e7ada80bca3b
build_command: venv/bin/python3 -m pytest --co -q
build_exit_code: 0
build_output_hash: sha256:4d220babead60c855fc46a89fdde53358ad3b5af0a89268fb717cfca578ed906
```

## Verification Report

**Change**: guardrail-pivot
**Slice**: 2 — Proxy Skeleton: KeyStore auth + per-key rate limit + audit shape (LLM-PROXY-1,2,3)
**Version**: llm-proxy spec (3 req / 7 scenarios counted from on-disk spec; orchestrator prompt stated 6 — drift flagged, see WARNING-3)
**Mode**: Strict TDD
**Base**: `main@d9e12d5` — branch `sdd/guardrail-pivot/slice-2`, 6 commits (0d89843, 8258003, 9c40c6e, 124def8, 92544b0, d11b640); working tree clean; diff vs main: 12 files, +775 / −34

### Completeness
| Metric | Value |
|--------|-------|
| Tasks total (slice 2) | 4 (T2.1–T2.4) |
| Tasks complete | 4 |
| Tasks incomplete | 0 |
| T2.1 RED tests on disk | `tests/test_proxy_skeleton.py` (7 tests) |
| T2.2 RED tests on disk | `tests/domain/test_reason_codes.py` (7 tests) |
| T2.4 RED tests on disk | `tests/application/test_guardrail_service.py` (7 tests) |
| T2.3 gate | T2.1 test file green after api.py rewrite (DoD met) |

### Build & Tests Execution
**Build (collection gate)**: ✅ Passed — `venv/bin/python3 -m pytest --co -q` → `38 tests collected in 1.02s`, exit 0 (hash `4d220bab…`)

**Tests**: ✅ 38 passed / 0 failed / 0 errors / 0 skipped (exit 0, hash `cb587404…`)
```text
38 passed, 17 warnings in 1.15s
```
Warnings are `datetime.utcnow()` DeprecationWarnings (pre-existing kept code) — non-blocking.

**Lint**: ✅ `venv/bin/ruff check src tests` → `All checks passed!`, exit 0

**Regression**: ✅ v10 baseline intact — 38 = 17 baseline (pre-slice-2 files untouched by the diff; only 3 new test files added) + 21 new.

**Independent behavioral checks** (not part of the apply suite, run via throwaway script):
- Per-key isolation: key k1 exhausts (200, 200, 429) while k2 still returns 200.
- 422 for missing `messages` field → `{"error": {"code": "validation_error"}}`.
- Non-Bearer scheme (Basic) → 401 `unauthenticated`.
- Route-level block path: blocking judge → 403 `judge_block` + `decision_id` present; audit entry written (`outcome=blocked`, `reason_code=judge_block`).
- Audit: forwarded decisions recorded with `prompt_hash` (sha256:), never prompt text; 401/403-scope/429 rejections NOT audited (see WARNING-2).

### Spec Compliance Matrix
| Requirement | Scenario | Test / Evidence | Result |
|-------------|----------|-----------------|--------|
| LLM-PROXY-1 — OpenAI-compatible endpoint | Valid chat request | `test_within_limit_pass` (tests/test_proxy_skeleton.py:144): 200, `body["object"] == "chat.completion"`, `choices[0].message.role == "assistant"`, content non-empty; request authenticated + evaluated. "Forwarded upstream" clause satisfied by stub (see WARNING-1, deferred to slice 3 per tasks.md). | ✅ COMPLIANT (slice-2 scope) |
| LLM-PROXY-1 | Malformed body | `test_malformed_body_returns_422` (line 64): 422 + `error.code == "validation_error"`; route exits at pydantic parse, no decision/upstream (custom handler src/core/api.py:121-129). | ✅ COMPLIANT |
| LLM-PROXY-2 — KeyStore auth | Valid key | `test_within_limit_pass` proceeds past auth (200); `KeyStore.verify_key` (src/auth/key_store.py:71) matches SHA-256 hash + enabled flag. `_MASTER_KEYS` absent from api.py (grep: only docstring mention "is gone"). | ✅ COMPLIANT |
| LLM-PROXY-2 | Missing, invalid, or disabled key | `test_missing_key_returns_401` (line 77), `test_invalid_key_returns_401` (line 86), `test_disabled_key_returns_401` (line 97): all 401 + `unauthenticated`; verified `verify_key` returns None for unknown hash and disabled flag; independent check: Basic scheme → 401. No evaluation/upstream (auth precedes decision). | ✅ COMPLIANT |
| LLM-PROXY-2 | Insufficient scope | `test_insufficient_scope_returns_403` (line 108): 403 + `error.code == "insufficient_scope"` (src/core/api.py:147-148). | ✅ COMPLIANT |
| LLM-PROXY-3 — Per-key rate limit | Limit exceeded | `test_rate_limit_returns_429_with_retry_after` (line 119): 3rd request 429 + `rate_limit_exceeded` + `Retry-After` header present, `>= 1` (src/core/api.py:149-155). | ✅ COMPLIANT |
| LLM-PROXY-3 | Within limit | `test_within_limit_pass` (200); independent check: k2 unaffected while k1 exhausted (per-key isolation by key name, src/core/api.py:62). | ✅ COMPLIANT |

**Compliance summary**: 7/7 scenarios compliant (0 UNTESTED, 0 FAILING). Requirements 3/3 PASS.

### Correctness (Static + Runtime Evidence)
| Requirement | Status | Notes |
|------------|--------|-------|
| 401 vs 403 vs 422 semantics | ✅ | 422 parse (validation_error) → 401 auth (unauthenticated) → 403 scope (insufficient_scope) → 429 rate (rate_limit_exceeded); matches design.md data flow. |
| 429 + Retry-After, per-key | ✅ | Header present with ceil'd seconds; bucket keyed by `key_data["name"]`; verified isolation independently. |
| Within-limit pass-through | ✅ | 200 OpenAI-shaped `chat.completion` stub; real upstream in slice 3 (stub marked). |
| Audit JSONL every decision outcome | ✅ | `_write_audit` (src/application/guardrail_service.py:112) appends for forwarded / judge_block / judge_unavailable; service tests assert 1 entry per outcome; proxy test asserts 2 entries (2 forwards) and 429 not audited. |
| Fail-closed | ✅ | `parse_verdict` (guardrail_service.py:45): None/empty/bad JSON → blocked `judge_unavailable`; route maps blocked → 403 with decision_id; config `guardrail.fail_open: false` (config/config.yaml:46). |

### Coherence (Design)
| Decision | Followed? | Notes |
|----------|-----------|-------|
| Route flow parse→auth→scope→ratelimit→decide (AD/design data flow) | ✅ Yes | src/core/api.py:140-170 exact order; `_MASTER_KEYS` gone (LLM-PROXY-2) |
| ReasonCode 12-code enum | ✅ Yes | src/domain/reason_codes.py matches design list exactly (test asserts 12 values) |
| Frozen kw_only guardrail models | ✅ Yes | IncomingPrompt/UpstreamResponse/Verdict/PolicyDecision `frozen=True, kw_only=True`; Finding.asset_id gone (no Asset refs in src/domain, src/application, src/core/contracts.py — grep 0 matches) |
| IJudgeLLM → Verdict; IAttackerLLM dropped | ✅ Yes | src/core/contracts.py:78-83; `IAttackerLLM` 0 matches repo-wide; ITargetAPI kept intentionally |
| PromptEvent storage model | ✅ Yes | src/storage/models.py:290-300 |
| Audit JSONL unsigned shape | ✅ Yes | version/timestamp/decision_id/key_name/outcome/reason_code/reason/prompt_hash; signing in slice 6a per design |
| GuardrailDecisionService shared decision pipeline | ✅ Yes | policy(allow-all placeholder)→judge→Decision+audit; policy real engine in slice 4 |
| Config guardrail section | ✅ Yes | config.py:149-157 (`guardrail_audit_path`, `guardrail_fail_open` default False); config/config.yaml:45-48 |

### TDD Compliance
| Check | Result | Details |
|-------|--------|---------|
| TDD Evidence reported | ❌ | Apply-progress (#2598, topic sdd/guardrail-pivot/apply-progress, 3 revisions) documents per-commit RED/GREEN in prose but **no formal TDD Cycle Evidence table** (RED/GREEN/TRIANGULATE/SAFETY NET/REFACTOR) — CRITICAL-1, protocol-format only |
| All tasks have tests | ✅ | 4/4 tasks have test files (T2.3 shares T2.1's file per tasks.md) |
| RED confirmed (tests exist) | ✅ | 3/3 test files verified on disk; git history shows RED commits before GREEN for every task (0d89843→d11b640, 8258003→9c40c6e, 124def8→92544b0) |
| GREEN confirmed (tests pass) | ✅ | 21/21 new tests + 17/17 baseline pass on execution (38 total) |
| Triangulation adequate | ✅ | LLM-PROXY-2: 3 scenarios → 4 tests (3 distinct 401 cases + scope); LLM-PROXY-1/3: distinct value assertions (status, code, body shape, audit contents) |
| Safety Net for modified files | ✅ | Baseline 17 green alongside 21 new; only new files authored in slice 2 |
| Assertion quality | ✅ | No tautologies, no ghost loops, no smoke-only tests; all assertions exercise production code (audit in Step 5f) |

**TDD Compliance**: 6/7 checks passed (missing table = CRITICAL-1, protocol-format only; substantive evidence independently confirmed)

### Test Layer Distribution
| Layer | Tests | Files | Tools |
|-------|-------|-------|-------|
| Unit | 14 | 2 (test_reason_codes.py, test_guardrail_service.py) | pytest |
| Integration (httpx ASGITransport) | 7 | 1 (test_proxy_skeleton.py) | pytest + httpx |
| E2E | 0 | 0 | not applicable (slice-2 scope) |
| **Total** | **21** | **3** | |

### Changed File Coverage
Coverage analysis skipped — no coverage tool detected (project forbids pytest-cov per V9-3). Informational, not a failure.

### Issues Found
**CRITICAL**
1. **Apply-progress lacks the formal TDD Cycle Evidence table** (strict-tdd-verify.md Step 5a). Observation #2598 (topic `sdd/guardrail-pivot/apply-progress`) documents per-commit RED/GREEN in prose but not the RED/GREEN/TRIANGULATE/SAFETY NET/REFACTOR table the protocol requires — same gap as Slice 1's CRITICAL-1. Independent verification confirms all substantive evidence exists and passes: commit history shows RED-before-GREEN for every task, all test files on disk, 38/38 green, real value assertions. Remediation = amend the apply report with the table; zero code impact.

**WARNING**
1. **LLM-PROXY-1 "Valid chat request" scenario's "forwarded upstream" clause is stubbed** — `_stub_completion` (src/core/api.py:88-106) returns a canned OpenAI-shaped response; no real upstream call until slice 3 (tasks.md T3.3/T3.4, LLM-PROXY-4). The OpenAI-shaped response contract is met and the stub is explicitly marked; LLM-PROXY-1 is only fully complete after slice 3.
2. **Transport-level rejections are not audited** — 401, 403 `insufficient_scope` and 429 exit before the decision service, so no audit entry (test_proxy_skeleton.py:138-140 codifies this). Compliant with T2.4's DoD ("audit entry for every outcome" of the decision service), but LLM-PROXY-8 (slice 6a: "every proxy decision regardless of outcome (allowed, blocked, or failed)") must decide whether transport rejections count as decisions.
3. **Scenario-count drift in planning artifacts** — orchestrator prompt and tasks.md header state "3 reqs / 6 scenarios"; the authoritative on-disk spec has **7 scenarios** (LLM-PROXY-1: 2, LLM-PROXY-2: 3, LLM-PROXY-3: 2). All 7 are covered and pass; same drift class as Slice 1's WARNING-5.
4. **Kept `JudgeAdapter` violates the redefined `IJudgeLLM` contract** — src/adapters/llms/judge_adapter.py:52 overrides `evaluate_prompt(self, payload: AttackPayload) -> EvaluationResult` instead of the new `(prompt: IncomingPrompt) -> Verdict` (src/core/contracts.py:82). Untouched by slice 2, currently unused (no importer), baseline tests green — but the ABC signature is silently mismatched; update or delete when slice 3 lands the real judge.

**SUGGESTION**
1. Per-key rate-limit isolation is verified behaviorally (independent check: k2 unaffected while k1 exhausted) but not asserted in the suite — add an explicit two-key test to test_proxy_skeleton.py.
2. `PromptForwarded`/`DecisionRecorded` (src/domain/events.py:52-64) are defined but never emitted — the service writes JSONL directly. Intentional for slice 2; wire event emission in slice 6 (alerts/hooks).
3. `GuardrailDecisionService` depends on `AIProvider.generate_content` (sync) rather than `IJudgeLLM.evaluate_prompt` (async, per contracts.py:82). Matches the sync skeleton, but slice 3 must reconcile the service dependency with the contract abstraction (design.md itself is internally inconsistent: data flow says "evaluate_prompt ... sync" while the ABC is async).
4. Rate limiter is in-memory per-process (src/core/api.py:49-69, marked with `ponytail:` comment) — a shared store (Redis) is needed for multi-process deployments; documented in code.

### Verdict
FAIL (not archive-ready) — single CRITICAL is protocol-format only (TDD Cycle Evidence table missing from apply report), identical in kind to Slice 1's CRITICAL-1. All 3 requirements / 7 scenarios COMPLIANT (0 UNTESTED, 0 FAILING), all runtime gates green (38 passed, 0 errors; ruff clean; 17-test v10 baseline intact), contract drift clean (no Asset refs, IJudgeLLM→Verdict, `_MASTER_KEYS` gone). After the apply report is amended with the TDD Cycle Evidence table (and WARNING-4 reconciled in slice 3), the slice is PR-ready.
