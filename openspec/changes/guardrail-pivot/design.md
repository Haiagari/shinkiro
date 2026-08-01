# Design: Guardrail Pivot (PromptWall)

## Technical Approach

Turn the broken v9 repo (20 pytest collection errors from the `Asset` import chain, #2590) into an OpenAI-compatible AI guardrail. Strategy: delete ~17k LOC of v9 recon (fixing the breakage by removal), extract the AIProvider pattern from `src/intelligence/ai_analyzer.py:16-96`, then build six TDD slices on the surviving scaffold: FastAPI proxy (`POST /v1/chat/completions`) with KeyStore auth + per-key rate limit + deterministic policy engine + synchronous OpenAI-compatible judge LLM, fail-closed, buffer-then-judge streaming, Ed25519-signed JSONL audit, and a feedback loop. `AIOrchestrator` remains as the in-app path and shares the same decision service with the proxy. Implements all 42 requirements / 69 scenarios across `llm-proxy`, `judge-llm`, `policy-engine`, `guardrail-audit`, `feedback-loop`, `guardrail-cli`, `v9-recon-removal`.

## Architecture Decisions

| # | Decision | Choice | Alternatives | Rationale |
|---|----------|--------|--------------|----------|
| AD-1 | Layout | Hexagonal per existing `src/` tree (domain / application / core / adapters) | Flat modules | Matches AGENTS.md + openspec/config.yaml; domain pure, adapters own I/O |
| AD-2 | Judge transport | Raw `httpx`, OpenAI-compatible protocol | `openai` SDK | httpx already in pyproject; exact `base_url` control (Gemini/OpenAI/Ollama); verdict = one `json()`; SDK adds churn for a single POST |
| AD-3 | Judge sync | In-request synchronous | Async event bus | Proposal default; buffer-then-judge bounds latency; event bus stays in-memory sync |
| AD-4 | Policy storage | YAML files under `config/policies/` | DB tables | Operator-editable, atomic reload (POLICY-6); DB later (POLICY-2 "DB later") |
| AD-5 | Key storage | KeyStore JSON (kept) | DB table | Works today; no migration; CLI-4 returns plaintext once |
| AD-6 | Audit store | Signed JSONL via AuditLogger (50MB × 5) | DB rows | Existing + rotation tested; privacy default excludes prompt content (AUDIT-2) |
| AD-7 | Audit sign scope | Decision + metadata + `prompt_hash` only | Full prompt text | Privacy default from proposal/spec |
| AD-8 | Fail-open | `guardrail.fail_open` defaults `false` | `true` | Fail-closed (LLM-PROXY-6, JUDGE-4); explicit `true` logs warning |
| AD-9 | Reload semantics | Explicit `promptwall rules reload` + SIGHUP, atomic swap | Auto file-watch | Deterministic + testable; invalid YAML keeps previous set |
| AD-10 | Streaming | Buffer-then-judge (buffer until verdict) | Stream-through | Block before first chunk (LLM-PROXY-7); documented latency tradeoff |
| AD-11 | Entry point | `ozy` → `promptwall` | Keep `ozy` | CLI-1 |
| AD-12 | Domain names | `AttackPayload`→`IncomingPrompt`, `TargetResponse`→`UpstreamResponse`; add `Verdict`, `PolicyDecision`, `Alert`, `AuditEntry`, `FeedbackReport` | Keep offensive names | Semantic correctness; only rewritten modules reference them |

## Data Flow — POST /v1/chat/completions

```
client ──POST /v1/chat/completions (Bearer key, body)
  → pydantic parse ──────────────── 422 validation_error (no upstream)
  → KeyStore.verify_key ──────────── 401 unauthenticated | 403 insufficient_scope
  → RateLimiter (per key) ────────── 429 rate_limit_exceeded + Retry-After
  → buffer body (stream=true: hold until verdict)
  → PolicyEngine.evaluate(prompt, active_set)
        block → 403 policy_block {rule_id, reason}; judge NOT invoked
  → JudgeLLM.evaluate_prompt (httpx, timeout+retries, sync)
        blocked → 403 judge_block {reason}
        error/timeout/malformed → 403 judge_unavailable  (fail-closed)
  → forward to upstream base_url (upstream key from env — NEVER client key)
        5xx/unreachable → 502 upstream_failure (generic, no internals)
  → relay response (SSE chunks in OpenAI chunk format for stream=true)
  → signed audit entry (JSONL append)
  → dispatch_hook("prompt_blocked" | "alert") + telegram (slice 6)
```

`AIOrchestrator.process_prompt` and the proxy route both call `GuardrailDecisionService.decide(prompt, key)` (application layer: policy → judge → Decision). Auth, rate limit and streaming live only in the transport (proxy) layer.

## Interfaces / Contracts

```python
# src/core/contracts.py (redefined)
class IJudgeLLM(ABC):
    @abstractmethod
    async def evaluate_prompt(self, prompt: IncomingPrompt) -> Verdict: ...

class IPolicyEngine(ABC):
    @abstractmethod
    def evaluate(self, prompt: str, policy_set: str = "default") -> PolicyDecision: ...
```

Judge verdict JSON (OpenAI chat completions response content; malformed → evaluation failure → fail-closed):

```json
{"verdict": "safe" | "blocked", "reason": "jailbreak", "confidence": 0.9}
```

```python
# src/domain/reason_codes.py — stable enumerated set (403 body carries code + reason)
class ReasonCode(str, Enum):
    POLICY_BLOCK = "policy_block"            # 403, plus rule_id
    JUDGE_BLOCK = "judge_block"              # 403, plus judge reason
    JUDGE_UNAVAILABLE = "judge_unavailable"  # 403, fail-closed
    INJECTION = "injection"                  # granular rule/judge reason
    JAILBREAK = "jailbreak"
    PII_EXFILTRATION = "pii_exfiltration"
    INSUFFICIENT_SCOPE = "insufficient_scope"  # 403
    UNAUTHENTICATED = "unauthenticated"        # 401
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"  # 429
    VALIDATION_ERROR = "validation_error"      # 422
    UPSTREAM_FAILURE = "upstream_failure"      # 502
    NOT_FOUND = "not_found"                    # 404
```

403 body (machine-readable, stable):

```json
{"error": {"code": "policy_block", "reason": "jailbreak", "rule_id": "r-jb-01",
           "decision_id": "dec_...", "message": "Request blocked by policy"}}
```

Rule schema (POLICY-3): `{id, kind: regex|keyword, pattern, action: block|allow, reason_code}` — declared order, first match wins; an allow rule preceding a matching block rule overrides it (POLICY-4). Policy sets named; active set from config, MAY per key scope (v1: config-level only).

Reload: `PolicyStore.reload()` parses YAML into a new immutable `PolicySet`, atomically swaps the reference; invalid YAML → previous set stays active + error reported.

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `src/adapters/llms/provider_base.py` | Create | AIProvider ABC + Mock/Gemini/OpenAI/Ollama registry extracted from `ai_analyzer.py` (V9-4) |
| `src/adapters/llms/openai_compatible_judge.py` | Create | httpx judge: POST `{base_url}/chat/completions`, structured verdict parse, timeouts/retries, fail-closed |
| `src/adapters/policy/policy_engine.py`, `src/adapters/policy/yaml_policy_loader.py` | Create | Deterministic rules, precedence, policy sets, atomic reload |
| `src/application/guardrail_service.py` | Create | `GuardrailDecisionService`: policy → judge → Decision, audit emission |
| `src/adapters/audit/signed_audit.py` | Create | EvidenceSigner over canonical decision payload + AuditLogger append (50MB×5) |
| `src/domain/reason_codes.py` | Create | ReasonCode enum above |
| `src/domain/models.py`, `src/domain/events.py` | Modify | Guardrail models/events; add `PromptForwarded`, `DecisionRecorded`, `AlertRaised` |
| `src/core/contracts.py` | Modify | IJudgeLLM → `Verdict`; add IPolicyEngine; drop `IAttackerLLM` |
| `src/core/api.py` | Rewrite | Proxy app: `/v1/chat/completions`, `/v1/audit`, `/v1/feedback`, `/health`; `_MASTER_KEYS` (lines 33-38) removed |
| `src/core/config.py` | Modify | `guardrail.judge/policy/upstream/audit` keys; `fail_open` default false |
| `src/application/orchestrator.py` | Modify | Delegates decision to `GuardrailDecisionService` |
| `src/storage/models.py` | Rewrite | Guardrail tables: `PromptEvent`, `Alert`, `FeedbackReport` (PolicyRule/ApiKey stay file-based in v1) |
| `src/storage/database.py` | Modify | Import guardrail models only |
| `cli/ozy.py` | Modify | Mode loader removed; entry point `promptwall` |
| `cli/commands/serve.py`, `keys.py`, `self_test.py` | Rewrite | Proxy serve; chat/audit/feedback scopes; guardrail self-test |
| `cli/commands/rules.py` | Create | `promptwall rules list|reload` |
| `pyproject.toml` | Modify | Unified deps (httpx, cryptography, fastapi, click, rich, python-telegram-bot, pydantic, sqlalchemy); script `ozy`→`promptwall`; pytest strict asyncio documented |
| `requirements.txt` | Delete | Superseded by pyproject (V9-6) |
| `config/config.yaml`, `config/policies/default.yaml` | Modify/Create | Guardrail section + starter rules |
| v9 tree: `src/{discovery,intelligence,modes,opsec,scheduler,scope,export,reporting,validation,workflow,events,scanners}`, `src/core/{providers,runtime_*}`, `src/adapters/{storage/sqlite_repository,policy/ozy_policy_adapter,events/webhook_adapter,registry}`, `src/gate/`, `src/agent/config_writer.py`, `src/security/target_validator.py`, `cli/commands/{analyze,audit,...}`, `tests/*v9*` | Delete | V9-1/2/5 |

Config (startup fails loudly if `judge.base_url`/`model` missing — JUDGE-1):

```yaml
guardrail:
  fail_open: false                          # MUST default closed
  policy:  {path: config/policies, active_set: default}
  judge:   {base_url: "", model: "", api_key_env: PROMPTWALL_JUDGE_API_KEY,
            timeout_seconds: 10, retries: 2}
  upstream:{base_url: "https://api.openai.com/v1", api_key_env: PROMPTWALL_UPSTREAM_API_KEY}
  audit:   {path: runs/audit_guardrail.jsonl}
```

## Testing Strategy

| Slice | Reqs | Test approach (all: pytest strict asyncio + ruff gate) |
|-------|------|-----------|
| 1 — v9 deletion + AIProvider extraction | V9-1..6 | Path-absence + `grep` no-`Asset`-import; `provider_base` importable + Mock instantiable; full suite green (0 collection errors); clean-venv install; every async test carries `@pytest.mark.asyncio` |
| 2 — proxy skeleton (KeyStore auth + rate limit + audit shape, MockProvider judge) | LLM-PROXY-1,2,3 | httpx AsyncClient against app with temp KeyStore: 422 malformed body, 401 missing/invalid/disabled, 403 insufficient_scope, 429 + Retry-After, within-limit pass; audit JSONL entry written |
| 3 — real judge + passthrough + streaming | JUDGE-1..5, LLM-PROXY-4,6,7 | httpx MockTransport: POSTs to configured `base_url` with model; valid/malformed verdict parse (malformed → fail-closed); retry-then-success; persistent failure → 403 judge_unavailable; upstream 502 generic; SSE relay + 403 before first chunk |
| 4 — policy engine | POLICY-1..7, LLM-PROXY-5 | Pure unit: declared order, first-match-wins, allow-overrides-block, sets; YAML valid/invalid load (startup fails on invalid); atomic reload swap; judge-spy asserts ZERO judge calls on rule block; 403 policy_block + rule_id |
| 5 — CLI + REST surface | CLI-1..6, AUDIT-5 | click CliRunner: `promptwall --help` lists commands, `ozy` gone; keys create/list/revoke (plaintext once, hash only stored); rules list/reload; audit verify (tampered entry flagged); self-test exit 0/non-zero; GET /v1/audit paginated + 403 without audit scope |
| 6 — signed audit + alerts + feedback | AUDIT-1..4, FEEDBACK-1..5, LLM-PROXY-8 | Ed25519 sign/verify roundtrip; tampered entry fails; 50MB rotation; feedback 202 / 404 unknown decision_id / 422 bad type / 401 no key; Alert row + `dispatch_hook` + mocked Telegram |

Gates every slice: `pytest` (strict asyncio — no `asyncio_mode=auto`) + `ruff`; no pytest-cov (V9-3). Slice order is dependency-safe: slices 3-4 test with default/allow-all policy so neither blocks the other; slice 6 completes audit signing (slices 2-5 carry the JSONL shape + rotation).

## Threat Matrix

| Boundary | Applicability | Design response |
|----------|---------------|-----------------|
| Documentation-like paths | N/A — no executable markdown/README exec | — |
| Git repository selection | N/A — no git invocation in guardrail code | — |
| Commit state | N/A — no VCS automation | — |
| Push state | N/A — no VCS automation | — |
| PR commands | N/A — no VCS/PR automation | — |

No shell/subprocess/VCS boundary. Closest edges handled by design: HTTP body = untrusted input (pydantic validation → 422); upstream/judge `base_url` comes from config, never user input; SIGHUP reload is signal handling with atomic swap. No RED tests required beyond the spec scenarios.

## Migration / Rollout

- Tag `v9-recon-last` on the pre-pivot commit before slice 1; deletion slice revertible via `git revert` (pure removal, no data migration).
- No DB schema migration: `PromptEvent`/`Alert`/`FeedbackReport` created fresh by `init_db`; audit is JSONL; keys are JSON.
- Config ships with `fail_open: false`; missing judge config fails startup (and `promptwall self-test` names it).
- Feature slices 2-6 are chained PRs, each self-contained with its own revert (review budget 400 lines / slice).

## Open Questions

- [ ] PolicyRule + ApiKey DB-backed in v2 — **default locked**: v1 file-based (YAML/JSON).
- [ ] Per-key policy-set selection (POLICY-5 MAY) — **default**: config-level active set only in v1.
- [ ] Alert delivery hardening (retries, fan-out beyond Telegram) — **default**: Telegram only in v1.
- [ ] Per-tenant upstream credentials — **default**: single upstream config in v1.
