# Judge LLM Specification

## Purpose

OpenAI-compatible judge adapter that evaluates prompts for injection, jailbreak, and PII exfiltration and returns a structured verdict. Fail-closed on any error, timeout, or malformed output.

## Requirements

### Requirement: JUDGE-1 — OpenAI-compatible client

The judge MUST call the configured `base_url` using the OpenAI chat completions protocol with model and API key from config/env (no bundled key), enabling Gemini/OpenAI/Ollama interchangeably.

#### Scenario: Configurable base_url

- GIVEN config pointing base_url at a mock OpenAI-compatible server
- WHEN a prompt is evaluated
- THEN the judge POSTs to `<base_url>/chat/completions` with the configured model

#### Scenario: Missing judge config

- GIVEN no judge base_url or model configured
- WHEN the proxy starts
- THEN configuration validation fails loudly (fail fast)

### Requirement: JUDGE-2 — Structured verdict

The judge MUST parse a structured JSON verdict (`safe`|`blocked`, `reason`, `confidence`) and MUST treat malformed output as an evaluation failure.

#### Scenario: Valid verdict

- GIVEN a judge response `{"verdict": "blocked", "reason": "jailbreak", "confidence": 0.9}`
- WHEN it is parsed
- THEN the decision is blocked with that reason

#### Scenario: Malformed verdict

- GIVEN judge output that is not valid JSON or misses required fields
- WHEN it is parsed
- THEN the evaluation fails and fail-closed applies (`judge_unavailable`)

### Requirement: JUDGE-3 — Timeouts and retries

The judge MUST apply configurable timeouts and retries for transient failures before giving up.

#### Scenario: Retry then success

- GIVEN two transient errors followed by a valid verdict
- WHEN the judge runs with retries=2
- THEN the valid verdict is used and the request succeeds

#### Scenario: Persistent failure

- GIVEN failures exceeding the retry budget
- WHEN the judge runs
- THEN the evaluation fails and fail-closed applies

### Requirement: JUDGE-4 — Fail-closed semantics

The judge MUST return a blocking verdict (reason `judge_unavailable`) on any error, timeout, or malformed output; it MUST NOT allow on uncertainty.

#### Scenario: Error on evaluation

- GIVEN any judge exception
- WHEN evaluating
- THEN the result is a block with `judge_unavailable`

### Requirement: JUDGE-5 — Verdict fields surfaced

The verdict's reason and confidence MUST be machine-readable and MUST be included in the audit entry and in the 403 response details (reason code).

#### Scenario: Reason code surfaced

- GIVEN a blocked verdict with reason `jailbreak`
- WHEN the proxy responds
- THEN the 403 body carries `jailbreak` and the audit entry records the confidence
