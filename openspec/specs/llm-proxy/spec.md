# LLM Proxy Specification

## Purpose

OpenAI-compatible guardrail proxy: intercepts chat completions traffic, authenticates via KeyStore, evaluates policy + judge before forwarding to a configurable upstream, and records every decision. Fail-closed by default.

## Requirements

### Requirement: LLM-PROXY-1 — OpenAI-compatible endpoint

The proxy MUST expose `POST /v1/chat/completions` accepting OpenAI Chat Completions request bodies (model, messages, stream, temperature) and MUST return OpenAI-compatible success responses.

#### Scenario: Valid chat request

- GIVEN a running proxy and a valid KeyStore key with `chat` scope
- WHEN a benign `POST /v1/chat/completions` with a chat body is sent
- THEN the request is authenticated, evaluated, and forwarded upstream
- AND an OpenAI-shaped response is returned to the client

#### Scenario: Malformed body

- GIVEN a request with invalid or missing JSON body
- WHEN it is POSTed to the endpoint
- THEN the proxy returns HTTP 422 with a machine-readable error code
- AND no upstream call is made

### Requirement: LLM-PROXY-2 — KeyStore authentication

The proxy MUST authenticate Bearer API keys via KeyStore (SHA-256 hashed, scopes, enabled flag) and MUST NOT accept hardcoded keys (`_MASTER_KEYS` removed from `src/core/api.py`).

#### Scenario: Valid key

- GIVEN a KeyStore-issued key with the required scope
- WHEN it is presented as `Authorization: Bearer <key>`
- THEN the request proceeds to evaluation

#### Scenario: Missing, invalid, or disabled key

- GIVEN no key, an unknown key, or a disabled key
- WHEN the request is sent
- THEN the proxy returns HTTP 401
- AND no evaluation or upstream call occurs

#### Scenario: Insufficient scope

- GIVEN a valid key lacking the `chat` scope
- WHEN a chat request is sent
- THEN the proxy returns HTTP 403 with reason code `insufficient_scope`

### Requirement: LLM-PROXY-3 — Per-key rate limiting

The proxy MUST enforce each key's configured per-minute rate limit and MUST return HTTP 429 with a `Retry-After` header when exceeded.

#### Scenario: Limit exceeded

- GIVEN a key whose per-minute limit is already exhausted
- WHEN another request is sent
- THEN the proxy returns HTTP 429 with `Retry-After`

#### Scenario: Within limit

- GIVEN a key below its per-minute limit
- WHEN requests are sent
- THEN they are processed normally (no 429)

### Requirement: LLM-PROXY-4 — Upstream passthrough

The proxy MUST forward allowed requests to the upstream `base_url` configured in config and MUST NOT bundle provider credentials in code.

#### Scenario: Upstream success

- GIVEN an allowed request and a healthy upstream
- WHEN the request is forwarded
- THEN the upstream response is returned with OpenAI-compatible shape

#### Scenario: Upstream failure

- GIVEN an upstream that returns 5xx or is unreachable
- WHEN forwarding
- THEN the proxy returns HTTP 502 with a generic message (no upstream internals leaked)

### Requirement: LLM-PROXY-5 — Policy block with reason code

The proxy MUST return HTTP 403 with a stable machine-readable reason code when the policy engine blocks a prompt, and MUST NOT emit any upstream bytes.

#### Scenario: Injection pattern blocked

- GIVEN a prompt matching an injection rule
- WHEN the request is sent
- THEN the proxy returns HTTP 403 with reason `policy_block` and the matching rule id
- AND no upstream call occurs

### Requirement: LLM-PROXY-6 — Fail-closed on judge error

The proxy MUST block (HTTP 403) with reason `judge_unavailable` when the judge errors or times out; it MUST NOT allow on uncertainty.

#### Scenario: Judge timeout

- GIVEN a judge that does not respond within its timeout
- WHEN a prompt requiring judge evaluation is sent
- THEN the proxy returns HTTP 403 with `judge_unavailable`
- AND no upstream bytes are emitted

### Requirement: LLM-PROXY-7 — Buffer-then-judge streaming

For `stream=true` requests the proxy MUST buffer the request until the verdict is known, MUST block before the first content chunk when blocked, and MUST forward an SSE stream when allowed.

#### Scenario: Blocked streaming request

- GIVEN a streaming request whose prompt is blocked
- WHEN it is sent
- THEN the proxy returns HTTP 403 before the first SSE data chunk

#### Scenario: Allowed streaming request

- GIVEN a streaming request that passes policy and judge
- WHEN it is sent
- THEN the proxy returns SSE chunks in OpenAI chat completion chunk format

### Requirement: LLM-PROXY-8 — Decision audit

Every proxy decision MUST produce a signed audit entry (per guardrail-audit spec) regardless of outcome (allowed, blocked, or failed).

#### Scenario: Decision recorded

- GIVEN any completed proxy decision
- WHEN it finishes
- THEN an audit entry with a valid signature exists in the JSONL log
