# 📖 OzyRecon: Use Cases & Operational Scenarios

OzyRecon v8.3.2 is a controlled reconnaissance and review engine. This document describes practical scenarios for discovery, correlation, evidence collection, and safe validation.

## Core scenarios

### 1. Controlled discovery under defensive controls

Use OzyRecon when a target needs explicit, reviewable discovery rather than opaque background scanning.

- Run the engine with the approved validation policy
- Review the normalized output and session trace
- Keep the run inside the authorized scope

### 2. Cross-asset correlation

The engine is useful when findings are spread across multiple assets and need relationship-based review.

- Correlate subdomains, services, and historical sessions
- Use the graph output to surface review priorities
- Treat the result as a triage layer, not as an exploit path

### 3. Evidence-based validation

Use the signed evidence layer when you need reproducible proof of exposure.

- Collect Ed25519-signed findings
- Preserve session context for audit
- Use the narrative analysis for remediation context

### 4. Continuous surface monitoring

Use the engine as a repeatable review loop for approved assets.

- Run scheduled hunts on allowed targets
- Compare new sessions against prior traces
- Track drift with `GET /sessions/{session_id}/trace`

### 5. Operator-facing review

Use the API when a dashboard or platform needs to present the same session state the CLI sees.

- `POST /hunt` to start a session
- `POST /sessions/{session_id}/cancel` to stop a run
- `GET /sessions/{session_id}/analyze` for narrative findings
- `GET /health` for engine status metrics

## What the engine is good at

- Relationship-first review
- Scoping through hashed API keys and scopes
- Narrative summaries for business and technical follow-up
- Non-blocking hunts with cancellation
- Signed outputs that support audit and tamper detection

## What it is not

- A replacement for an authorized penetration test
- A tool for blind exploitation
- A source of truth for secrets or private keys
- A substitute for human review

## Technical anchors

- Local entrypoint: [`ozy.py`](../ozy.py)
- API runtime: [`src/core/api.py`](../src/core/api.py)
- Bootstrap: [`src/core/bootstrap.py`](../src/core/bootstrap.py)
- Auth registry: [`src/auth/key_store.py`](../src/auth/key_store.py)
- Runtime contract: [`RUNTIME_CONTRACT.md`](RUNTIME_CONTRACT.md)

## Practical note

If you are updating this document, keep the wording aligned with the live runtime contract rather than the historical phase notes in `docs/archive/`.
