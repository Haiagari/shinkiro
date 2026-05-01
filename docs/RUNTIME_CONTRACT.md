# OzyRecon Runtime Contract

This document defines the local engine contract for this repository.

## Runtime entrypoints

- Canonical local entrypoint: [`ozy.py`](../ozy.py)
- CLI wrapper: [`cli/ozy.py`](../cli/ozy.py)
- API runtime: [`src/core/api.py`](../src/core/api.py)
- Runtime bootstrap: [`src/core/bootstrap.py`](../src/core/bootstrap.py)

## Core runtime surfaces

- Frozen contract constants: [`src/core/contracts.py`](../src/core/contracts.py)
- Context and observability: [`src/core/context.py`](../src/core/context.py)
- Auth registry: [`src/auth/key_store.py`](../src/auth/key_store.py)
- Workflow orchestration: [`src/workflow/orchestrator.py`](../src/workflow/orchestrator.py)
- Normalized export: [`src/export/normalizer.py`](../src/export/normalizer.py)
- Mode envelope: [`src/modes/base.py`](../src/modes/base.py)
- Session trace API: `GET /sessions/{session_id}/trace`
- Session analysis API: `GET /sessions/{session_id}/analyze`

## Runtime bootstrap contract

The engine is responsible for materializing mutable runtime files when missing:

- `config/config.yaml` from `config/config.example.yaml`
- `config/api_keys.json` from `config/api_keys.example.json`
- `resources/keys/evidence_key.priv` as a local Ed25519 seed

The bootstrap is idempotent and should not overwrite existing local state unless explicitly requested.

## Authentication contract

Protected endpoints require the `X-API-KEY` header.

- `admin:*` is required for full operator actions
- `sessions:read` is sufficient for the dashboard and read-only inspection
- `hunt:run` is used for controlled execution flows

API key records are hash-based. The default tracked seed is `config/api_keys.example.json`.

## Session lifecycle contract

Hunts are asynchronous and return a `session_id` immediately.

- `POST /hunt` starts a new session
- `POST /sessions/{session_id}/cancel` stops an active scan
- `GET /sessions/{session_id}/analyze` returns the narrative analysis
- `GET /sessions/{session_id}/trace` returns the execution trace

## Normalized output contract

All primary modes should return the same outer envelope:

- `status`
- `session_id`
- `target`
- `mode`
- `contract_version`
- `result`

The frozen envelope fields are declared in [`src/core/contracts.py`](../src/core/contracts.py) and are covered by contract tests.

The normalized result payload uses [`ScanResult`](../src/export/schema.py) as the source of truth.

## Traceability contract

Each run should expose:

- a context timeline
- error count and event count
- a consolidated session trace
- workflow steps
- evidence records
- decisions
- health metrics for the current runtime window

## Bridge boundary

The platform adapter is maintained in the Ozy Platform repository.
This tree defines the runtime and the contract, but not the platform bridge implementation.

## Safety contract

- Block unsafe scope before validation
- Require approval for gated validation
- Reject insecure HTTP verification unless explicitly opted in
- Keep blocked paths visible in logs and trace output
- Surface Smart Graph truncation when `is_truncated` is true
