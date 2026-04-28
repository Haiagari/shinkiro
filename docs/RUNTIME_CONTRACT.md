# OzyRecon Runtime Contract

This document defines the local engine contract for this repository.

## Runtime entrypoints

- Canonical local entrypoint: [`ozy.py`](../ozy.py)
- CLI wrapper: [`cli/ozy.py`](../cli/ozy.py)
- API runtime: [`src/core/api.py`](../src/core/api.py)

## Core runtime surfaces

- Frozen contract constants: [`src/core/contracts.py`](../src/core/contracts.py)
- Context and observability: [`src/core/context.py`](../src/core/context.py)
- Workflow orchestration: [`src/workflow/orchestrator.py`](../src/workflow/orchestrator.py)
- Normalized export: [`src/export/normalizer.py`](../src/export/normalizer.py)
- Mode envelope: [`src/modes/base.py`](../src/modes/base.py)
- Session trace API: `GET /sessions/{session_id}/trace`

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

## Bridge boundary

The platform adapter is maintained in the Ozy Platform repository.
This tree defines the runtime and the contract, but not the platform bridge implementation.

## Safety contract

- Block unsafe scope before validation
- Require approval for gated validation
- Reject insecure HTTP verification unless explicitly opted in
- Keep blocked paths visible in logs and trace output
