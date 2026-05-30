# Runtime Contract

## Entrypoints

- `ozy.py`
- `cli/ozy.py`
- `src/core/api.py`
- `src/core/contracts.py`

## Required output fields

These frozen envelope fields must remain stable for consumers and tests.

- `status`
- `session_id`
- `target`
- `mode`
- `contract_version`
- `result`

## Session lifecycle

- `POST /hunt` starts a session
- `GET /sessions/{session_id}/trace` exposes trace data
- `GET /sessions/{session_id}/analyze` exposes narrative analysis
- `POST /sessions/{session_id}/cancel` stops a run

## Safety

- validate scope before active work
- keep runtime files local and idempotent
- preserve evidence and traceability
