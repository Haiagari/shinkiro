# Bridge Contract

This document defines the compatibility closure between the OzyRecon runtime surface and any external platform bridge.

## Scope

- `src/core/contracts.py` is the frozen runtime contract source of truth.
- The bridge must preserve the published envelope and trace shapes.
- Compatibility closure means bridge adapters may translate transport details, but they MUST NOT rename or drop frozen runtime fields.

## Required runtime anchors

- `GET /sessions/{session_id}/trace`
- `GET /sessions/{session_id}/analyze`
- `GET /health`
- `POST /hunt`

## Contract rules

- The bridge MUST consume the same `CONTRACT_VERSION` exported by `src/core/contracts.py`.
- The bridge MUST preserve normalized session trace payloads.
- The bridge SHOULD remain a thin adapter over the local runtime API.
- The bridge MAY add transport metadata, but it MUST NOT alter runtime semantics.

## Notes

This file exists to keep the repository and any external bridge aligned without relying on implicit coupling.
