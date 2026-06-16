# Platform Documentation

- [Bridge Contract](#bridge-contract)
- [Runtime Contract](#runtime-contract)

---

## Bridge Contract

Defines the compatibility closure between OzyRecon runtime and any external platform bridge.

### Scope

- `src/core/contracts.py` is the frozen runtime contract source of truth.
- The bridge must preserve the published envelope and trace shapes.
- Compatibility closure means bridge adapters may translate transport details, but they MUST NOT rename or drop frozen runtime fields.

### Required runtime anchors

- `GET /sessions/{session_id}/trace`
- `GET /sessions/{session_id}/analyze`
- `GET /health`
- `POST /hunt`

### Contract rules

- The bridge MUST consume the same `CONTRACT_VERSION` exported by `src/core/contracts.py`.
- The bridge MUST preserve normalized session trace payloads.
- The bridge SHOULD remain a thin adapter over the local runtime API.
- The bridge MAY add transport metadata, but it MUST NOT alter runtime semantics.

---

## Runtime Contract

### Entrypoints

- `ozy.py`
- `cli/ozy.py`
- `src/core/api.py`
- `src/core/contracts.py`

### Required output fields

These frozen envelope fields must remain stable for consumers and tests:

- `status`
- `session_id`
- `target`
- `mode`
- `contract_version`
- `result`

### Session lifecycle

- `POST /hunt` starts a session
- `GET /sessions/{session_id}/trace` exposes trace data
- `GET /sessions/{session_id}/analyze` exposes narrative analysis
- `POST /sessions/{session_id}/cancel` stops a run

### Safety

- Validate scope before active work
- Keep runtime files local and idempotent
- Preserve evidence and traceability
