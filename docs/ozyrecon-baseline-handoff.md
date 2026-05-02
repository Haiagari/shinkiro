# OzyRecon v8.3.2 Baseline Handoff

This document is the conservative handoff for the current `OzyRecon` baseline.
It keeps the live runtime, the active docs, and the historical material separated.

## Baseline

- Version: `v8.3.2`
- Runtime contract: `ozy.runtime.v1`
- Canonical local entrypoint: `ozy.py`
- API surface: `src/core/api.py`
- Orchestrator: `src/intelligence/orchestrator.py`

The current runtime is stable, documented, and aligned with the live code.

## Active Sources of Truth

Treat these as the live documents for the current baseline:

- `README.md`
- `docs/STATUS.md`
- `docs/RUNTIME_CONTRACT.md`
- `docs/architecture.md`
- `docs/USAGE.md`
- `docs/INSTALL.md`
- `docs/BRIDGE_CONTRACT.md`

## Historical Material

Treat these as historical or archival, not as the current baseline:

- `docs/archive/`
- `docs/ROADMAP.md`
- `mejora/PLAN_COMPLETO.md`

## What Is Closed

- The runtime contract no longer points to the old `src/workflow/orchestrator.py`
- The active architecture describes the real pipeline instead of a stale pillar list
- `docs/STATUS.md` now acts as the quick pointer to the current baseline
- Historical planning no longer competes with the live docs

## Maintenance Rules

1. Do not reintroduce `src/workflow/orchestrator.py` into active docs.
2. Do not treat `docs/ROADMAP.md` as current state.
3. Do not promote `docs/archive/` into live documentation.
4. Do not change runtime unless there is a real drift to fix.
5. Do not add new versions or phases unless the code actually changes.
6. Keep code, contract, and docs aligned in the same change when drift appears.

## When To Reopen

Reopen the baseline only if one of these changes:

- the canonical entrypoint changes
- the runtime contract changes
- the orchestrator moves
- the API surface changes
- persistence or export semantics change

## Practical Resume

If work resumes from this baseline, read in this order:

1. `docs/STATUS.md`
2. `docs/RUNTIME_CONTRACT.md`
3. `docs/architecture.md`
4. `README.md`
5. `docs/BRIDGE_CONTRACT.md`

That sequence gives the shortest accurate picture of the live engine.
