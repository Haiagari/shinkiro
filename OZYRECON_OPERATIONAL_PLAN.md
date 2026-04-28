# OzyRecon Operational Plan

This is the execution-oriented companion to the master hardening plan.

This is the execution-oriented version of the `OzyRecon` hardening work.

It turns the audit and improvement notes into a phase-by-phase worklist with:

- the problem
- the correction
- the files to edit first
- the exit criterion

## Phase Summary

| Phase | Fault | Correction | First Edits | Exit Criterion |
|---|---|---|---|---|
| 0 | Baseline was undocumented in a single place | Capture the real state of the engine, bridge, and placeholder areas | `README.md`, `OZYRECON_PHASE0_AUDIT.md` | The engine can be described accurately and consistently |
| 1 | Runtime source of truth is not formally chosen | Pick one official bootstrap path and make it the documented runtime | `src/core/api.py`, repo root entrypoint, `README.md` | A developer can say exactly how the engine starts |
| 2 | Platform bridge and engine runtime drift apart | Align manifest, adapter, and runtime endpoint | `registry/projects/ozyrecon.json`, `adapters/ozyrecon/adapter.go` | The platform launches the intended runtime path only |
| 3 | Discovery flows diverge by mode | Unify shared discovery behavior across modes | `src/modes/hunt.py`, `src/modes/research.py`, `src/modes/continuous.py` | One consistent discovery pipeline exists |
| 4 | Placeholder behavior remains in production paths | Replace or isolate placeholder/demo logic | `src/discovery/targets/program_scraper.py`, `src/discovery/services/ports.py`, `src/validation/http.py` | Production behavior no longer depends on placeholders |
| 5 | Safety rules are present but not formalized | Publish explicit scope and probing policy | `src/opsec/manager.py`, `src/validation/*.py` | Safe probing rules are explicit and enforceable |
| 6 | Output shape is not fully contract-driven | Normalize scan/session metadata and export fields | `src/export/normalizer.py`, `src/export/schema.py` | Output is predictable for `Ozy Platform` |
| 7 | Runs are not easy enough to reconstruct | Improve traceability and failure visibility | `src/core/api.py`, `src/workflow/orchestrator.py`, `src/workflow/engine.py` | A run can be rebuilt from logs and stored state |
| 8 | Documentation does not fully describe the runtime | Align README and add runtime contract docs | `README.md`, `OZYRECON_HARDENING_PLAN.md` | Docs match the runtime contract |
| 9 | End-to-end behavior is not formally proven | Add and run contract and integration tests | bridge tests, mode tests, export tests | Real flows pass through the intended runtime path |
| 10 | Compatibility is implied instead of formal | Freeze bridge fields and platform expectations | `registry/projects/ozyrecon.json`, adapter tests, docs | The platform can consume OzyRecon without guessing |
| 11 | Drift can reappear after cleanup | Add recurring guardrails and review rules | README, tests, docs notes | The engine stays stable after hardening |

## What To Fix First

If you need to start now, do this in order:

1. Align the runtime source of truth.
2. Fix the platform bridge drift.
3. Remove placeholder behavior.
4. Tighten unsafe HTTP defaults.
5. Formalize the output contract.
6. Add bridge and runtime tests.
7. Align docs with the final runtime.

## Main Faults, Condensed

### Bridge drift

- Manifest and adapter do not yet point at the same runtime model.
- The adapter still defaults to the internal copy.
- The manifest expects an external runtime shape that is not fully reflected in the current tree.

### Unsafe defaults

- `verify=False` appears in validation paths.
- HTTP probing is more permissive than it should be for a published contract.

### Placeholder behavior

- `save_scope_to_db()` is not implemented.
- scope synchronization still has manual gaps.
- `HTTPValidator` screenshot capture is explicitly placeholder-like.
- `ports.py` still caps scans with a demo/seguridad note.

### Mode fragmentation

- `hunt`, `research`, `continuous`, `campaign`, `forensic`, and `servicio` are all real.
- They need one shared discovery contract so the engine does not split into multiple slightly different behaviors.

## Recommended Edits

Start with these files:

1. `registry/projects/ozyrecon.json`
2. `adapters/ozyrecon/adapter.go`
3. `src/core/api.py`
4. `src/validation/http.py`
5. `src/validation/auth.py`
6. `src/validation/automation.py`
7. `src/discovery/targets/program_scraper.py`
8. `src/discovery/services/ports.py`
9. `src/export/normalizer.py`
10. `README.md`

## Operational Definition of Done

`OzyRecon` is operationally complete when:

- the runtime source of truth is explicit
- the adapter and manifest agree
- placeholder behavior is out of the production path
- the output contract is stable
- the platform can consume the engine without guessing
- the workflow is backed by tests and docs

## Closure Notes

- Phase 8 is already implemented in this tree through `README.md`, `docs/RUNTIME_CONTRACT.md`, `docs/USAGE.md`, `docs/INSTALL.md`, and `docs/architecture.md`.
- The local runtime contract is the source of truth here; the platform bridge remains a separate repository concern.
- Phase 9 is already implemented in this tree through `tests/test_runtime_end_to_end.py`, `tests/test_observability.py`, and the API/export contract tests.
- Phase 10 is already implemented in this tree through `src/core/contracts.py` and `tests/test_contracts.py`.
- Phase 11 is already implemented in this tree through `tests/test_hardening_guardrails.py` and the recurring contract guardrails.
