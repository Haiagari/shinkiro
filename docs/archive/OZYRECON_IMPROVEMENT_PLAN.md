# OzyRecon Improvement Plan

This is the explanatory companion to the master hardening plan.

This document summarizes the current state of `OzyRecon`, the faults that need correction, and the staged plan to harden it into a clean, explicit engine.

## How Many Phases

I proposed **12 phases total**:

- Phase 0: baseline audit
- Phase 1: define the runtime source of truth
- Phase 2: align the platform bridge
- Phase 3: unify the discovery execution flow
- Phase 4: complete safe autonomy and remove placeholder behavior
- Phase 5: harden safety and scope
- Phase 6: normalize output and contracts
- Phase 7: improve observability and traceability
- Phase 8: align documentation
- Phase 9: verify end-to-end
- Phase 10: close compatibility formally
- Phase 11: keep hardening continuously

## Current State

`OzyRecon` is not a mock. It already has a working discovery and correlation core.

It currently includes:

- capability-driven discovery through `tool_manager`
- multiple operating modes
- workflow state transitions for hypotheses
- evidence capture
- normalized export
- OPSEC controls such as rate limiting, jitter, WAF detection, and kill-switch support
- a FastAPI API surface with dashboard endpoints
- storage-backed scan and hypothesis history
- a canonical normalized export contract in `src/export/normalizer.py`
- a safe autonomy layer for review planning and non-exploitative correlation
- an explicit legacy export helper kept only for compatibility
- a unified mode envelope for normalized output contracts

## Main Faults Found

### 1. Bridge/runtime drift

The platform manifest and the Go adapter do not fully describe the same runtime.

Observed issues:

- the manifest says `source_repo` is `/home/sam/Proyectos/OzyRecon`
- the manifest says `entrypoint` is `/home/sam/Proyectos/OzyRecon/ozy.py`
- the Go adapter still defaults to the internal copy at `/home/sam/Proyectos/ozy-platform/engines/recon`
- the adapter expects a wrapper binary at `/home/sam/Proyectos/ozy-platform/bin/ozyrecon`
- the local engine tree now exposes a stable `ozy.py` entrypoint

Impact:

- `Ozy Platform` can end up consuming a different runtime than the one the manifest describes.

### 2. Unsafe validation defaults

Several validators use permissive network behavior.

Observed issues:

- `verify=False` is used in `HTTPValidator`
- `verify=False` is used in `AutomationValidator`
- `verify=False` is used in `AuthValidator`
- `crawler.py` also uses permissive HTTP behavior

Impact:

- the engine is harder to trust in production-like environments
- validation behavior is less explicit than it should be

### 3. Placeholder / legacy behavior

The engine still contains partial behavior that should not remain in the production path.

Observed issues:

- `save_scope_to_db()` in `program_scraper.py` is a placeholder
- `program_scraper.py` comments indicate manual configuration gaps
- `ports.py` includes a “demo/seguridad” sampling limit
- `HTTPValidator` has screenshot logic marked as placeholder
- `storage/database.py` still supports legacy formats
- `intelligence` modules still mention legacy data shapes in comments

Impact:

- production behavior can look more complete than it really is
- the engine is harder to maintain and reason about

### 4. Multiple flows without a formal contract

The engine has several real modes, but the public contract is not yet formalized.

Observed modes:

- `hunt`
- `research`
- `continuous`
- `campaign`
- `forensic`
- `servicio`

Impact:

- the engine is usable, but not yet governed by one explicit published runtime contract

### 5. Security and policy can be tightened

The OPSEC layer exists, but it should be documented and standardized better.

Observed issues:

- rate limiting is present but not formally exposed as a contract
- jitter is present but not clearly bounded by policy in docs
- kill-switch support exists but not yet formalized in the bridge contract
- scope validation is helpful but still relatively lightweight

Impact:

- safety is real, but not yet framed as a published operating contract

## How I Would Correct It

### Phase 0: Baseline audit

What I would do:

- keep the current audit doc as the baseline
- freeze the current runtime state in documentation
- list what is real, what is legacy, and what is placeholder

Edits:

- document runtime entrypoints
- document adapter defaults
- document current validation paths
- document current placeholder behavior

### Phase 1: Choose the runtime source of truth

What I would do:

- decide whether the engine should run from the external repo or the internal copy
- align manifest, wrapper, and adapter to that choice

Edits:

- update the manifest
- add or formalize a real entrypoint
- remove ambiguous startup paths

### Phase 2: Align the platform bridge

What I would do:

- make the platform consume the same runtime the manifest publishes
- remove default fallback to the internal copy if the external repo is the source of truth

Edits:

- update `adapters/ozyrecon/adapter.go`
- update `registry/projects/ozyrecon.json`
- add bridge tests that fail on runtime drift

### Phase 3: Unify execution flow

What I would do:

- separate shared discovery logic from mode-specific behavior
- ensure every mode uses the same core selection and export rules

Edits:

- extract shared flow helpers where behavior is duplicated
- normalize mode initialization
- keep output paths consistent

### Phase 4: Complete safe autonomy and remove placeholder behavior

What I would do:

- formalize safe autonomy as prioritization, correlation and review planning
- keep all phase 4 behavior non-exploitative and human-visible
- isolate or remove logic that only exists as a demo or placeholder
- make legacy support explicit and opt-in

Edits:

- finish `save_scope_to_db()`
- replace placeholder comments with actual implementation or explicit compatibility notes
- remove demo sampling assumptions from production paths
- move screenshot or optional capture logic behind a documented policy
- add safe autonomy planner outputs and contract tests

### Phase 5: Harden safety and scope

What I would do:

- make validation policy explicit
- reduce permissive HTTP behavior where possible
- keep OPSEC behavior auditable

Edits:

- review `verify=False` usage
- add opt-in policy flags for unsafe probing where absolutely necessary
- document rate limiting and kill-switch behavior

### Phase 6: Normalize output and contracts

What I would do:

- standardize the output contract the platform consumes
- keep export schema stable

Edits:

- formalize scan/session metadata
- map discovery outputs into platform contracts cleanly
- keep the normalized exporter as the source of truth
- document the required normalized fields

### Closure note

In this repository, the output contract work is already implemented through `src/export/schema.py` and `src/export/normalizer.py`. The remaining bridge work belongs to the Ozy Platform repository.

The runtime mode envelope is also shared now through `src/modes/base.py`, so mode outputs follow the same stable outer shape.
- document the required normalized fields

### Phase 7: Improve observability and traceability

What I would do:

- make discovery runs easy to reconstruct
- expose mode, target, hypothesis, and evidence flow clearly

Edits:

- add or standardize scan identifiers in the runtime path
- ensure validation decisions are visible in logs and export
- make failure causes explicit

Closure note:

- Implemented in this repository through `ScanContext` timelines, the shared mode envelope, the session trace API, and the normalized export contract.

### Phase 8: Align documentation

What I would do:

- document the runtime contract
- document the bridge contract
- document what is real vs legacy

Edits:

- update `README.md`
- update a runtime contract doc
- update the platform integration notes

Closure note:

- Implemented in this repository through `README.md`, `docs/RUNTIME_CONTRACT.md`, `docs/USAGE.md`, `docs/INSTALL.md`, and `docs/architecture.md`.

### Phase 9: Verify end-to-end

What I would do:

- validate the API bootstrap
- validate the main modes
- validate export output
- validate platform bridge behavior

Edits:

- add integration tests for the runtime surface
- add contract tests for bridge behavior
- add regression tests for placeholder removal

Closure note:

- Implemented in this repository through `tests/test_runtime_end_to_end.py`, `tests/test_observability.py`, and the normalized export/API contract tests.

### Phase 10: Close compatibility formally

What I would do:

- freeze the runtime contract fields
- verify manifest and adapter agree
- verify the platform can consume the engine without guessing

Edits:

- add compatibility notes
- add guardrail coverage
- lock the bridge contract in tests

Closure note:

- Implemented in this repository through `src/core/contracts.py`, `tests/test_contracts.py`, and the runtime/bridge contract docs.

### Phase 11: Continuous hardening

What I would do:

- keep drift from reappearing
- keep placeholder behavior out of production
- keep the platform bridge honest

Edits:

- add recurring guardrails
- update docs whenever runtime changes
- re-run bridge tests whenever manifest or adapter behavior changes

Closure note:

- Implemented in this repository through `tests/test_hardening_guardrails.py`, `tests/test_contracts.py`, and the frozen runtime contract docs.

## What I Would Edit First

If I had to start now, I would edit these in this order:

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

## Summary of Corrections

- fix runtime drift
- remove placeholder behavior
- tighten validation safety
- formalize the bridge contract
- normalize output consistently
- document the actual runtime
- add tests so drift fails fast

## Final Reading

`OzyRecon` is already a real engine. The remaining work is not to invent it, but to make it explicit, safer, and contract-driven so the platform can consume it without ambiguity.
