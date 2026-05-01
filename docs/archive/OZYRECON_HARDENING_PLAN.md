# 🛡️ OzyRecon Hardening Plan [COMPLETED]

> **STATUS: ARCHIVED.** The hardening objectives defined in this document were successfully implemented in the v7.5 - v8.3.2 release cycle.

This is the master plan for hardening `OzyRecon`.

This document is the roadmap to turn `OzyRecon` into a single, explicit, consumable engine.

The goal is to remove runtime ambiguity, align the platform bridge, and keep the discovery engine real while eliminating placeholder behavior from the production path.

## Status

- Phase 0 completed: baseline audit captured in [OZYRECON_PHASE0_AUDIT.md](./OZYRECON_PHASE0_AUDIT.md).
- The remaining phases describe the staged path to a formal runtime contract and a stable platform bridge.
- In this tree, safe autonomy and normalized export are already implemented.
- The bridge adapter remains a platform-repo responsibility and is documented in [docs/BRIDGE_CONTRACT.md](./docs/BRIDGE_CONTRACT.md).

## Purpose

- Make `OzyRecon` the source of truth for discovery and correlation.
- Ensure the platform consumes it through one explicit runtime contract.
- Remove bridge drift between the manifest, adapter, and engine tree.
- Keep the engine safe, observable, and auditable.

## Principles

- One runtime source of truth.
- One official bootstrap path.
- One discovery pipeline.
- One normalized output contract.
- No hidden internal copy as a silent fallback.
- No placeholder logic in the production path.
- Routing and compatibility must stay explicit.

## Current State

### What exists and is real

- FastAPI API and dashboard in `src/core/api.py`.
- Capability registry in `src/core/register_providers.py`.
- Capability execution in `src/core/tool_manager.py`.
- Workflow engines and validators in `src/workflow/` and `src/validation/`.
- Evidence capture in `src/evidence/`.
- Normalized export in `src/export/normalizer.py`.
- OPSEC helpers in `src/opsec/`.

### What needs correction

- Manifest/adapter runtime drift.
- Missing stable entrypoint in the local tree.
- `verify=False` validation calls.
- Placeholder persistence in scope syncing.
- Demo sampling limits that should become policy-driven.
- Legacy compatibility paths that should not be part of the default production flow.

### What is already closed here

- Stable local entrypoint via `ozy.py`.
- Safe autonomy planner and API endpoint.
- Normalized export contract with `ScanResult`.
- Legacy export helper kept only as compatibility shim.
- Phase 5 safety and scope enforcement is now implemented in the runtime path.
- Phase 6 output contract is now enforced through a shared mode envelope.
- Phase 7 observability and traceability is implemented through context timelines and session trace output.
- Phase 8 documentation alignment is now implemented through the runtime contract document and updated guides.
- Phase 9 end-to-end verification is now implemented through runtime, trace, and export tests.
- Phase 10 compatibility closure is now implemented through frozen contract fields and contract tests.

## Result Sought

At the end of this plan:

- the runtime bootstrap is explicit
- the control plane bridge is aligned
- the engine can be consumed without guessing
- the discovery and validation pipeline is auditable
- placeholder behavior is isolated or removed
- docs and code tell the same story

## Phase 0. Baseline Audit

### Objective

Document what is real today and what is still placeholder, legacy, or bridge drift.

### Tasks

- Identify the engine runtime surface.
- Identify the platform-facing adapter surface.
- Identify placeholder or demo logic.
- Identify runtime defaults that contradict the manifest.
- Identify the safety model that is already present.

### Exit Criteria

- A closed baseline exists.
- The engine can be described accurately without hand-waving.

## Phase 1. Define the Runtime Source of Truth

### Objective

Choose one official bootstrap path for `OzyRecon`.

### Tasks

- Decide whether the authoritative runtime is the internal tree or the external repo.
- Align the manifest to that decision.
- Add or formalize a wrapper entrypoint.
- Document the canonical way to start the engine.

### Exit Criteria

- A developer can answer which file or command boots the engine in production.

## Phase 2. Align the Platform Bridge

### Objective

Make the control-plane adapter consume the same runtime contract the engine publishes.

### Tasks

- Remove internal-copy defaults from the adapter.
- Resolve `source_repo`, `entrypoint`, and runtime endpoint from manifest or config.
- Stop relying on a silent fallback to the monorepo copy.
- Ensure the adapter probes before execution.

### Exit Criteria

- `Ozy Platform` launches the intended runtime path and not a hidden duplicate.

## Phase 3. Unify the Discovery Execution Flow

### Objective

Make discovery flows consistent across modes and capabilities.

### Tasks

- Review `hunt`, `research`, `continuous`, `campaign`, `forensic`, and `servicio`.
- Extract shared pipeline logic where it is duplicated.
- Keep capability execution consistent across modes.
- Ensure scans, sessions, and exports follow one flow.

### Exit Criteria

- There is one clear discovery pipeline, not a collection of competing mini-pipelines.

## Phase 4. Complete Safe Autonomy and Remove Placeholder Behavior

### Objective

Ship the safe autonomy layer for prioritization and correlation while eliminating behavior that looks real but is only partial or placeholder.

### Tasks

- Formalize safe autonomy as review planning, prioritization and non-exploitative correlation.
- Remove or isolate `verify=False` where it is not strictly required.
- Replace placeholder persistence in scope sync.
- Rework demo sampling limits into policy-driven limits.
- Remove placeholder screenshot and DB-sync assumptions from production paths.
- Decide what legacy support is still needed and make it opt-in.

### Exit Criteria

- The production path no longer depends on placeholder logic.
- The safe autonomy layer is available through code and API.

## Phase 5. Harden Safety and Scope

### Objective

Keep reconnaissance controlled and bounded.

### Tasks

- Formalize safe scope validation.
- Make allowlists and policy explicit.
- Tighten OPSEC defaults.
- Review rate limiting, jitter, and kill-switch behavior.
- Make target selection and credential use auditable.

### Exit Criteria

- Safe probing rules are explicit and enforceable.

## Phase 6. Normalize Output and Contracts

### Objective

Produce a stable output contract that the platform can consume cleanly.

### Tasks

- Map discovery, evidence, and validation outputs to the shared contracts.
- Normalize session and scan metadata.
- Keep export schema stable across modes.
- Document required metadata and canonical fields.

### Exit Criteria

- Output shape is predictable and platform-friendly.

## Phase 7. Observability and Traceability

### Objective

Make discovery runs easy to audit.

### Tasks

- Add or improve scan identifiers in all major paths.
- Record evidence and validation decisions consistently.
- Expose routing and mode selection in metadata.
- Make failure causes visible.

### Exit Criteria

- A run can be reconstructed from logs, DB state, and export artifacts.

### Closure note

This phase is already implemented in this repository through `src/core/context.py`, `src/modes/base.py`, `src/storage/queries.py`, and `src/core/api.py`.

## Phase 8. Documentation Alignment

### Objective

Make docs reflect the runtime that actually exists.

### Tasks

- Update the engine README.
- Add runtime contract documentation.
- Add an integration note for the platform bridge.
- Clarify what is real, what is legacy, and what is placeholder.

### Exit Criteria

- Documentation matches the runtime contract and the bridge contract.

### Closure note

This phase is already implemented in this repository through `README.md`, `docs/USAGE.md`, `docs/INSTALL.md`, `docs/architecture.md`, and `docs/RUNTIME_CONTRACT.md`.

## Phase 9. End-to-End Verification

### Objective

Prove the engine works through the bridge and through its own runtime.

### Tasks

- Validate the API bootstrap.
- Validate a hunt flow.
- Validate a research flow.
- Validate a continuous flow.
- Validate the export path.
- Validate the adapter bridge.

### Exit Criteria

- Real flows pass through the intended runtime path and export normalized output.

### Closure note

This phase is already implemented in this repository through `tests/test_runtime_end_to_end.py`, `tests/test_observability.py`, and the API/export contract tests.

## Phase 10. Compatibility Closure

### Objective

Close the contract with the platform.

### Tasks

- Freeze the runtime contract fields.
- Verify the manifest and adapter agree.
- Verify the platform bridge uses the correct source repo and entrypoint.
- Verify fallback behavior is explicit.

### Exit Criteria

- The platform can consume `OzyRecon` without guessing or drifting.

### Closure note

This phase is already implemented in this repository through `src/core/contracts.py`, `tests/test_contracts.py`, and the runtime contract documentation.

## Phase 11. Continuous Hardening

### Objective

Prevent drift back into ambiguity.

### Tasks

- Review new capabilities before merging.
- Keep platform and manifest aligned.
- Keep placeholder logic out of production paths.
- Re-run compatibility checks when runtime or bridge behavior changes.

### Exit Criteria

- The engine remains stable after hardening.

### Closure note

This phase is already implemented in this repository through recurring contract tests, docs guardrails, and the frozen runtime contract in `src/core/contracts.py`.

## Recommended Execution Order

1. Audit baseline.
2. Define runtime source of truth.
3. Align the platform bridge.
4. Unify execution flow.
5. Remove placeholder behavior.
6. Harden safety and scope.
7. Normalize output and contracts.
8. Improve observability.
9. Align documentation.
10. Verify end-to-end.
11. Close compatibility formally.
12. Keep hardening continuously.

## Current Risks

- Bridge drift between manifest and adapter.
- Unsafe defaults in validation requests.
- Placeholder behavior leaking into production paths.
- Multiple modes diverging in behavior.
- Documentation describing a different runtime than the code.

## Definition of Done

`OzyRecon` is considered hardened when:

- the runtime source of truth is explicit
- the bridge is aligned
- placeholder behavior is not part of the production path
- the output contract is stable
- the engine can be consumed without guessing
- the behavior is verified by real scans and exports
