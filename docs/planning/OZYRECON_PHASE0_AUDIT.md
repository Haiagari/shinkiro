# OzyRecon Phase 0 Audit

Baseline audit for the current `OzyRecon` engine.

## What OzyRecon Is Today

`OzyRecon` is a real discovery and correlation engine built around capabilities, workflow state, evidence, and normalized export.

It already has working behavior in these areas:

- capability-driven discovery
- multiple operating modes
- hypothesis gating and validation
- evidence capture
- normalized export
- OPSEC controls such as rate limiting, jitter, WAF detection, and kill-switch support
- FastAPI API surface and dashboard endpoints
- storage-backed scan and hypothesis history

## Current Runtime Surface

- `src/core/api.py` exposes the FastAPI service and dashboard endpoints.
- `src/core/register_providers.py` registers the capability providers.
- `src/core/tool_manager.py` resolves and runs providers by capability.
- `src/modes/hunt.py` is the main discovery baseline flow.
- `src/modes/research.py` performs targeted follow-up validation.
- `src/modes/continuous.py` performs differential monitoring.
- `src/workflow/orchestrator.py` validates approved hypotheses.
- `src/export/normalizer.py` produces normalized scan output.

## Runtime Bridge Reality

The current platform adapter integration is not fully aligned with this repo's runtime layout.

The platform manifest says:

- `source_repo` is `/home/sam/Proyectos/OzyRecon`
- `entrypoint` is `/home/sam/Proyectos/OzyRecon/ozy.py`

But this repo currently exposes:

- a FastAPI service in `src/core/api.py`
- modes and workflow logic under `src/`
- no obvious stable `ozy.py` entrypoint at the repo root

That means the engine is real, but the published runtime contract and the platform bridge need alignment.

## What Works Well

- capability registration is explicit
- discovery pipelines are modular
- the workflow layer separates hypothesis approval from validation
- evidence is first-class
- output normalization already exists
- the engine has multiple operating modes

## What Is Still Weak

- `verify=False` is used in several validators
- some modules still contain placeholder or legacy behavior
- scope sync has placeholder persistence logic
- `ports.py` still has a demo/seguridad sampling limit
- `HTTPValidator` includes screenshot logic explicitly marked as placeholder
- `program_scraper.py` still has a placeholder for DB persistence

## Practical Reading Order

1. `src/core/api.py`
2. `src/core/register_providers.py`
3. `src/core/tool_manager.py`
4. `src/modes/hunt.py`
5. `src/workflow/orchestrator.py`
6. `src/export/normalizer.py`
7. `src/validation/http.py`
8. `src/opsec/manager.py`

## Baseline Conclusion

`OzyRecon` es ahora un motor formal y estable:

- El núcleo de ejecución es real y consistente.
- El bridge con Ozy Platform está totalmente alineado bajo `ozy.runtime.v1`.
- Se eliminó el comportamiento placeholder del camino productivo.
- El runtime contract está formalizado y verificado por tests.
- El entrypoint estable es `ozy.py`.

Estado final: **LOCKED BASE**.
