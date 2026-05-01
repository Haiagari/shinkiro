# OzyRecon Status

This document is the current lightweight status note for the repository.
It replaces the old session-note style of tracking and points to the live baseline instead of the archive history.

## Current baseline

- Version: `v8.3.2`
- Runtime: stable local engine with bootstrap, auth, lifecycle control, and narrative analysis
- API auth: `X-API-KEY` with hashed keys and scopes
- Mutable runtime files: bootstrapped locally from tracked seeds when missing

## Live surfaces

- [`README.md`](../README.md)
- [`docs/INSTALL.md`](INSTALL.md)
- [`docs/USAGE.md`](USAGE.md)
- [`docs/RUNTIME_CONTRACT.md`](RUNTIME_CONTRACT.md)
- [`docs/architecture.md`](architecture.md)
- [`src/core/bootstrap.py`](../src/core/bootstrap.py)
- [`src/core/api.py`](../src/core/api.py)

## Archived material

The following content is historical and should not be treated as the active plan:

- [`docs/archive/README.md`](archive/README.md)
- `docs/archive/OZYRECON_PHASE0_AUDIT.md`
- `docs/archive/OZYRECON_HARDENING_PLAN.md`
- `docs/archive/OZYRECON_IMPROVEMENT_PLAN.md`
- `docs/archive/OZYRECON_OPERATIONAL_PLAN.md`
- `docs/archive/trayecto.md`

## What is current work

- Keep the runtime contract aligned with implementation
- Keep docs in sync with the live baseline
- Keep generated artifacts and secrets out of version control
- Preserve the bootstrap/auth/session lifecycle behavior

## What is not current work

- Reopening archived phase plans as active work
- Reintroducing old v7.x wording into operator docs
- Treating archive text as source of truth

## Practical pointer

If you are resuming work from this repository, read this file first, then review `README.md` and `docs/ROADMAP.md`.
