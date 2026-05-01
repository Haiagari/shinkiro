# OzyRecon v8.3.2 Architecture - The Enterprise Baseline

## Overview

OzyRecon v8.3.2 is a resilient intelligence engine organized around four live layers: identity, runtime bootstrap, inference, and forensic evidence.

---

## Runtime Surface

1. `ozy.py` - canonical local entrypoint
2. `src/core/api.py` - API protected by `X-API-KEY`
3. `src/auth/` - hashed key registry and RBAC
4. `src/core/bootstrap.py` - mutable runtime file bootstrap
5. `GET /sessions/{session_id}/analyze` - narrative analysis surface
6. `GET /health` - runtime metrics surface

---

## Architectural Pillars

### 1. Identity & Control

- Hashed API key registry
- Scope-based authorization
- Seeded defaults in `config/api_keys.example.json`
- Local materialization of `config/api_keys.json` when missing

### 2. Operational Hardening

- Anti-SSRF validation before probe execution
- Session cancellation for long-running hunts
- Structured trace output for each run
- Log cleanup and blocked-path visibility

### 3. Forensic Integrity

- Ed25519 signatures for evidence and findings
- Contextual metadata such as `session_id` and timestamp
- Tamper detection against stored findings

### 4. Smart Graph Intelligence

- Graph output with prioritization
- `is_truncated` flag when output is a prioritized slice
- Narrative layer to explain business impact and technical guidance

---

## Mutable Runtime Files

The engine bootstraps three mutable files at runtime:

- `config/config.yaml`
- `config/api_keys.json`
- `resources/keys/evidence_key.priv`

These files are intentionally excluded from version control because they are operational state, not source code.

---

## Project Status

- Phase 5: Elite Intelligence - completed
- Phase 7: Operational Hardening - completed
- Phase 8: Enterprise Baseline v8.3.2 - completed

Classification: Enterprise-grade security intelligence platform

Last updated: 2026-05-01
