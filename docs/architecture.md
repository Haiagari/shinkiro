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

## Operational Pipeline

OzyRecon processes targets through a sequential intelligence pipeline:

1. **Discovery**: `DiscoveryOrchestrator` identifies assets and services.
2. **Validation**: `target_validator.py` applies OPSEC and SSRF Pro shields.
3. **Enrichment**: `classifier.py` infers roles, `scoring_engine.py` assesses impact.
4. **Correlation**: `graph_builder.py` maps relationships; `autonomy.py` builds memory.
5. **Evidence**: Findings are signed via Ed25519; `feedback_engine.py` refines future runs.
6. **Export**: `normalizer.py` packages the result into `ScanResult` schema.
7. **Traceability**: `session_manager.py` tracks the full lifecycle; `trace` endpoints expose it.

This pipeline ensures that every byte of data passes through a controlled, auditable, and increasingly intelligent execution flow.

## Architectural Pillars

### 1. Identity & Control
- Hashed API key registry (`src/auth/key_store.py`)
- Scope-based authorization (`admin:*`, `sessions:read`, `hunt:run`)
- Local materialization of mutable runtime files

### 2. OPSEC & Hardening
- Anti-SSRF and DNS-Rebinding protection (`src/security/target_validator.py`)
- Session cancellation (`POST /sessions/{id}/cancel`)
- JSONL structured logging with rotation

### 3. Forensic Integrity
- Ed25519 signatures for evidence (`resources/keys/evidence_key.priv`)
- Contextual metadata (`session_id`, `contract_version`)
- Tamper detection via forensic mode

### 4. Intelligence Core
- Semantic classification and scoring (`src/intelligence/`)
- Smart Graph with prioritization and `is_truncated` flag
- Narrative analysis (`/sessions/{id}/analyze`)

---

## Mutable Runtime Files

The engine bootstraps three mutable files at runtime:

- `config/config.yaml`
- `config/api_keys.json`
- `resources/keys/evidence_key.priv`

These files are intentionally excluded from version control because they are operational state, not source code.

---

## Project Status
- Elite Intelligence - completed
- Operational Hardening - completed
- Enterprise Baseline v8.3.2 - completed

Classification: Enterprise-grade security intelligence platform

Last updated: 2026-05-01
