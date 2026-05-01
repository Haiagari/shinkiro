# OzyRecon v8.3.2 Architecture — The Enterprise Baseline

## Overview

OzyRecon v8.3.2 ha evolucionado a una **plataforma de inteligencia ofensiva resiliente** con una arquitectura blindada de tres capas: Identidad, Motor de Inferencia y Capa de Evidencia Forense.

---

## Runtime Surface (v8.3.2)

1. `ozy.py` — Entrypoint local canónico.
2. `src/core/api.py` — API protegida por **X-API-KEY (Hashed)** y Scopes.
3. `src/auth/` — Sistema de gestión de identidades y RBAC.
4. `GET /sessions/{session_id}/analyze` — Capa de Inteligencia Narrativa (IA).
5. `src/core/bootstrap.py` — Bootstrap de archivos mutables desde seeds versionados.

---

## Pilares de la Arquitectura v8.3.2

### 1. Identity & Control (RBAC)
- Registro de llaves hasheadas (SHA-256).
- Scopes granulares por endpoint.
- Rate Limiting adaptativo por Key e IP.
- Seed versionado en `config/api_keys.example.json`, materializado a `config/api_keys.json` cuando falta.

### 2. Operational Hardening
- **Anti-SSRF Shield**: Pre-scan DNS resolution para evitar rebinding y ataques internos.
- **Session Manager**: Seguimiento y cancelación de tareas en tiempo real.
- **Log Scrubber**: Limpieza automática de secretos en logs estructurados.

### 3. Forensic Integrity 2.0
- Firmas Ed25519 contextuales (`session_id`, `timestamp`).
- Versionado de esquemas de datos.
- Auditoría de manipulación (Tamper Detection).

### 4. Smart Graph Intelligence
- Truncamiento inteligente de nodos (prioridad por score).
- Inferencia semántica trazable (Explainability).

---

## Project Status

**Phase 5: Elite Intelligence** — COMPLETED
**Phase 7: Operational Hardening** — COMPLETED
**Phase 8: Enterprise Baseline v8.3.2** — COMPLETED

**Classification**: Enterprise-Grade Security Intelligence Platform

**Última actualización**: 01/05/2026 (v8.3.2 Final Release)
