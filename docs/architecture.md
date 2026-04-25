# OzyRecon v5.7 Architecture — Assisted Offensive Validation Platform

## Overview

OzyRecon v5.7 es una **Security Validation Platform** diseñada para transformar el reconocimiento ofensivo en inteligencia auditable y de alta confianza. Se especializa en descubrimiento de superficie, validación asistida y evidencia visual con integridad criptográfica.

**Filosofía: NO EXPLOITATION** — Confirmamos exposición, no la explotamos.

---

## Los 8 Pilares de OzyRecon

### 1. Tool Manager + Capabilities
Abstracción de herramientas basada en capacidades:
- `asset_discovery` — subdominios, activos
- `service_discovery` — puertos, servicios
- `template_scan` — nuclei
- `port_scan` — nmap, naabu

### 2. Modos Operativos (6 modos)
- **HUNT**: Ejecución exhaustiva, línea base
- **CONTINUOUS**: Monitoreo reactivo basado en delta
- **RESEARCH**: Escaneo dirigido por tecnología/CVE
- **CAMPAIGN**: Escalado de patrones
- **FORENSIC**: Análisis histórico
- **SERVICIO**: Reportes ejecutivos

### 3. Memoria Táctica
- `AgentMemory` — razonamientos guardados
- `host_reputation` — historial de hallazgos
- `waf_detected` — presencia de WAF

### 4. Diff Engine Reactivo
- Detecta nuevos subdominios → Escanea automáticamente
- Detecta cambios de versión → Investiga
- Detecta puertos cerrados → Limpia memoria

### 5. Priority Engine
Scoring dinámico basado en:
- Reputación histórica del host
- Novedad del activo
- Patrones detectados

### 6. OPSEC Integrado
- Pre-flight WAF detection
- Rate adaptation automática
- Kill-switch automático
- Identity rotation

### 7. Knowledge Graph + Inteligencia Generada (v5.7)
- `IntelligenceBrief` con surface delta %
- Knowledge Graph visualizable (Cytoscape.js)
- Recomendaciones concretas

### 8. Output Normalizado
- `ScanResult` schema: JSON para OzyAudit, Markdown para clientes, CSV, Burp SAR

---

## Pipeline de Validación

```
Discovery → Hypothesis → Human Gate (Approval) → Validation → Evidence → Report
```

### Human Gate
Todas las hipótesis generadas requieren autorización manual antes de ejecución.

### Evidence Engine (v5.7)
- Captura screenshots automatizada con Playwright
- Hash SHA256 por cada evidencia
- Integridad criptográfica verificable

---

## Estructura de Directorios

```
src/
├── agent/              # Config writer, scoring weights
├── core/               # API (11 endpoints), config, tool_manager
├── discovery/          # Assets, services, targets, crawler
├── evidence/           # Evidence engine + screenshots
├── export/             # Normalizer, platforms (H1, BC, IF)
├── gate/               # Human-in-the-loop control
├── intelligence/       # Priority, analyzer, brief, learning_orchestrator
├── modes/              # hunt, continuous, research, campaign, forensic, servicio
├── notifications/      # Telegram notifier
├── opsec/              # Rate limiter, WAF detector, kill_switch, jitter
├── reporting/          # Report engine
├── scanners/           # Templates, web fuzzing, DB scanners
├── storage/            # Database, models, queries, diff
├── utils/              # Visual (screenshots), benchmark
├── validation/         # HTTP, auth, CMS, config, infra, web validators
└── workflow/           # Orchestrator, engine, states
```

---

## API Endpoints (src/core/api.py)

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/` | GET | Status y versión |
| `/intelligence/graph` | GET | Knowledge Graph (nodes + edges) |
| `/intelligence/status` | GET | Métricas del sistema de aprendizaje |
| `/intelligence/export` | GET | Exporta brain a .ozy |
| `/targets` | GET | Lista de targets conocidos |
| `/targets/{domain}/latest` | GET | Último scan normalizado |
| `/gate/pending` | GET | Hipótesis pendientes de aprobación |
| `/gate/approve/{hyp_id}` | POST | Aprueba hipótesis |
| `/gate/reject/{hyp_id}` | POST | Rechaza hipótesis |
| `/evidence/{hyp_id}` | GET | Evidencia de una hipótesis |
| `/dashboard` | GET | Dashboard de inteligencia |

---

## Technical Flow: Visual Evidence (v5.7)

1. **Detection**: `HTTPValidator` confirma un finding sensible
2. **Trigger**: Si status es `confirmed`, llama `src.utils.visual.capture_screenshot()`
3. **Headless Execution**: Playwright lanza Chromium headless, navega y renderiza
4. **Capture**: PNG guardado en `runtime/evidence/screenshots/`
5. **Integrity**: `EvidenceEngine` calcula SHA256 del archivo

---

## Data Flow Pipeline

```
Target → Discovery → Intelligence (Correlation)
                     ↓
             [HYPOTHESIS GENERATED]
                     ↓
               [HUMAN GATE] <─── Operator Authorization
                     ↓
             [VALIDATION LAYER] ───> Surgical Probes
                     ↓
              [VISUAL EVIDENCE] ───> Automated Screenshots + SHA256
                     ↓
              [EVIDENCE ENGINE] ───> Secure Evidence Vault
                     ↓
               [REPORT ENGINE] ───> Executive Narrative (MD/JSON)
```

---

## Project Status

**Phase 1: Adaptativo (reacciona al delta)** — ✅ COMPLETED  
**Phase 2: Reflexivo (evalúa y aprende)** — ✅ COMPLETED  
**Classification**: Professional Security Validation Platform

**Test Suite**: 43 tests passing (API integration + architecture)

**Última actualización**: 24/04/2026