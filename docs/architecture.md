# OzyRecon v6.0 Architecture — Safe Autonomy, Normalized Output, and Traceability

## Overview

OzyRecon v6.0 ha evolucionado a un **headless reconnaissance engine** con contrato de runtime local explícito. Se especializa en reconocimiento controlado, correlación de activos, salida normalizada y trazabilidad de sesiones. La integración con la plataforma vive en el contrato del bridge, no en el runtime principal de este árbol.

---

## Runtime Surface

El runtime expone estos puntos de entrada:

1. `ozy.py` como entrypoint local canónico.
2. `cli/ozy.py` como wrapper de línea de comandos.
3. `src/core/api.py` como API FastAPI.
4. `src/export/normalizer.py` como contrato de salida normalizado.
5. `GET /sessions/{session_id}/trace` como superficie de trazabilidad.

La integración con Ozy Platform se define por `docs/BRIDGE_CONTRACT.md` y no por el runtime interno de este árbol.

---

## Los Pilares de OzyRecon v6.0

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
- `ScanResult` schema: JSON normalizado para consumo de plataforma y export local

### 9. Observability and Traceability
- `ScanContext` mantiene timeline de eventos
- `BaseMode` adjunta observability al envelope de salida
- `GET /sessions/{session_id}/trace` consolida scan, session, workflow, evidence y decisions

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

## API Endpoints (`src/core/api.py`)

| Endpoint | Método | Descripción |
|----------|--------|-------------|
| `/` | GET | Status y versión |
| `/intelligence/graph` | GET | Knowledge Graph (nodes + edges) |
| `/intelligence/status` | GET | Métricas del sistema de aprendizaje |
| `/intelligence/export` | GET | Exporta brain a .ozy |
| `/targets` | GET | Lista de targets conocidos |
| `/targets/{domain}/latest` | GET | Último scan normalizado |
| `/sessions/{session_id}/trace` | GET | Trazado consolidado de una sesión |
| `/gate/pending` | GET | Hipótesis pendientes de aprobación |
| `/gate/approve/{hyp_id}` | POST | Aprueba hipótesis |
| `/gate/reject/{hyp_id}` | POST | Rechaza hipótesis |
| `/evidence/{hyp_id}` | GET | Evidencia de una hipótesis |
| `/dashboard` | GET | Dashboard de inteligencia |

---

## Technical Flow: Evidence and Traceability

1. **Detection**: `HTTPValidator` o un validador equivalente produce un hallazgo o hipótesis.
2. **Gate**: La policy decide si puede ejecutarse o si requiere aprobación.
3. **Evidence**: `EvidenceEngine` registra evidencia ligada a la hipótesis.
4. **Trace**: `ScanContext` agrega eventos a su timeline y `BaseMode` adjunta el record observability.
5. **Replay**: `GET /sessions/{session_id}/trace` reconstruye la ejecución desde DB.

---

## Data Flow Pipeline (Platform Unified)

```
Target → Ozy Platform Orchestrator → OzyRecon Engine
                                          ↓
                              [STEALTH RECONNAISSANCE]
                                          ↓
                            [KNOWLEDGE GRAPH CORRELATION]
                                          ↓
                            [NORMALIZED TELEMETRY STREAM]
                                          ↓
                       Ozy Platform Data Layer (data/scans.json)
                                          ↓
                         Tactical HUD (Relationship Surface Map)
```

---

## Project Status

**Phase 3: The Phantom Blade** — current runtime baseline
**Phase 4: Safe Autonomy** — completed in this tree as review planning and non-exploitative correlation
**Phase 5: Harden Safety and Scope** — implemented in the runtime path
**Phase 6: Normalize Output and Contracts** — implemented through the shared mode envelope
**Phase 7: Observability and Traceability** — implemented through timeline + trace surfaces
**Phase 8: Documentation Alignment** — completed in this tree

**Classification**: Professional security validation and reconnaissance platform

**Validation**: focused contract, trace, and round-trip tests passing in the current tree

**Última actualización**: 26/04/2026 (Hardening closure)
