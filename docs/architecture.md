# Arquitectura de OzyRecon v4.0

## Visión General

OzyRecon es una **plataforma de reconocimiento ofensivo local-first** que se especializa en:
- Descubrimiento de superficie de ataque
- Detección de cambios entre escaneos (Diff Engine reactivo)
- Inteligencia adaptativa basada en memoria
- OPSEC de grado militar
- Export normalizado para OzyAudit

## Diferencia Clave: Plataforma vs Wrapper

| Wrapper | OzyRecon (Plataforma) |
|---------|----------------------|
| Ejecuta herramientas | Toma decisiones basadas en estado |
| Sin memoria | Persiste reputation, WAF, hallazgos |
| Pipeline fijo | Reacciona al delta automáticamente |
| Output heterogéneo | Schema normalizado único |
| Sin intelgiencia | Genera IntelligenceBrief |

## Arquitectura de 8 Pilares

### 1. tool_manager + Capabilities
Abstracción de herramientas en capacidades lógicas:
- `asset_discovery`
- `service_discovery`
- `template_scan`
- `port_scan`

### 2. Modos Operativos (con intención distinta)
Cada modo tiene lógica diferente:
- **HUNT**: Ejecución exhaustiva, establece línea base
- **CONTINUOUS**: Monitoreo reactivo basado en delta
- **RESEARCH**: Escaneo dirigido por tecnología/CVE
- **CAMPAIGN**: Escalado de patrones
- **FORENSIC**: Análisis histórico
- **SERVICIO**: Reportes ejecutivos

### 3. Memoria Táctica
Persistencia de decisiones y aprendizajes:
- `AgentMemory` (razonamientos)
- `host_reputation` (historial de hallazgos)
- `waf_detected` (presencia de WAF)

### 4. Diff Engine Reactivo
Compara estados y dispara acciones:
- Detecta nuevos subdominios → Escanea
- Detecta cambios de versión → Investiga
- Detecta puertos cerrados → Limpia memoria

### 5. Priority Engine
Scoring dinámico basado en:
- Reputación histórica del host
- Novedad del activo
- Patrones detectados

### 6. OPSEC Integrado
Comportamiento adaptativo:
- Pre-flight WAF detection
- Rate adaptation automática
- Kill-switch automático

### 7. Inteligencia Generada
Output accionable (`IntelligenceBrief`):
- Surface delta %
- Nuevos endpoints críticos
- Patrones de vulnerabilidad
- Recomendaciones

### 8. Output Normalizado
Schema único (`ScanResult`):
- JSON para OzyAudit
- Markdown para clientes
- CSV para Excel
- Burp SAR para importar

## Estructura de Directorios

```
src/
├── core/
│   ├── tool_manager.py     # Orquestador de capacidades
│   ├── providers/       # Proveedores (Subfinder, Nuclei, Nmap, etc.)
│   └── config.py       # Configuración global
├── modes/
│   ├── base.py              # BaseMode (contrato)
│   ├── hunt.py             # Caza agresiva
│   ├── continuous.py       # Monitoreo reactivo
│   ├── research.py        # Investigación dirigida
│   ├── campaign.py      # Escalado
│   ├── forensic.py      # Análisis
│   └── servicio.py     # Reportes
├── storage/
│   ├── models.py       # SQLAlchemy models
│   ├── queries.py     # DBQueries
│   ├── diff.py        # DiffEngine
│   └── database.py  # SQLite
├── intelligence/
│   ├── priority.py    # PriorityEngine
│   ├── analyzer.py   # Severity + Deduplication
│   ├── brief.py      # IntelligenceBrief
│   └── enrichment.py # Tech detection
├── opsec/
│   ├── manager.py         # OPSECManager
│   ├── rate_limiter.py  # Rate adaptation
│   ├── waf_detector.py # WAF detection
│   ├── kill_switch.py  # Emergency stop
│   └── jitter.py     # Random delays
└── export/
    ├── schema.py      # ScanResult
    ├── normalizer.py # Exportador
    └── platforms.py # Bug Bounty platforms
```

## Flujo de Datos

```
Input → Modo → validation_preconditions
         ↓
    OPSEC (pre_flight_check) → Ajusta estrategia
         ↓
    Discovery (asset_discovery) → Subdomains
         ↓
    Priority (score_hosts) → Ordena por reputación
         ↓
    Service Discovery → Puertos/Servicios
         ↓
    Vulnerability Scan → Findings
         ↓
    Diff Engine (get_diff) → Detecta cambios
         ↓
    REACCIÓN AUTOMÁTICA → Escanea lo nuevo
         ↓
    Intelligence Brief → Recomendaciones
         ↓
    Export → ScanResult (JSON/MD/CSV/Burp)
```

## Modos: Intención Operativa

| Modo | Intención | Discovery | Scan | Reacción |
|------|----------|----------|------|---------|
| **HUNT** | Exhaustivo | all_providers | full | Ninguna (línea base) |
| **CONTINUOUS** | Diferencial | pasivo | ligero | Lo nuevo |
| **RESEARCH** | Quirúrgico | memoria | tags/CVE | directed |
| **CAMPAIGN** | Masivo | histórico | patrón | escalado |
| **FORENSIC** | Histórico | DB | análisis | N/A |
| **SERVICIO** | Reporte | DB | N/A | N/A |

## OPSEC: Comportamiento Adaptativo

```python
# Pre-flight
if waf_detected:
    threads = 10          # Reducido
    delay = 3            # Incrementado
    strategy = "stealth"

# Rate adaptation
if 403/429 responses > 10:
    rpm /= 2             # Reduce speed
if consecutive_errors > 50:
    kill_switch.trigger()  # Emergency stop
```

## Output: Schema Normalizado

```json
{
  "type": "scan-result",
  "source": "ozy-recon",
  "version": "4.0",
  "session_id": "abc123",
  "target": "example.com",
  "mode": "hunt",
  "timestamp": "2026-04-19T12:00:00Z",
  "assets": [...],
  "services": [...],
  "findings": [...],
  "diff": [...],
  "intelligence": {
    "surface_delta_pct": 15.2,
    "new_critical_endpoints": ["api.internal"],
    "recommendations": [...]
  }
}
```

## Fase 2: Aprendizaje Reflexivo (Próxima Iteración)

| Capa | Componente | Función |
|------|----------|---------|
| 1 | DecisionLog | Persistir decisiones |
| 2 | OutcomeEvaluator | Medir resultado |
| 3 | FeedbackEngine | Recalibrar scoring |
| 4 | FalsePositiveMemory | Aprender de ruido |

---

**Clasificación**: Sistema ofensivo basado en estado, con inteligencia adaptativa y ejecución reactiva.

**Estado**: Fase 1 completada ✅