# Arquitectura de OzyRecon v5.0 — Assisted Offensive Validation

## Visión General

OzyRecon v5.0 ha pasado de ser un motor de inteligencia a una **Plataforma de Validación Ofensiva Asistida**. Se especializa en:
- Descubrimiento de superficie de ataque inteligente.
- Generación de hipótesis de ataque basadas en correlación.
- **Human-in-the-loop**: Control humano obligatorio para acciones sensibles.
- **Validación Quirúrgica**: Probes controlados para confirmar hallazgos sin impacto.
- **Evidence Vault**: Recolección de evidencia con integridad criptográfica (SHA256).

## Diferencia Clave: Plataforma vs Wrapper

| Wrapper | OzyRecon (Plataforma) |
|---------|----------------------|
| Ejecuta herramientas | Toma decisiones basadas en estado |
| Sin memoria | Persiste reputation, WAF, hallazgos |
| Pipeline fijo | Reacciona al delta automáticamente |
| Output heterogéneo | Schema normalizado único |
| Sin intelgiencia | Genera IntelligenceBrief |

## Arquitectura de 12 Pilares (Evolucionada)

### 1-8. Pilares Legacy (HUNT, Intelligence, OPSEC, etc.)
Se mantienen intactos como base de datos y descubrimiento.

### 9. Human Gate (NEW)
Introduce puntos de decisión críticos. El sistema propone, el humano dispone.
- `ozy gate list`: Revisión de hipótesis.
- `ozy gate approve`: Autorización de ejecución.

### 10. Validation Layer (NEW)
Módulo de ejecución de probes controlados.
- `web.py`, `http.py`, `cms.py`: Validadores específicos por tipo de hipótesis.

### 11. Evidence Engine (NEW)
Guardian de la integridad técnica.
- Almacena respuestas raw, headers y metadatos asociados a cada validación.
- Genera hashes SHA256 para asegurar la cadena de custodia de la prueba.

### 12. Workflow State Machine (NEW)
Maneja el ciclo de vida de cada activo y sospecha:
`DISCOVERED` → `ANALYZED` → `HYPOTHESIZED` → `PENDING_APPROVAL` → `APPROVED` → `VALIDATING` → `VALIDATED` → `REPORTED`.

## Estructura de Directorios v5.0

```
src/
├── gate/           # Human Gate Manager (NEW)
├── validation/     # Surgical Validators (NEW)
├── evidence/       # Integrity Vault & Evidence Engine (NEW)
├── workflow/       # State Machine & Orchestrator (NEW)
├── reporting/      # Narrative Report Engine (NEW)
├── intelligence/   # Cerebral Core & Correlation
├── core/           # Tool Manager & Providers
├── modes/          # Operational Intents
├── storage/        # Persistence & SQL Models
└── opsec/          # Stealth & Protection Layer
```

## Flujo de Datos v5.0

```
Input → Discovery → Intelligence (Correlate)
                     ↓
             [HYPOTHESIS GENERATED]
                     ↓
               [HUMAN GATE] <─── Operador decide (Approve/Reject)
                     ↓
            [VALIDATION LAYER] ───> Probes controlados
                     ↓
             [EVIDENCE ENGINE] ───> Registro con Integridad (SHA256)
                     ↓
              [REPORT ENGINE] ───> Reporte Narrativo MD/JSON
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

## Modos: Intención Operativa v5.0

| Modo | Intención | Discovery | Scan | Validación | Reacción |
|------|----------|----------|------|------------|----------|
| **HUNT** | Exhaustivo | all_providers | full | Manual (Gate) | Línea base + Hypo |
| **CONTINUOUS** | Diferencial | pasivo | ligero | Auto (Low risk) | Lo nuevo |
| **RESEARCH** | Quirúrgico | memoria | tags/CVE | Directa | Directed |

## Estado del Proyecto
**Fase 2: Assisted Validation completada ✅**
**Clasificación**: Plataforma de validación ofensiva controlada, auditable y DevSecOps-ready.
