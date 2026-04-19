# Arquitectura de OzyRecon v3.0

## Visión General

OzyRecon es una plataforma de reconocimiento ofensivo local-first que se especializa en:
- Descubrimiento de superficie de ataque
- Detección de cambios entre escaneos
- Operación con sigilo (OPSEC-aware)
- Export normalizado para OzyAudit

## Arquitectura de 6 Pilares

### 1. Capa Agéntica (IA)
Orquestador inteligente con razonamiento contextual.

### 2. Memoria Táctica
Persistencia de sesiones y hallazgos entre ejecuciones.

### 3. Resiliencia Total
Fallback determinista cuando fallan las APIs de IA.

### 4. Auditoría Táctica
Logging estructurado de decisiones del agente.

### 5. OPSEC de Grado Militar
Jitter, rotación de User-Agents, Kill-Switch.

### 6. Aprendizaje Estadístico
Scoring dinámico configurable.

## Estructura de Directorios

```
src/
├── core/           # Config, logging, errors, context
├── opsec/          # Rate limiting, identity rotation, jitter, kill_switch
├── discovery/      # Subdomains, ports, fingerprinting
├── scanners/       # Nuclei, Dalfox, SQLMap, wrappers
├── storage/        # SQLite, models, queries, diff_engine
├── intelligence/   # Severity, deduplication, correlation
├── notifications/  # Telegram alerts
├── export/         # Normalized output, platform exporters
└── modes/          # hunt, continuous, campaign, research, forensic, servicio
```

## Flujo de Datos

1. **Input**: Target + Modo de operación
2. **Discovery**: Subdomain enumeration, port scanning
3. **Scanning**: Vulnerability detection
4. **Storage**: Persistencia en SQLite
5. **Intelligence**: Severity, deduplication
6. **Export**: JSON normalizado para OzyAudit

## Modos Operativos

| Modo | Descripción |
|------|-------------|
| HUNT | Caza agresiva en targets nuevos |
| CONTINUO | Monitoreo 24/7 con detección de cambios |
| CAMPAÑA | Escalado de patrones específicos |
| INVESTIGACIÓN | Búsqueda de CVEs |
| FORENSE | Análisis post-mortem |
| SERVICIO | Reportes ejecutivos |

## Integración con OzyAudit

OzyRecon produce un JSON normalizado que OzyAudit puede consumir:

```json
{
  "type": "scan-result",
  "source": "ozy-recon",
  "session_id": "abc123",
  "target": "example.com",
  "assets": [],
  "services": [],
  "findings": [],
  "diff": []
}
```