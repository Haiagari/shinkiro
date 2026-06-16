# OzyRecon Usage Guide

**Version**: 9.1.0  
**Last Updated**: 2026-06-16

---

## Quick Start

```bash
# Init + scope + hunt
python ozy.py init
python ozy.py scope add target.com
python ozy.py hunt target.com --steroids

# Full pipeline with all discovery modules
python ozy.py hunt target.com --steroids --depth 2 --autonomous
```

## Commands

### Reconnaissance

| Command | Descripción | Flags |
|---|---|---|
| `hunt <target>` | Full recon + nuevas fases (JS, permutaciones, params, S3, dorks) | `--steroids`, `--depth`, `--ghost`, `--autonomous`, `--intent` |
| `flow <target>` | Pipeline completo 5 fases | `--profile`, `--dry-run` |
| `continuous <target>` | Monitoreo diferencial | `--speed`, `--intent` |
| `research <target>` | Solo pasivo, sin active scanning | `--depth`, `--steroids` |
| `campaign <targets>` | Multi-target batch | `--threads`, `--speed` |
| `forensic <session>` | Enfocado en evidencia | `--intent`, `--depth` |

### Análisis

| Command | Descripción |
|---|---|
| `analyze <host>` | Análisis profundo IA de un asset |
| `diff <target>` | Compara últimos 2 scans |
| `inventory assets <target>` | Lista assets descubiertos |
| `paths <target>` | Enumeración de directorios/endpoints |
| `secrets <target>` | Busca secrets en JS |
| `export <target>` | Exporta findings a JSON/CSV |

### Gestión

| Command | Descripción |
|---|---|
| `scope add/remove/list` | Manejo de scope autorizado |
| `doctor` | Valida entorno completo |
| `init` | Inicializa config, DB, estructura |
| `serve` | API REST |

## Discovery Phases (Hunt --steroids)

Cuando corrés `ozy hunt target --steroids`, se ejecutan **15 fases**:

```
 1. Seed target
 2. Passive discovery (subfinder + assetfinder + amass recursivo)
 3. DNS brute-force (11k wordlist)
 4. Endpoint recon (gau + waybackurls)
 5. JS endpoint extraction ← NUEVO
 6. Subdomain permutations ← NUEVO
 7. Parameter discovery ← NUEVO
 8. S3 bucket scan ← NUEVO
 9. Google dorking ← NUEVO
10. Active resolution (httpx)
11. Service analysis (naabu + nmap)
12. Takeover detection (nuclei)
13. Autonomous tactical loop
14. Scoring & prioritization
15. Intelligence & reporting
```

### Opciones globales

```bash
--steroids           Activa JS extraction, permutaciones, params, S3, dorks
--depth INT          Profundidad de recursión en passive discovery (default: 1)
--intent passive|balanced|aggressive
--ghost              Rutear vía Tor
--autonomous         Loop táctico autónomo (default: true)
--threads INT        Workers paralelos
--speed slow|normal|fast
--dry-run            Solo muestra el plan, no ejecuta
--json               Output en JSON
```

## Output

```
runs/{session_id}/
├── js_endpoints/endpoints.json      ← Rutas extraídas de JS
├── discovered_params.json            ← Parámetros encontrados
├── s3_buckets.json                   ← Buckets S3 detectados
├── google_dorks.json                 ← Resultados de dorking
├── analysis.json                     ← Findings normalizados
├── analysis.md                       ← Reporte ejecutivo
└── audit_{hash}.tar.gz              ← Bundle de evidencia firmado
```
