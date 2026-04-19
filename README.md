# 🚀 OzyRecon v3.0

**Local-first offensive reconnaissance and target intelligence platform.**

Plataforma profesional de descubrimiento, enumeración y observación de cambios para Bug Bounty y auditorías de seguridad.

---

## 🏛️ Arquitectura de 6 Pilares

1. **🧠 Capa Agéntica (IA):** Orquestador inteligente con razonamiento contextual
2. **💾 Memoria Táctica:** Persistencia de sesiones y hallazgos entre ejecuciones
3. **🛡️ Resiliencia Total:** Fallback determinista cuando fallan las APIs de IA
4. **📊 Auditoría Táctica:** Logging estructurado de decisiones del agente
5. **🥷 OPSEC de Grado Militar:** Jitter, rotación de User-Agents, Kill-Switch
6. **📈 Aprendizaje Estadístico:** Scoring dinámico configurable

---

## 🎯Qué es OzyRecon

**OzyRecon** es el motor ofensivo de descubrimiento e inteligencia de tu arsenal de seguridad.

- Encuentra y mapea superficie de ataque
- Detecta cambios entre escaneos (diff engine)
- Persiste sesiones y evidencias
- Opera con sigilo (OPSEC-aware)
- Exporta resultados normalizados para análisis externo

> **OzyRecon encuentra y organiza. OzyAudit interpreta.**

---

## 🕹️ Modos Operativos

| Modo | Descripción |
|:-----|:------------|
| **HUNT** | Caza agresiva en targets nuevos para llegar primero al lead |
| **CONTINUO** | Centinela 24/7. Analiza deltas antes de alertar |
| **SERVICIO** | Reportes ejecutivos para clientes |
| **CAMPAÑA** | Escalado de patrones específicos sobre base histórica |
| **INVESTIGACIÓN** | Búsqueda quirúrgica de CVEs en superficie conocida |
| **FORENSE** | Análisis post-mortem de brechas de detección |

---

## 🚀 Inicio Rápido

```bash
# 1. Configurar APIs en config/config.yaml
# 2. Ejecutar modo Hunt
python3 src/cli/main.py hunt -t target.com

# 3. Modo continuo
python3 src/cli/main.py continuous -t target.com

# 4. CLI interactiva
python3 agent.py scan target.com --full
```

---

## 📦 Estructura del Proyecto

```
OzyRecon/
├── src/
│   ├── cli/               # Interfaz de línea de comandos
│   ├── core/              # Logging, config, errors, context
│   ├── opsec/             # Rate limiting, identity rotation, jitter, waf, kill_switch
│   ├── discovery/         # Subdomains, puertos, fingerprinting
│   ├── scanners/          # Nuclei, Dalfox, SQLMap, fuzzing
│   ├── storage/           # SQLite, diff engine, session store
│   ├── intelligence/      # Severity, correlación, deduplicación
│   ├── notifications/     # Telegram alerts
│   ├── export/            # Normalized output, H1, Bugcrowd
│   └── modes/             # hunt, continuous, campaign, research, forensic
├── config/                # Configuración, targets, scoring
├── docs/                  # Metodología, arquitectura, roadmap
├── resources/             # Wordlists, templates
├── scripts/               # Utilidades
└── tests/                 # Pruebas unitarias e integración
```

---

## 🛡️ Uso Ético

Esta herramienta fue creada para Bug Hunting legal y auditorías autorizadas. El autor no se hace responsable por el mal uso de esta herramienta. **Caza con responsabilidad.**

---

## 🧹 Utilidades

```bash
# Limpiar scans antiguos (conserva últimos 5 por target)
./scripts/prune_scans.sh 5

# Validar estructura del repo
make check-layout
```

---

## 📄 Licencia

MIT License - Uso autorizado únicamente.

---

**OzyRecon** - *Encuentra. Persiste. Exporta.*