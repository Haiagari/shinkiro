# 🦉 OzyRecon v4.0

<p align="center">
  <img src="https://img.shields.io/badge/version-4.0.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10+-green" alt="Python">
  <img src="https://img.shields.io/badge/license-MIT-orange" alt="License">
</p>

**Local-first offensive reconnaissance and target intelligence platform.**

OzyRecon es una plataforma profesional de descubrimiento, enumeración y observación de cambios para Bug Bounty y auditorías de seguridad. Diseñada para operar con sigilo, aprender de cada sesión y proporcionar inteligencia procesable.

---

## ✨ Características Principales

| Pilar | Descripción |
|-------|-------------|
| 🧠 **Capa Agéntica** | Orquestador inteligente con razonamiento contextual |
| 💾 **Memoria Táctica** | Persistencia de sesiones y hallazgos entre ejecuciones |
| 🛡️ **Resiliencia Total** | Fallback determinista cuando fallan las APIs de IA |
| 📊 **Auditoría Táctica** | Logging estructurado de decisiones |
| 🥷 **OPSEC de Grado Militar** | Jitter, rotación de User-Agents, Kill-Switch |
| 📈 **Aprendizaje Estadístico** | Scoring dinámico configurable |

---

## 🎯 Modos Operativos

```
┌─────────────┬────────────────────────────────────────┐
│ Modo        │ Objetivo                               │
├─────────────┼────────────────────────────────────────┤
│ HUNT        │ Caza agresiva en targets nuevos        │
│ CONTINUO    │ Monitoreo 24/7 con detección de cambios│
│ CAMPAÑA     │ Escalado de patrones específicos       │
│ INVESTIGACIÓN│ Búsqueda de CVEs en superficie conocida│
│ FORENSE     │ Análisis post-mortem                   │
│ SERVICIO    │ Reportes ejecutivos para clientes      │
└─────────────┴────────────────────────────────────────┘
```

---

## 🚀 Inicio Rápido

```bash
# Clonar el repo
git clone https://github.com/SamBleed/OzyRecon.git
cd OzyRecon

# Instalar dependencias
make install

# Configurar (copiar config.example.yaml)
cp config/config.example.yaml config/config.yaml
# Editar config.yaml con tus API keys

# Modo Hunt - Caza agresiva
python3 src/cli/main.py hunt -t target.com

# Modo Continuo - Monitoreo
python3 src/cli/main.py continuous -t target.com

# CLI Interactiva
python3 agent.py
```

---

## 📂 Estructura del Proyecto

```
OzyRecon/
├── src/
│   ├── core/           # Config, logging, errors, context
│   ├── opsec/          # Rate limiting, identity rotation, jitter, kill_switch
│   ├── discovery/      # Subdomains, ports, fingerprinting
│   ├── scanners/       # Nuclei, Dalfox, wrappers
│   ├── storage/        # SQLite, models, queries, diff
│   ├── intelligence/   # Severity, deduplication, correlation
│   ├── notifications/  # Telegram alerts
│   ├── export/         # Normalized JSON, platform exporters
│   └── modes/          # hunt, continuous, campaign, research, forensic, servicio
├── config/             # Configuración, targets, scoring
├── docs/               # Documentación técnica
├── resources/          # Wordlists, templates
├── scripts/            # Utilidades
└── tests/              # Pruebas
```

---

## 🔧 Configuración

### config/config.yaml

```yaml
threads: 50
timeout: 10
rate_limit: 50

api_keys:
  shodan: ""        # Para reconocimiento de red
  virustotal: ""    # Para inteligencia de IPs

notifications:
  telegram_token: "TU_TOKEN"
  telegram_chat_id: "TU_CHAT_ID"
  alert_level: "medium"  # critical, high, medium, low, all

ai:
  gemini_api_key: ""  # Opcional - para análisis inteligente
  claude_api_key: ""
```

---

## 📖 Documentación

- [Arquitectura](docs/architecture.md) - Visión general del sistema
- [Modos Operativos](docs/modes.md) - Guía detallada de cada modo
- [OPSEC](docs/opsec.md) - Guía de seguridad operativa
- [Metodología](docs/METHODOLOGY.md) - Estándar de trabajo

---

## 🛡️ Uso Ético

> **IMPORTANTE**: Esta herramienta fue creada para Bug Hunting legal y auditorías autorizadas. El autor no se hace responsable por el mal uso de esta herramienta.

- ✅ Usar solo en programas donde tengas permiso
- ✅ Respetar rate limits y no Sobrecargar objetivos
- ✅ Verificar hallazgos antes de reportar
- ✅ No reportar sin validación manual

---

## 🤝 Contribuir

1. Fork el proyecto
2. Crear una rama (`git checkout -b feature/amazing`)
3. Commitear cambios (`git commit -m 'Add amazing feature'`)
4. Pushear (`git push origin feature/amazing`)
5. Abrir un Pull Request

---

## 📄 Licencia

MIT License - Ver [LICENSE](LICENSE) para más detalles.

---

## 🙏 Agradecimientos

- [ProjectDiscovery](https://github.com/projectdiscovery) - Herramientas ofensivas
- [SecLists](https://github.com/danielmiessler/SecLists) - Wordlists
- Comunidad de Bug Hunters

---

## ✅ Identidad del Proyecto

| Atributo | Valor |
|----------|-------|
| **Nombre** | OzyRecon |
| **Repositorio** | github.com/SamBleed/OzyRecon |
| **Tagline** | Local-first offensive reconnaissance and target intelligence platform |
| **Versión** | v4.0.0 |

---

<p align="center">
  <sub>Construido con ❤️ para la comunidad de Bug Hunters</sub>
</p>