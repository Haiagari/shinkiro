# 🚀 BugBounty Automation Framework v2.3 (Validated Edition)

**Plataforma de elite con Agentes IA, Memoria Táctica y Protocolo de Validación Real.**

Este framework ha superado la etapa de laboratorio. Ahora es un sistema de caza profesional diseñado para operar con sigilo, aprender de cada sesión y proporcionar recomendaciones tácticas basadas en datos reales.

---

## 🏛️ Los 6 Pilares de Elite (Arquitectura Pro)

1.  **🧠 Capa Agentica (IA):** Orquestador inteligente que razona cada paso del ataque.
2.  **💾 Memoria Táctica (AgentMemory):** El sistema recuerda sus razonamientos previos, heredando conocimiento entre sesiones.
3.  **🛡️ Resiliencia Total (Deterministic Fallback):** Motor de reglas senior que toma el mando si las APIs de IA fallan. El bot nunca se detiene.
4.  **📊 Auditoría Táctica (Structured Logging):** Registro detallado en `agent_reasoning.log` del *por qué* de cada decisión.
5.  **🥷 OPSEC de Grado Militar:** Jitter aleatorio, rotación de User-Agents y Kill-Switch automático.
6.  **📈 Aprendizaje Estadístico:** Motor de scoring que optimiza el escaneo según el éxito histórico (via `config/scoring.yaml`).

---

## 🕹️ Modos Operativos Principales

| Modo | Objetivo |
|:-----|:---------|
| **🎯 HUNT** | Caza agresiva en targets nuevos para llegar primero al lead. |
| **👁️ CONTINUO** | Centinela 24/7. El Agente analiza deltas antes de alertar. |
| **💼 SERVICIO** | Traduce hallazgos técnicos a reportes ejecutivos para clientes. |
| **📊 CAMPAÑA** | Escala patrones específicos sobre toda la base de datos histórica. |
| **🔬 INVESTIGACIÓN**| Búsqueda quirúrgica de CVEs en superficie conocida. |
| **🕵️ FORENSE** | Análisis post-mortem de brechas de detección y auto-ajuste de scoring. |

---

## 🛡️ Protocolo de Ejecución Ética (Run Real)

Para garantizar la seguridad y reputación del hunter, seguimos este flujo en cada run nuevo:

1.  **Validación Manual de Reglas:** Leer los términos del programa en H1/Bugcrowd.
2.  **Foundation Check:** Correr fases manuales primero (`--recon`, `--ports`, `--urls`).
3.  **Delegación IA:** Lanzar el Agente (`--agent hunt`) solo cuando los datos base son sólidos.
4.  **Observación vs Caza:** El primer run es para validar el sistema. **No reportar inmediatamente**.
5.  **Verificación Manual:** Todo hallazgo de la IA debe ser validado en Burp Suite antes de cualquier acción.

---

## 🚀 Inicio Rápido

```bash
# 1. Configurar APIs y presupuesto en `config/config.yaml`
# 2. Validar foundation
python3 backend/main.py -t target.com --recon
# 3. Lanzar Agente con Memoria Táctica
python3 backend/main.py -t target.com --agent hunt
```

---

## 🛡️ Uso Ético
Este framework fue creado para Bug Hunting legal y auditorías autorizadas. El autor no se hace responsable por el mal uso de esta herramienta. **Caza con responsabilidad.**

---
---

## ✅ Run Real Completado (2026-04-17)

Primer scan real ejecutado contra target real:

| Métrica | Valor |
|---------|-------|
| Target | fya57cefop.edu.pe |
| Subdominios | 22 |
| Hosts vivos | 8 |
| Puertos | 77 |
| Findings | 2 |

### Findings reportados
- 🔴 **MySQL 3306 Expuesto a Internet** (CVSS 9.8) - CRÍTICO
- 🟡 **cPanel Accesible desde Internet** (CVSS 5.3) - MEDIO

---

## 🗂️ Estructura

- `backend/`: API, orquestador y scheduler.
- `config/`: configuración, targets y scoring.
- `cli/`: CLI interactiva estilo command center.
- `docs/`: documentación de proyecto.
- `resources/`: templates y wordlists reutilizables.
- `runtime/`: datos generados en ejecución.
- `scripts/`: utilidades operativas.
- `tests/`: checks y pruebas.
- `ui/`: componentes visuales de terminal.

## ⌨️ CLI / TUI

Lanzar la interfaz interactiva tipo command center:

```bash
python3 agent.py
```

Comandos útiles:

```bash
python3 agent.py scan target.com --full
python3 agent.py status
python3 agent.py overview
python3 agent.py targets
python3 agent.py focus target.com
python3 agent.py diff target.com
python3 agent.py export target.com --format md
python3 agent.py inspect target.com
python3 agent.py watch target.com
python3 agent.py history
python3 agent.py doctor
```

## 🧹 Limpieza

Si el historial crece demasiado:

```bash
./scripts/prune_scans.sh 5
```

Eso conserva las últimas 5 ejecuciones por target dentro de `runtime/scans/`.

Para validar que el layout del repo siga sano:

```bash
make check-layout
```

---

**Desarrollado por el equipo de Elite con ❤️ para la comunidad de Bug Hunters.**
