# 🧠 OzyRecon v5.0 — Security Validation Platform

> **"OzyRecon reduces false positives and provides decision-grade security intelligence."**

<div align="center">

![OzyRecon Banner](./assets/banner.svg)

<br/>

![Stars](https://img.shields.io/github/stars/SamBleed/OzyRecon?style=for-the-badge&color=00ff88&labelColor=0a0f1a)
![Version](https://img.shields.io/badge/version-v5.0.0-00d4ff?style=for-the-badge&labelColor=0a0f1a)
![Python](https://img.shields.io/badge/Python-3.10+-ffd700?style=for-the-badge&logo=python&logoColor=ffd700&labelColor=0a0f1a)
</div>

# OzyRecon v5.0

OzyRecon es una **Plataforma de Validación de Seguridad (Security Validation Platform)** para ecosistemas DevSecOps y AppSec. Su misión no es solo "encontrar cosas", sino **validar riesgos de seguridad con evidencia auditada**, transformando el ruido técnico en inteligencia accionable para la toma de decisiones.

## 🔄 The Validation Pipeline

OzyRecon sigue un workflow riguroso para asegurar precisión quirúrgica:

**Discovery** → **Hypothesis** → **Approval (Human Gate)** → **Validation** → **Evidence** → **Report**

---

## 📑 Core Capabilities v5.0

### 1. Risk Classification Layer (New)
Cada hipótesis y hallazgo validado se clasifica según su impacto real de negocio:
- **🔴 HIGH**: Impacto directo (Exposición de datos, RCE, Crit-Vuln confirmada).
- **🟡 MEDIUM**: Impacto condicional (Requiere interacción o pre-condiciones).
- **🟢 LOW**: Informativo (Buenas prácticas, endurecimiento de superficie).

### 2. Assisted Offensive Validation
- **Zero Exploitation**: Validación sin intrusión ni payloads destructivos.
- **Human Gate**: Intervención manual obligatoria para autorizar probes (`ozy gate`).
- **Evidence Vault**: Cada validación incluye pruebas con integridad criptográfica (SHA256).

---

## 💻 Professional CLI Experience

```bash
# 1. Start an intelligent hunt
ozy hunt -t target.com

# 2. Review generated hypotheses
ozy gate list

# 3. Approve critical points
ozy gate approve --id hyp_8a2f --reason "Critical API endpoint"

# 4. Execute validation orchestrator
ozy validate

# 5. Generate executive report
ozy report
```

---

## 🛡️ Core Philosophy: NO EXPLOITATION
OzyRecon se posiciona como una herramienta de ingeniería de seguridad:
- **Surgical Validation**: Confirmamos la exposición, no la explotamos.
- **Audit Ready**: Trazabilidad total de cada acción y decisión.
- **Industry First**: Diseñado para escalar en equipos de AppSec profesionales.

**⚠️ WARNING: Use this tool only on systems you are authorized to test. Read the [DISCLAIMER.md](DISCLAIMER.md) before proceeding.**

## 📑 Core Capabilities v5.0

### 1. Assisted Offensive Validation (New)
A diferencia de los escáneres automáticos, OzyRecon v5.0 implementa un flujo controlado:
- **Hypothesis Generation:** El cerebro correlaciona señales y propone vectores de ataque específicos.
- **Human Gate:** Intervención manual obligatoria para autorizar validaciones sensibles (`ozy gate`).
- **Controlled Validation:** Ejecución de probes no destructivos para confirmar exposiciones sin causar impacto.

### 2. Evidence Engine & Reporting (New)
Trazabilidad total de cada acción del sistema:
- **Evidence Vault:** Cada hallazgo validado incluye pruebas (headers, respuestas) con hash SHA256.
- **Workflow State Machine:** Seguimiento del ciclo de vida: `DISCOVERED` → `HYPOTHESIZED` → `APPROVED` → `VALIDATED`.
- **Narrative Reports:** Generación de reportes Markdown pro que conectan la señal con la evidencia.

### 3. Adaptive Intelligence Layer
- **Dynamic Scoring:** Ajusta prioridades basadas en reputación, novedad y señales de cambio.
- **Closed-Loop Learning:** Mejora la precisión aprendiendo de las aprobaciones/rechazos del usuario.
- **Decision Tracking:** Registro forense de por qué se tomó cada decisión operativa.

---

## 🚀 Uso de la v5.0 (Workflow Recomendado)

### 1. Descubrimiento e Inteligencia (HUNT)
Genera la superficie y las hipótesis iniciales.
```bash
python3 -m ozy hunt -t example.com
```

### 2. Revisión Humana (Human Gate)
Lista las hipótesis generadas y decide cuáles validar.
```bash
# Listar hipótesis pendientes
python3 -m ozy gate list

# Aprobar una hipótesis para validación
python3 -m ozy gate approve --id <HYP_ID>
```

### 3. Ejecución de Validación
Lanza el orquestador para procesar las autorizaciones.
```bash
python3 -m ozy validate
```

### 4. Reporte y Evidencia
Visualiza los hallazgos confirmados y genera el reporte final.
```bash
python3 -m ozy report
python3 -m ozy export --format md
```

---

## 📂 Estructura del Proyecto v5.0

```
OzyRecon/
├── src/
│   ├── core/           # Providers & Swarm Manager
│   ├── intelligence/   # Cerebral Core & Correlation
│   ├── gate/           # Human-in-the-loop (NEW)
│   ├── validation/     # Surgical Probes (NEW)
│   ├── evidence/       # Integrity Vault (NEW)
│   ├── workflow/       # State Machine (NEW)
│   ├── reporting/      # Narrative Engines (NEW)
│   └── modes/          # Operational Intents
```

---

**OzyRecon: Controlled Intelligence, Verifiable Evidence.** 🚀  
*Construido para profesionales que exigen control, precisión y rigor técnico.*
