# 🧠 OzyRecon v4.0

<div align="center">

![OzyRecon Banner](./assets/banner.svg)

<br/>

![Stars](https://img.shields.io/github/stars/SamBleed/bugbounty-framework?style=for-the-badge&color=00ff88&labelColor=0a0f1a)
![Version](https://img.shields.io/badge/version-v4.0.0-00d4ff?style=for-the-badge&labelColor=0a0f1a)
![Python](https://img.shields.io/badge/Python-3.10+-ffd700?style=for-the-badge&logo=python&logoColor=ffd700&labelColor=0a0f1a)
![Status](https://img.shields.io/badge/Fase-2_Reflexiva-ff00ff?style=for-the-badge&labelColor=0a0f1a)

<br/>

**OzyRecon es una plataforma de reconocimiento ofensivo stateful, OPSEC-aware y self-improving, diseñada para convertir señales técnicas en inteligencia accionable y mejorar su criterio con cada ciclo operativo.**

[🚀 Inicio rápido](#-inicio-rápido) · [📖 Documentación](#-documentación) · [🎯 Modos](#-modos-operativos) · [⚙️ Configuración](#️-configuración)

</div>

---

## 🚀 ¿Qué es OzyRecon?

OzyRecon no es un simple wrapper de herramientas. Es un sistema de inteligencia ofensiva con **aprendizaje adaptativo** y **evaluación reflexiva**. A diferencia de otros frameworks, OzyRecon:

1. **Recuerda**: Mantiene memoria histórica de activos, reputación y WAFs.
2. **Decide**: Prioriza objetivos y ajusta su estrategia de sigilo automáticamente.
3. **Reacciona**: Dispara acciones dirigidas basadas en cambios detectados.
4. **APRENDE**: Evalúa sus propias decisiones y ajusta su criterio para futuras sesiones.

---

## 🧩 Arquitectura Cognitiva (Fase 2)

OzyRecon implementa un ciclo de aprendizaje reflexivo completo:

- **DecisionLog**: Registro estructurado de cada acción con su contexto y motivo.
- **OutcomeEvaluator**: Clasificación automática de resultados (Success/Neutral/Failure).
- **FeedbackEngine**: Ajuste dinámico de pesos de scoring basado en aciertos históricos.
- **FalsePositiveMemory**: Identificación y omisión proactiva de patrones ruidosos.

---

## 🎯 Modos Operativos

| Modo | Intención | Discovery | Acción Diferencial |
|------|-----------|-----------|--------------------|
| 🏹 `HUNT` | Exhaustiva | All Providers | Establece línea base |
| 🔄 `CONTINUO` | Reactiva | Pasivo/Delta | Escanea solo novedades |
| 🔍 `RESEARCH` | Quirúrgica | Memoria | Dirigido por Tech/CVE |
| 📢 `CAMPAÑA` | Escala | Histórico | Aplica patrones masivos |
| 🔬 `FORENSE` | Análisis | DB | Historial de patrones |
| 📋 `SERVICIO` | Reporte | DB | Microservicio/API |

---

## ✨ Características Pro

### 🧠 Inteligencia Adaptativa
El **PriorityEngine** utiliza la reputación histórica y señales de novedad para ordenar la cola de escaneo, maximizando el "Value per Scan".

### 🥷 OPSEC de Grado Militar
El **OPSECManager** detecta protecciones (WAF) antes del scan y ajusta el **Rate Limiter adaptativo** en tiempo real ante señales de baneo (403/429).

### 📊 Inteligencia Accionable
Genera un **IntelligenceBrief** que resume no solo lo encontrado, sino el incremento de superficie, cambios críticos y recomendaciones tácticas.

---

## 🚀 Inicio Rápido

```bash
# Clonar repositorio
git clone https://github.com/SamBleed/OzyRecon.git
cd OzyRecon

# Instalar plataforma
make install

# Lanzar modo HUNT (Caza agresiva)
python3 src/cli/main.py hunt -t target.com

# Lanzar modo CONTINUOUS (Monitoreo diferencial)
python3 src/cli/main.py continuous -t target.com
```

---

## 📂 Estructura del Proyecto

```
OzyRecon/
├── src/
│   ├── core/           # Capabilities & Providers
│   ├── modes/          # Operational Intent
│   ├── storage/        # Persistence & DiffEngine
│   ├── intelligence/   # Learning & Decisions
│   ├── opsec/          # Adaptive Stealth
│   └── export/         # Normalized Output
```

---

## 📊 Demo (Fase 2)

```
$ ozy hunt -t target.com

[*] OzyRecon v4.0 — APRENDIZAJE REFLEXIVO
[*] OPSEC: WAF detectado (Cloudflare) → Strategy: STEALTH
──────────────────────────────────────────────────────
[+] Priority Engine: Priorizando 'api.target.com' (Reputación: 8.5)
[+] Discovery: 2 nuevos subdominios detectados
──────────────────────────────────────────────────────
[!] INTELLIGENCE BRIEF:
    → Superficie incrementada un 4.2%
    → Nuevo endpoint crítico: 'admin.dev.target.com'
    → Patrón detectado: 3x XSS en mismo controlador
──────────────────────────────────────────────────────
[+] Feedback: Decisión exitosa. Ajustando pesos de reputación (+0.1)
[+] Sesión guardada → memory.db
```

---

## 🛡️ Uso Ético

> **IMPORTANTE:** Esta herramienta fue creada para Bug Hunting legal y auditorías autorizadas únicamente.

- ✅ Usar solo en programas donde tengas permiso explícito
- ✅ Respetar rate limits — no saturar objetivos
- ✅ Verificar hallazgos manualmente antes de reportar
- ✅ Seguir los disclosure guidelines de cada programa
- ❌ No usar en targets sin autorización escrita

---

**OzyRecon: Intelligence, not just results.** 🚀
