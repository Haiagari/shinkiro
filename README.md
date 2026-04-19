# 🧠 OzyRecon v4.0

<div align="center">

![OzyRecon Banner](./assets/banner.svg)

<br/>

![Stars](https://img.shields.io/github/stars/SamBleed/OzyRecon?style=for-the-badge&color=00ff88&labelColor=0a0f1a)
![Version](https://img.shields.io/badge/version-v4.0.0-00d4ff?style=for-the-badge&labelColor=0a0f1a)
![Python](https://img.shields.io/badge/Python-3.10+-ffd700?style=for-the-badge&logo=python&logoColor=ffd700&labelColor=0a0f1a)
![Status](https://img.shields.io/badge/Fase-2_Reflexiva-ff00ff?style=for-the-badge&labelColor=0a0f1a)
![OPSEC](https://img.shields.io/badge/OPSEC-Grade%20A-00ff88?style=for-the-badge&labelColor=0a0f1a)

<br/>

**OzyRecon es una plataforma de reconocimiento ofensivo stateful, OPSEC-aware y self-improving, diseñada para convertir señales técnicas en inteligencia accionable y mejorar su criterio con cada ciclo operativo.**

[🚀 Inicio rápido](#-inicio-rápido) · [🏗️ Arquitectura](#-arquitectura-reflexiva) · [🎯 Modos](#-modos-operativos) · [📊 Dashboard](#-intelligencedashboard)

</div>

---

## 🚀 ¿Qué es OzyRecon?

OzyRecon no es un simple wrapper de herramientas. Es un sistema de **inteligencia ofensiva** con aprendizaje adaptativo y evaluación reflexiva. A diferencia de otros frameworks, OzyRecon no solo ejecuta, sino que **aprende de sus propios aciertos y errores en tiempo real**.

### 🧠 El Salto Cognitivo
- **Recuerda**: Mantiene memoria histórica de activos, reputación de hosts y protecciones detectadas.
- **Decide**: Prioriza objetivos basándose en probabilidad de éxito histórica.
- **Reacciona**: Dispara investigaciones automáticas ante cambios de versión o nuevos activos.
- **Reflexiona**: Evalúa el resultado de cada decisión y recalibra su modelo de scoring (Feedback Loop).

---

## 🏗️ Arquitectura Reflexiva (Fase 2)

OzyRecon implementa un ciclo de aprendizaje cerrado (Closed-Loop Learning):

1. **DecisionLog**: Cada acción (priorizar host, disparar scan) se registra con su contexto y motivo.
2. **OutcomeEvaluator**: Clasifica los resultados (CRITICAL, SUCCESS, NEUTRAL, FAILURE) según el valor encontrado.
3. **FeedbackEngine**: Ajusta dinámicamente los pesos de scoring (`reputation`, `novelty`, `diff`) para optimizar futuros scans.
4. **FalsePositiveMemory**: Aprende a identificar y omitir patrones ruidosos para reducir el tiempo de escaneo.

---

## 🎯 Modos Operativos

| Modo | Intención Operativa | Acción Diferencial |
|------|--------------------|--------------------|
| 🏹 `HUNT` | **Exhaustiva** | Establece línea base profunda |
| 🔄 `CONTINUO` | **Diferencial** | Reacciona al delta (solo novedades) |
| 🔍 `RESEARCH` | **Quirúrgica** | Dirigido por Tech Stack / CVE |
| 📢 `CAMPAÑA` | **Escala** | Aplica patrones masivos en todo el scope |
| 🔬 `FORENSE` | **Histórica** | Análisis de regresión y brechas |
| 📋 `SERVICIO` | **Reporte** | OzyRecon como microservicio / API |

---

## 📊 IntelligenceDashboard

OzyRecon ofrece transparencia total sobre su proceso de aprendizaje. El dashboard permite auditar la efectividad del agente:

```bash
ozy dashboard
```

### Métricas de Élite:
- **Decision Accuracy Rate**: % de decisiones que produjeron hallazgos valiosos.
- **Signal-to-Noise Ratio**: Relación entre vulnerabilidades reales y ruido técnico.
- **Weight Evolution**: Trazabilidad de cómo el sistema ajustó sus criterios de prioridad.
- **Top Decisiones**: Explicabilidad de los mayores aciertos y fracasos operativos.

---

## 🥷 OPSEC de Grado Militar

- **WAF Detection**: Pre-flight check para detectar protecciones y ajustar agresividad.
- **Adaptive Rate Limiting**: Reducción automática de RPM ante respuestas 403/429.
- **Kill-Switch**: Freno de mano automático si la reputación de la IP está en riesgo.
- **Native Jitter**: Retrasos aleatorios inteligentes para evadir detección de patrones.

---

## 🚀 Inicio Rápido

```bash
# 1. Clonar e instalar
git clone https://github.com/SamBleed/OzyRecon.git
cd OzyRecon
make install

# 2. Configurar (config/config.yaml)
# Añade tus API keys de Shodan, Gemini/Claude, etc.

# 3. Lanzar primer HUNT (Línea de base)
ozy hunt -t example.com

# 4. Iniciar monitoreo inteligente
ozy continuous -t example.com
```

---

## 📂 Estructura del Proyecto

```
OzyRecon/
├── src/
│   ├── core/           # Capabilities & Providers
│   ├── modes/          # Operational Intent (Hunt, Continuous...)
│   ├── storage/        # Persistence & DiffEngine
│   ├── intelligence/   # Learning, Decisions & Dashboard
│   ├── opsec/          # Adaptive Stealth Layer
│   └── export/         # Normalized ScanResult Output
```

---

**OzyRecon: Intelligence, not just results.** 🚀  
*Construido para investigadores que valoran el tiempo y la precisión.*
