# 🚀 Trayecto del Proyecto

## Visión Original

Crear una plataforma de reconocimiento continuo e inteligente, comparable a Shodan Monitor, Attack Surface Management de CrowdStrike, o Recon.dev.

La diferencia con herramientas existentes como reconftw o axiom: **inteligencia real** - los módulos se retroalimentan, el sistema aprende, y el análisis no para entre sesiones.

---

## Evolución Real del Proyecto

### Fase 1: Fundación
- Estructura base del framework
- Módulos individuales: recon, ports, crawler, vuln
- Logging profesional
- Persistencia en JSON

### Fase 2: Inteligencia
- Scoring CVSS automático
- Correlación entre fases
- Detección IDOR
- Análisis JS (secretos + endpoints)

### Fase 3: Automatización
- Scheduler 24/7 con modos daemon/watch/diff
- Motor de Diff para detectar cambios
- Alertas Telegram inteligentes

### Fase 4: Interfaces
- API REST con FastAPI
- Dashboard web con Tailwind CSS
- Endpoints para scans y hallazgos

### Fase 5: IA
- Integración con Claude/Gemini
- PoC automático
- Generación de hipótesis

### Fase 6: Enhancements
- Fuzzing contextual
- WAF Detection
- Rate Limiting automático
- Multi-platform reports

### Fase 7: Setup
- Scripts `scripts/setup.sh` y `scripts/run.sh`
- Herramientas Go locales (382MB)
- Documentación completa

### Fase 8: Offensive Validation (v5.7)
- **Knowledge Graph**: Decision-making tool to visualize correlations and risk context.
- **Visual Evidence**: Screenshots for proof of exposure without impact.
- **Auth Exposure**: Non-intrusive validation of credential leaks.
- **Human-in-the-loop**: Consolidation of the Human Gate via Web Dashboard.

---

## Lecciones Aprendidas

1. **No reinventar la rueda** - Usar tools existentes (ProjectDiscovery) en vez de reescribir
2. **Modoularidad** - Cada módulo independiente facilita debugging
3. **Fallbacks** - Siempre tener alternativas cuando falta una tool
4. **Entorno local** - Tools en carpeta local evita ensuciar sistema
5. **Calidad > Cantidad** - Mejor un framework que funciona que 100 features rotas

---

## Estado Actual

**✅ v5.7 COMPLETA**

- 22 módulos Python (incluyendo validadores especializados)
- 6 herramientas Go preinstaladas
- Motor de Inteligencia & Human Gate Dashboard
- Visual Evidence Engine
- Listo para operaciones de alto nivel

---

## Siguientes Pasos (v6.0)

- Docker-compose para ambiente completo
- Tests automatizados
- Dashboard con gráficos en tiempo real
- Integración con más plataformas (Intigriti, YesWeHack)
- Módulo de brute force automático

---

**Fecha de release:** 17/04/2026
**Mantenedor:** SamBleed
**Licencia:** MIT
