# Modos Operativos de OzyRecon v5.0

## Overview

OzyRecon v5.0 introduce el concepto de **Assisted Validation** en sus modos operativos, transformando el output técnico en inteligencia accionable y verificada.

## Modo HUNT (Evolucionado)

**Objetivo**: Establecer una línea base inteligente y generar hipótesis de ataque para validación manual.

### Uso
```bash
python3 -m ozy hunt -t target.com
```

### Flujo v5.0
1. **Asset Discovery**: Enumeración total de subdominios y activos.
2. **Intelligence Correlation**: Cruce de puertos, servicios y tech stack.
3. **Hypothesis Generation**: El sistema propone vectores de ataque basados en la correlación.
4. **Human Gate**: Las hipótesis quedan en estado `PENDING_APPROVAL` esperando acción humana (`ozy gate`).
5. **Assisted Validation**: Solo las hipótesis aprobadas son validadas por el orquestador (`ozy validate`).

### Cuándo usarlo
- Target nuevo sin historial.
- Auditorías donde se requiere control total sobre el ruido generado.
- Escenarios de "Red Teaming" asistido.

---

## Modo CONTINUO

**Objetivo**: Monitoreo 24/7 con detección de cambios y auto-validación de bajo riesgo.

### Uso
```bash
python3 -m ozy continuous -t target.com
```

### Flujo v5.0
1. Escaneo diferencial periódico.
2. Detección de nuevos activos o cambios en servicios.
3. Auto-validación de hipótesis de bajo riesgo (ej: versiones expuestas).
4. Escalamiento al Human Gate para cambios críticos.

---

## Resumen de Capacidades v5.0

| Modo | Objetivo Primario | Validación | Control |
|------|-------------------|------------|---------|
| **HUNT** | Inteligencia Base | Manual (Gate) | Total |
| **CONTINUOUS** | Delta & Drift | Híbrida | Automático/Manual |
| **RESEARCH** | CVE & Explotación | Directa | Quirúrgico |
| **CAMPAIGN** | Patrones Masivos | Basada en Reglas | Centralizado |
| **SERVICIO** | Compliance & Reporte | Evidencia | Auditoría |
