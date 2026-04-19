# Metodología de Operación y Validación (v3.0)

Este documento define el estándar de trabajo para el uso de OzyRecon en entornos reales. El objetivo es maximizar el ROI del hunter minimizando el ruido y los riesgos legales.

## 1. El Ciclo de Vida de una Cacería
1.  **Reconocimiento Base (Manual/Scripts)**: Obtener el baseline de activos.
2.  **Validación de Scope**: Asegurar que cada host es parte del programa.
3.  **Inyección de Inteligencia (IA)**: El Agente decide dónde profundizar basándose en el tech stack y el historial.
4.  **Análisis de Recomendaciones**: Revisar el `next_recommended` para encadenar ataques quirúrgicos.

## 2. Los 4 KPIs del Run Real
Después de cada ejecución del Agente, debemos reportar:
- **Ratio de Recon**: Eficiencia del descubrimiento de activos.
- **Paso 1 (Confianza)**: Calidad del punto de entrada decidido por la IA.
- **Eficiencia de Pasos (Useful steps)**: Porcentaje de acciones que aportaron datos reales.
- **Coherencia Estratégica**: Alineación entre los hallazgos y la recomendación final.

## 3. Verificación de Hallazgos (Hallazgo != Bug)
Ningún hallazgo generado por la IA o los módulos es un bug hasta que se prueba manualmente.
- **Nuclei/Vuln matches**: Probar en Burp Repeater.
- **IDOR candidates**: Validar con dos cuentas de diferentes niveles.
- **Exposed Files**: Confirmar que no es un falso positivo del WAF (ej: 403 genérico).

## 4. Mejora del Sistema
Si el Agente toma una decisión incorrecta:
1.  Analizar el `agent_reasoning.log`.
2.  Verificar si el `tech_stack` detectado fue erróneo.
3.  Ajustar el prompt en `llm_router.py` o los pesos en `config/scoring.yaml`.

---
*La inteligencia artificial es el navegador, pero el humano es el piloto.*
