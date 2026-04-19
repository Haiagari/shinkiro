# Modos Operativos de OzyRecon

## Overview

OzyRecon tiene 6 modos operativos que cubren diferentes escenarios de reconocimiento ofensivo.

## Modo HUNT

**Objetivo**: Caza agresiva en targets nuevos para llegar primero al lead.

### Uso
```bash
python3 src/cli/main.py hunt -t target.com
python3 src/cli/main.py hunt -t target.com --threads 100 --dry-run
```

### Flujo
1. Descubrimiento de subdominios
2. Detección de hosts vivos
3. Escaneo de puertos
4. Fingerprinting
5. Detección de vulnerabilidades

### Cuándo usarlo
- Target nuevo sin historial
- Programas de bug bounty recién publicados
- Para encontrar bugs de día cero

---

## Modo CONTINUO

**Objetivo**: Monitoreo 24/7 con detección de cambios.

### Uso
```bash
python3 src/cli/main.py continuous -t target.com
python3 src/cli/main.py continuous -t target.com --interval 7200
```

### Flujo
1. Escaneo ligero periódico
2. Comparación con snapshot anterior
3. Detección de deltas
4. Alertas solo si hay cambios

### Cuándo usarlo
- Targets en programas activos
- Monitoreo de programas de largo plazo
- Detección de cambios en infraestructura

---

## Modo CAMPAÑA

**Objetivo**: Escalar un patrón específico sobre múltiples targets.

### Uso
```bash
python3 src/cli/main.py campaign -p CVE-2024-1234 -t target1.com target2.com
python3 src/cli/main.py campaign -p xss
```

### Flujo
1. Recibir patrón (CVE, template, tipo)
2. Aplicar sobre lista de targets
3. Recolectar resultados

### Cuándo usarlo
- Buscar una vulnerabilidad específica
- Aplicar nuevo template de Nuclei
- Auditoría masiva

---

## Modo INVESTIGACIÓN

**Objetivo**: Búsqueda quirúrgica de CVEs en superficie conocida.

### Uso
```bash
python3 src/cli/main.py research -t target.com
python3 src/cli/main.py research -t target.com --cve CVE-2024-1234
```

### Flujo
1. Obtener tech stack del target
2. Buscar CVEs relacionados
3. Verificar vulnerabilidad específica

### Cuándo usarlo
- Después de detectar tecnologías
- Para verificar CVEs específicos
- Investigación de amenazas

---

## Modo FORENSE

**Objetivo**: Análisis post-mortem de brechas de detección.

### Uso
```bash
python3 src/cli/main.py forensic -t target.com
```

### Flujo
1. Analizar historial de scans
2. Identificar patrones fallidos
3. Detectar brechas
4. Proponer ajustes de scoring

### Cuándo usarlo
- Después de falsos negativos
- Para mejorar configuración
- Análisis de cobertura

---

## Modo SERVICIO

**Objetivo**: Generar reportes ejecutivos para clientes.

### Uso
```bash
python3 src/cli/main.py servicio -t target.com --client "Empresa X"
```

### Flujo
1. Recolectar todos los hallazgos
2. Generar resumen ejecutivo
3. Crear reporte en Markdown/PDF

### Cuándo usarlo
- Entregas a clientes
- Reportes formales
- Documentación de auditorías

---

## Resumen

| Modo | Target | Frecuencia | Output |
|------|--------|------------|--------|
| HUNT | Nuevo | Una vez | Hallazgos |
| CONTINUO | Existente | Periódico | Deltas + alertas |
| CAMPAÑA | Múltiples | Bajo demanda | Hallazgos |
| INVESTIGACIÓN | Conocido | Bajo demanda | CVEs |
| FORENSE | Histórico | Ocasional | Recomendaciones |
| SERVICIO | Cliente | Por entrega | Reporte |