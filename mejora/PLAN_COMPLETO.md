# Plan Completo de OzyRecon (HISTORICAL / ARCHIVED)

> **NOTA**: Este documento es un plan histórico. El baseline actual y operativo es **v8.3.2**.
> Para el estado actual, ver [`docs/STATUS.md`](../docs/STATUS.md).

Este documento define la arquitectura objetivo y el plan de trabajo para dejar `OzyRecon` como un motor completo, autonomo y consumible por `ozy-platform` sin llamadas falsas ni logica de motor duplicada en la plataforma.

## 1. Propósito

`OzyRecon` debe funcionar como un proyecto completo de reconnaissance y correlacion:

- discovery de assets
- correlacion de evidencias
- validacion segura
- trazabilidad de sesiones
- export normalizado
- health y verify real

La plataforma no debe reimplementar esa logica. Solo la debe consumir por contrato.

## 2. Principios

- Un solo runtime oficial.
- Un solo entrypoint oficial.
- Un solo contrato de salida.
- Cero placeholders en rutas productivas.
- Cero simulaciones en el camino del motor.
- Cero dependencia de la plataforma para la logica de negocio.

## 3. Estado actual resumido

Lo que ya existe y vale:

- `ozy.py` como wrapper estable.
- `cli/ozy.py` como CLI principal.
- `cli/commands/verify.py` como verificacion de capacidades y smoke.
- `src/core/api.py` como API runtime local.
- `src/export/normalizer.py` como export normalizado.
- `src/intelligence/orchestrator.py` como capa de aprobacion y validacion.
- `src/core/tool_manager.py` como resolutor de capacidades.

Lo que aun debe endurecerse:

- placeholders en rutas de autonomia y validacion.
- drift entre docs, runtime y compatibilidad externa.
- contrato de bridge que debe quedar totalmente explicito.
- uniformidad entre modos `hunt`, `research`, `continuous`, `campaign`, `forensic` y `servicio`.

## 4. Arquitectura objetivo

```text
Usuario
  -> CLI / API / verify
  -> Runtime local OzyRecon
  -> Capabilities / Workflow / Validation
  -> Normalized export
  -> Traces + evidence + storage
  -> Ozy Platform via bridge minimo
```

### Superficies oficiales

- `ozy.py`
- `cli/ozy.py`
- `src/core/api.py`
- `src/export/normalizer.py`
- `src/intelligence/orchestrator.py`
- `src/core/tool_manager.py`
- `docs/BRIDGE_CONTRACT.md`
- `docs/RUNTIME_CONTRACT.md`

## 5. Responsabilidades

### Motor

`OzyRecon` debe:

- ejecutar discovery real
- correlacionar evidencia
- normalizar resultados
- exponer trace de sesion
- verificar capacidades disponibles
- mantener OPSEC basico y controlado

### Bridge

El puente con `ozy-platform` debe:

- resolver entrypoint oficial
- pasar variables de entorno canonicas
- lanzar el runtime real
- capturar salida y errores
- validar el schema de salida
- mapear fallos tecnicos

### Plataforma

`ozy-platform` solo debe:

- seleccionar el motor
- validar compatibilidad
- invocar el runtime real
- normalizar y persistir el resultado

## 6. Contratos

### Entrada

La entrada al motor debe ser estable y legible:

- `target`
- `mode`
- `scan_id`
- `profile`
- `capabilities`
- `metadata`

### Salida

La salida debe ser canonica:

- `status`
- `session_id`
- `target`
- `mode`
- `contract_version`
- `result`

### Resultado normalizado

`ScanResult` debe seguir siendo la base de export:

- `session_id`
- `target`
- `mode`
- `assets`
- `services`
- `findings`
- `diff`
- `stats`
- `config`
- `errors`

## 7. Flujo de ejecucion

1. El usuario lanza una operacion desde CLI o API.
2. Se valida el entorno y la capacidad disponible.
3. El motor selecciona el modo y ejecuta el pipeline real.
4. Se recolecta evidencia, estado y resultados.
5. Se normaliza la salida.
6. Se expone el trace y el export final.
7. La plataforma consume ese resultado sin recrearlo.

## 8. Huecos a cerrar

- definir y congelar un manifiesto de compatibilidad unico.
- quitar placeholders de autonomia y validacion.
- unificar la experiencia entre modos.
- cerrar drift entre runtime real y docs historicas.
- asegurar que `verify` ejecute smoke real y no solo matriz de capacidades.
- estabilizar la ruta de entrada publica para que no haya dudas.

## 9. Plan por fases

### Fase 1 - Contrato

- congelar entrada/salida
- formalizar runtime contract
- formalizar bridge contract
- documentar variables de entorno

### Fase 2 - Limpieza de runtime

- retirar placeholders del camino principal
- dejar una sola ruta oficial de arranque
- separar legacy de production

### Fase 3 - Consolidacion de modos

- compartir pipeline comun cuando aplique
- evitar duplicacion de validacion
- mantener diferencias solo donde sean funcionales

### Fase 4 - Verificacion real

- smoke real por modo
- validacion de schema
- tests de contrato
- verificacion de health y trace

### Fase 5 - Operacion

- observabilidad completa
- docs sincronizadas
- salida estable para `ozy-platform`

## 10. Criterio de terminado

`OzyRecon` queda bien cuando:

- el runtime es unico y explicito
- el bridge no inventa logica
- la salida es normalizada y estable
- los placeholders dejaron de estar en el camino productivo
- la plataforma puede consumir el motor sin adivinar nada

