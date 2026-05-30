# Ozy Platform Master Roadmap

## Propósito

Construir una infraestructura modular de nivel `OzyRecon`, no una colección de repos sueltos.

La meta no es tener muchos proyectos. La meta es tener una plataforma coherente, con control plane central, contratos claros, datos canónicos, seguridad interna real, automatización segura, observabilidad operable y expansión controlada.

## Principios base

- `Ozy Platform` es el centro de mando.
- `OzyRecon` marca el estándar de calidad.
- Cada módulo debe nacer con contrato, tests, docs y demo.
- Ninguna capacidad crítica se duplica.
- Ningún motor decide por fuera de policy.
- Ningún dato importante vive sin evidence.
- Ninguna prioridad se calcula sin risk.
- Ninguna extensión entra sin verificación.
- Ninguna acción sensible corre sin sandbox o aprobación.
- Ningún cambio se considera listo sin PASS/FAIL.

## Visión de arquitectura

Ozy no debe verse como una lista de servicios. Debe verse como una plataforma en capas:

### 1. Control plane

- `Ozy Platform`
- `Ozy MCP`
- `Ozy Dashboard`
- `Ozy CLI/TUI`

### 2. Motores de dominio

- `OzyRecon`
- `Ozy Zero Trust`
- `OzyAudit`

### 3. Datos y decisión

- `Ozy Asset Inventory`
- `Ozy Findings Store`
- `Ozy Evidence Store`
- `Ozy Policy Engine`
- `Ozy Risk Engine`

### 4. Seguridad e integraciones internas

- `Ozy Secrets Vault`
- `Ozy API Registry`
- `Ozy Connector SDK`
- `Ozy Sandbox Runner`
- `Ozy Event Bus`

### 5. Operación y automatización

- `Ozy Workflow Engine`
- `Ozy Observability`
- `Ozy Report Studio`

### 6. Expansión controlada

- `Ozy Knowledge OS`
- `Ozy Marketplace`
- `Ozy Training Lab`
- `Ozy Compliance Hub`

## Orden correcto de construcción

### Fase A - Núcleo real

Construir primero el control plane y los motores base.

- `Ozy Platform`
- `OzyRecon`
- `Ozy Zero Trust`
- `OzyAudit`
- `Ozy MCP`
- `Ozy API Registry`

### Fase B - Datos y decisión

Convertir resultados en datos operativos reales.

- `Ozy Asset Inventory`
- `Ozy Findings Store`
- `Ozy Evidence Store`
- `Ozy Policy Engine`
- `Ozy Risk Engine`

### Fase C - Seguridad interna

Cerrar la superficie interna y definir cómo se integran módulos y secretos.

- `Ozy Secrets Vault`
- `Ozy Connector SDK`
- `Ozy Sandbox Runner`
- `Ozy Event Bus`

### Fase D - Operación

Automatizar, observar y presentar.

- `Ozy Workflow Engine`
- `Ozy Observability`
- `Ozy Report Studio`
- `Ozy Dashboard`
- `Ozy CLI/TUI`

### Fase E - Expansión controlada

Extender sin romper la base.

- `Ozy Knowledge OS`
- `Ozy Marketplace`
- `Ozy Training Lab`
- `Ozy Compliance Hub`

## Contrato de calidad por módulo

Cada módulo debe cumplir esto:

- `README.md` claro
- propósito explícito
- frontera de responsabilidad definida
- contratos de entrada/salida
- tests unitarios
- tests de integración si aplica
- demo mínima reproducible
- ejemplo de uso
- criterios PASS/FAIL
- observabilidad básica
- sin lógica duplicada
- sin secretos hardcodeados
- sin side effects no controlados

Si un módulo no puede pasar este estándar, todavía no está listo.

## Roles de cada módulo

### `Ozy Platform`

Control plane. Orquesta todo el ecosistema.

### `OzyRecon`

Descubre, valida y normaliza superficie y hallazgos.

### `Ozy Zero Trust`

Evalúa postura, control interno y condiciones de acceso o ejecución.

### `OzyAudit`

Conserva trazabilidad operacional, acciones y evidencia de proceso.

### `Ozy MCP`

Expone consultas y acciones controladas para agentes o usuarios.

### `Ozy API Registry`

Define qué fuentes externas, APIs, MCP servers o conectores están aprobados.

### `Ozy Asset Inventory`

Guarda la verdad canónica de activos conocidos.

### `Ozy Findings Store`

Guarda la verdad canónica de hallazgos normalizados.

### `Ozy Evidence Store`

Guarda evidencia verificable, con hash, metadatos y retención.

### `Ozy Policy Engine`

Decide si algo pasa, se avisa, falla o se bloquea.

### `Ozy Risk Engine`

Prioriza qué importa primero y por qué.

### `Ozy Secrets Vault`

Administra secretos, tokens y credenciales de forma segura.

### `Ozy Connector SDK`

Define cómo crear integraciones seguras y consistentes.

### `Ozy Sandbox Runner`

Ejecuta tareas sensibles de forma aislada y controlada.

### `Ozy Event Bus`

Transporta eventos internos y permite replay.

### `Ozy Workflow Engine`

Automatiza flujos seguros y repetibles.

### `Ozy Observability`

Monitorea salud, logs, métricas, alertas y trazas.

### `Ozy Report Studio`

Genera reportes ejecutivos, técnicos y de compliance.

### `Ozy Dashboard`

Ofrece operación visual de la plataforma.

### `Ozy CLI/TUI`

Permite operar la plataforma desde terminal.

### `Ozy Knowledge OS`

Acumula aprendizaje, conocimiento y contexto.

### `Ozy Marketplace`

Publica extensiones controladas y verificadas.

### `Ozy Training Lab`

Simula escenarios seguros para pruebas y demos.

### `Ozy Compliance Hub`

Mapea hallazgos y evidencia a marcos de cumplimiento.

## Estándar OzyRecon

Todo módulo debe acercarse al estándar de `OzyRecon` en:

- diseño claro
- dominio bien aislado
- evidencias trazables
- estructura hexagonal o modular cuando aplique
- contratos explícitos
- comportamiento reproducible
- documentación seria
- tests que realmente protejan el diseño

Ozy no se construye "más o menos". Se construye con la misma disciplina en cada capa.

## Diseño de repositorio por módulo

Cada módulo debería tener una estructura parecida a esta:

```text
module-name/
├── README.md
├── docs/
├── src/
├── tests/
├── contracts/
├── examples/
├── fixtures/
└── reports/
```

Si el módulo lo requiere:

```text
module-name/
├── adapters/
├── domain/
├── application/
├── infrastructure/
└── interfaces/
```

No todos los módulos necesitan la misma complejidad. Pero todos necesitan frontera clara.

## Contratos transversales

### Identidad

Todo proyecto, asset, finding, evidence y workflow debe poder relacionarse con:

- `project_id`
- `scope_id`
- `source_engine`
- `created_at`
- `updated_at`

### Evidencia

Todo hallazgo importante debe poder enlazarse con evidencia.

- hash
- origen
- integridad
- retención
- exportabilidad

### Policy

Toda acción sensible debe pasar por policy.

- `PASS`
- `WARN`
- `FAIL`
- `BLOCKED`

### Risk

Todo hallazgo y activo relevante debe poder priorizarse.

- score 0-100
- nivel contextual
- explicación legible

### Audit

Toda acción relevante debe dejar trazabilidad.

- quién
- qué
- cuándo
- por qué
- con qué resultado

### Events

Todo módulo importante debe emitir eventos de dominio.

- `asset.discovered`
- `finding.created`
- `evidence.created`
- `policy.decided`
- `risk.calculated`
- `workflow.started`
- `report.generated`

## Flujo objetivo de extremo a extremo

```text
Scope autorizado
↓
Ozy Platform
↓
Policy Engine
↓
OzyRecon + Ozy Zero Trust
↓
Asset Inventory + Findings Store
↓
Evidence Store + OzyAudit
↓
API Registry + Connector SDK
↓
Risk Engine
↓
Workflow Engine
↓
Report Studio
↓
Dashboard / CLI / MCP
↓
Usuario / auditor / equipo técnico
```

Ese flujo es el corazón de toda la plataforma.

## Fases de implementación

### Fase A

Núcleo operativo mínimo.

Objetivo:

- habilitar control real
- generar hallazgos base
- orquestar decisiones

### Fase B

Datos y decisión.

Objetivo:

- normalizar activos
- centralizar findings
- formalizar evidence
- priorizar con risk
- bloquear o permitir con policy

### Fase C

Seguridad interna.

Objetivo:

- secretos seguros
- conectores estándar
- sandbox de ejecución
- eventos internos

### Fase D

Operación y presentación.

Objetivo:

- automatizar workflows
- observar salud
- generar reportes
- operar por dashboard y CLI

### Fase E

Expansión controlada.

Objetivo:

- knowledge
- marketplace
- training
- compliance

## Gate de cierre por fase

Cada fase termina solo si cumple:

- módulos principales operativos
- contratos integrados
- tests pasando
- demo reproducible
- reporte de cierre
- checklist PASS/FAIL
- trazabilidad en audit
- sin deuda oculta en la capa nueva

## Definition of Done por módulo

Un módulo no se considera listo si le falta cualquiera de estos puntos:

- contrato definido
- responsabilidad única
- README completo
- pruebas reales
- ejemplos de uso
- integración con la plataforma
- observabilidad mínima
- decisión de diseño documentada
- reporte final de cierre

## Anti-patrones a evitar

- servicios por estética
- duplicar auth en cada repo
- duplicar stores por comodidad
- policy repartida en varios lados
- risk como cálculo informal
- evidence guardada después
- workflow sin control
- sandbox inexistente
- API Registry como lista basura
- dashboard sin contratos
- CLI con lógica duplicada
- marketplace sin verificación
- compliance sin evidence

## Orden de prioridad real

### Obligatorios

- `Ozy Platform`
- `Ozy Policy Engine`
- `Ozy Asset Inventory`
- `Ozy Findings Store`
- `Ozy Evidence Store`
- `Ozy Risk Engine`
- `OzyAudit`
- `Ozy Secrets Vault`
- `Ozy API Registry`
- `Ozy Connector SDK`
- `Ozy Sandbox Runner`

### Muy importantes

- `Ozy Event Bus`
- `Ozy Workflow Engine`
- `Ozy Observability`
- `Ozy Report Studio`
- `Ozy Dashboard`
- `Ozy CLI/TUI`
- `OzyRecon`
- `Ozy Zero Trust`
- `Ozy MCP`

### Opcionales

- `Ozy Knowledge OS`
- `Ozy Marketplace`

### Futuros

- `Ozy Training Lab`
- `Ozy Compliance Hub`

## Regla final

No estamos construyendo muchos proyectos. Estamos construyendo una plataforma seria.

Y una plataforma seria se reconoce porque:

- decide bien
- guarda bien
- prioriza bien
- audita bien
- opera bien
- se extiende bien
- y no se rompe cuando crece

Ese es el estándar.
