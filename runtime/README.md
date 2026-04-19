# Runtime

Este directorio contiene solo artefactos generados en ejecución.

## Estructura

- `db/`: base de datos SQLite persistente.
- `logs/`: logs longitudinales y auditoría.
- `scans/`: historial de scans por target y timestamp.
- `state/`: archivos pequeños de estado operativo.

## Política de retención

- Mantener `scans/` como histórico operativo, pero podar ejecuciones antiguas de forma regular.
- Recomendación:
  - conservar las últimas 5 ejecuciones por target;
  - archivar o borrar sesiones más viejas si el disco empieza a crecer;
  - no commitear este directorio.

## Limpieza sugerida

Usar `scripts/prune_scans.sh` para reducir el histórico local de `runtime/scans`.

## Verificación

Usar `make check-layout` para confirmar que `runtime/` conserva la estructura esperada y que no reaparecieron carpetas heredadas o sesiones con nombres inválidos.
