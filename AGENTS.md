# AGENTS.md - Coding Standards for OzyRecon

## Hard Rules (Obligatorias)
- **Python 3.11+**: Usar características modernas del lenguaje.
- **Tipado Fuerte**: Usar siempre type hints (`typing`) en firmas de métodos y funciones.
- **Inmutabilidad en el Dominio**: Usar `dataclass(frozen=True)` para los modelos de dominio.
- **Funciones Concisas**: Mantener las funciones cortas (idealmente < 30 líneas) con una única responsabilidad.
- **Docstrings**: Toda función o clase pública debe tener su respectivo docstring (formato Google o Sphinx).
- **Asincronismo**: Usar `async/await` únicamente para operaciones de I/O (ej. FastAPI, peticiones de red). El dominio puro debe ser síncrono.
- **Testing**: Los tests deben ubicarse en la carpeta `tests/` y usar `pytest`. Archivos con prefijo `test_*.py`.

## Project Standards (Arquitectura)
- **Arquitectura Hexagonal / Clean Architecture**: Mantener la estricta separación de responsabilidades.
  - `src/domain/`: Lógica de negocio pura e inmutabilidad. Sin dependencias externas.
  - `src/application/` y `src/core/`: Casos de uso y orquestación.
  - `src/adapters/`: Integraciones con el mundo exterior (bases de datos, Nmap, Subfinder, etc.).
- **Composición sobre Herencia**: Preferir inyectar dependencias y componer comportamientos en lugar de heredar.
- **Bajo Acoplamiento**: Los módulos no deben conocer la implementación interna de otros módulos.

## Strict TDD (Cuando aplique)
- Cuando se agregue o modifique lógica con tests existentes:
  - Seguir el ciclo **Red → Green → Refactor**.
  - El commit debe mostrar evidencia clara de que los tests pasaron (ej. captura o log de `pytest`).
- No es obligatorio en cambios muy pequeños (UI, config, docs), pero sí en la lógica core/dominio.

## Review Guidelines
- El código debe ser fácil de entender sin necesidad de leer todo el historial.
- Preferir cambios pequeños y atómicos (work units).
- Si el cambio es grande, usar **SDD (Spec-Driven Development)** antes de escribir código.