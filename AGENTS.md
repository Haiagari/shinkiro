# Coding Standards for OzyRecon

## Hard Rules
- **Python 3.11+**: Use modern language features.
- **Strong Typing**: Always use type hints (`typing`) in function and method signatures.
- **Domain Immutability**: Use `dataclass(frozen=True)` for domain models.
- **Concise Functions**: Keep functions short (ideally < 30 lines) with a single responsibility.
- **Docstrings**: Every public function or class must have a docstring (Google or Sphinx format).
- **Async**: Use `async/await` only for I/O operations (e.g., FastAPI, network requests). Pure domain logic must be synchronous.
- **Testing**: Tests go in `tests/` using `pytest`. Files prefixed with `test_*.py`.

## Project Architecture
- **Hexagonal / Clean Architecture**: Maintain strict separation of concerns.
  - `src/domain/`: Pure business logic, immutable, no external dependencies.
  - `src/application/` and `src/core/`: Use cases and orchestration.
  - `src/adapters/`: External integrations (databases, Nmap, Subfinder, etc.).
- **Composition over Inheritance**: Prefer dependency injection and composition.
- **Low Coupling**: Modules must not know each other's internal implementations.

## Strict TDD (When Applicable)
- When adding or modifying logic with existing tests:
  - Follow **Red → Green → Refactor** cycle.
  - Commits must show clear evidence tests pass (e.g., pytest log or screenshot).
- Not mandatory for small changes (UI, config, docs), but required for core/domain logic.

## Review Guidelines
- Code must be understandable without reading the full history.
- Prefer small, atomic changes (work units).
- For large changes, use **SDD (Spec-Driven Development)** before writing code.
