# ozy-entrypoint Design

## Overview
- **Change**: `ozy-entrypoint` - CLI Entry Point para OzyRecon
- **Type**: Infrastructure / CLI
- **Status**: DESIGN
- **Created**: 2026-04-26

## Goal
Crear el punto de entrada CLI de OzyRecon usando Click con Rich console, que:
1. Dispache a los módulos en `src/modes/` dinámicamente
2. Muestre un banner inicial con Rich
3. Asegure carga de configuración singleton ANTES de cualquier comando
4. Maneje excepciones globalmente con output limpio

---

## Technical Design

### 1. Estructura de `cli/ozy.py`

```
cli/
├── __init__.py           # Package marker
├── __main__.py          # python -m cli entry
├── ozy.py               # MAIN: Click group + global handlers
└── commands/
    ├── __init__.py
    ├── hunt.py
    ├── continuous.py
    ├── campaign.py
    ├── servicio.py
    ├── forensic.py
    ├── research.py
    └── discover.py
```

**`cli/ozy.py`** (main entry point):

```python
"""
OzyRecon CLI Entry Point
 Punto de entrada principal con Click + Rich console.
"""
import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from src.core.config import config as _config_singleton

# Console singleton para toda la aplicación
console = Console(rich=True)

# Banner inicial
BANNER = """
╔═══════════════════════════════════════════════════════════╗
║  OZYRECON v{version}                                      ║
║  Advanced Persistent Reconnaissance Platform            ║
║  [Phantom Blade Edition]                                ║
╚═══════════════════════════════════════════════════════════╝
"""

def get_banner():
    """Genera el banner con la versión actual."""
    from src import __version__ as VERSION
    banner = BANNER.format(version=VERSION)
    return Text(banner, style="cyan bold")


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """
    OzyRecon - Advanced Persistent Reconnaissance Platform.
    
    Uso: ozy <command> [options]
    
    Comandos disponibles:
      hunt, continuous, campaign, servicio, forensic, research, discover
    """
    # Mostrar banner solo si no hay subcomando (o con --help)
    if ctx.invoked_subcommand is None:
        console.print(get_banner())


# Import dinámico de comandos desde src/modes/
def register_mode_commands():
    """Registra automáticamente comandos desde src/modes/"""
    from pathlib import Path
    from importlib import import_module
    import pkgutil
    
    modes_path = Path(__file__).parent.parent / "src" / "modes"
    
    for importer, modname, ispkg in pkgutil.iter_modules([str(modes_path)]):
        if modname in ('base', '__pycache__'):
            continue
        
        # Import dinámico del módulo
        module = import_module(f"src.modes.{modname}")
        
        # Asumir que cada modo tiene un comando Click con el mismo nombre
        if hasattr(module, 'cli'):
            cli.add_command(module.cli, name=modname)


# Registrar comandos al inicio
register_mode_commands()


# Manejo global de excepciones
@cli.exception_handler
def handle_exception(ctx, exc):
    """Manejo centralizado de excepciones para output limpio."""
    from rich.errors import ConsoleError
    
    if isinstance(exc, click.ClickException):
        raise exc
    
    # Error desconocido: mostrar con Rich (sin traceback feo)
    console.print(f"\n[bold red]Error:[/bold red] {exc}")
    console.print_exception(show_locals=False, extra_lines=0)
    ctx.exit(1)
```

### 2. Mecanismo de Despacho a `src/modes/`

**Estrategia**: Descubrimiento dinámico en tiempo de importación.

```
┌─────────────────────────────────────────────────────────────┐
│  cli/ozy.py                                                │
│  ├── import src.core.config (CARGA PRIMERO)                  │
│  ├── register_mode_commands()                              │
│  │   ├── itera src/modes/ con pkgutil                    │
│  │   ├── importa dinámicamente cada modo                 │
│  │   └── cli.add_command(module.cli, name=modname)        │
│  └── Click routing: ozy <mode> → src.modes.<mode>.cli       │
└─────────────────────────────────────────────────────────────┘
```

**Cada `src/modes/*.py` EXPORTA**:
```python
# src/modes/hunt.py ejemplo
import click
from rich.console import Console

console = Console()

@click.command()
@click.argument('target')
@click.option('--threads', default=50, help='Hilos de ejecución')
def cli(target: str, threads: int):
    """Modo hunt: Escaneo activo de superficie de ataque."""
    from src.modes.hunt import HuntMode
    
    mode = HuntMode(target=target, options={'threads': threads})
    result = mode.run()
    console.print(f"[green]Completado:[/green] {result}")
```

### 3. Rich Console y Banner Inicial

**Console singleton**:
```python
# cli/ozy.py
from rich.console import Console
console = Console(rich=True, force_terminal=True)

# Banner con Rich
def get_banner():
    from src import __version__
    banner_text = f"""
╔═══════════════════════════════════════════════════════════╗
║  OZYRECON v{__version__}                                  ║
║  Advanced Persistent Reconnaissance Platform    ║
║  [Phantom Blade Edition]                        ║
╚═══════════════════════════════════════════════════╝
"""
    return Text(banner_text, style="cyan bold")
```

**Display**:
```
$ ozy

╔═══════════════════════════════════════════════════════════╗
║  OZYRECON v6.0.0-alpha.1                                ║
║  Advanced Persistent Reconnaissance Platform           ║
║  [Phantom Blade Edition]                                ║
╚═══════════════════════════════════════════════════════════╝

Usage: ozy <command> [options]
```

### 4. Singleton de Configuración (Carga anticipada)

**Patrón**: Import directo en el módulo CLI, NO lazy loading.

```python
# cli/ozy.py - LÍNEA 1
from src.core.config import config as _config_singleton  # SE CARGA AQUÍ

# Verificación inmediata
def verify_config_loaded():
    """Se ejecuta ANTES de cualquier comando."""
    if not config._config:
        console.print("[yellow]Advertencia: config.yaml no encontrado, usando defaults[/yellow]")
    return True
```

**Decorator de verificación**:
```python
def ensure_config_loaded(func):
    """Decorator que verifica config antes de ejecutar comando."""
    @click.pass_context
    def wrapper(ctx, *args, **kwargs):
        verify_config_loaded()
        return func(ctx, *args, **kwargs)
    return wrapper
```

### 5. Manejo de Excepciones Globales

**Solución**: Custom `exception_handler` en el Click group.

```python
@cli.exception_handler
def handle_exception(ctx, exc):
    """Manejo centralizado - NO muestra tracebacks feos."""
    from rich.console import Console
    
    console = Console()
    
    if isinstance(exc, click.ClickException):
        # Errores de Click (ayuda, argumentos inválidos)
        console.print(f"[red]{exc.message}[/red]")
        ctx.exit(exc.exit_code)
    
    # Otros errores: limpio con Rich
    console.print(f"\n[bold red]Error:[/bold red] {str(exc)}")
    
    # Traceback limpio (sin líneas extra, sin locals)
    console.print_exception(
        show_locals=False,
        extra_lines=0,
        max_width=console.width
    )
    
    ctx.exit(1)
```

**Output ejemplo**:
```
$ ozy hunt http://example.com

[cyan bold]╔═══════════════════════════════════════╗[/cyan bold]
[cyan bold]║  OZYRECON v6.0.0                    ║[/cyan bold]
[cyan bold]╚═══════════════════════════════════════╝[/cyan bold]

Error: Connection refused to http://example.com

Traceback (most recent call last):
  File "src/modes/hunt.py", line 45, in cli
    mode = HuntMode(target=target)
ConnectionRefusedError: [Errno 111] Connection refused
```

---

## Implementation Tasks

| # | Task | Phase |
|---|------|-------|
| 1.1 | Crear estructura `cli/` directorio | infra |
| 1.2 | Implementar `cli/ozy.py` con Click group y banner | infra |
| 1.3 | Implementar mecanismo de descubrimiento dinámico de modos | infra |
| 1.4 | Agregar exception handler con Rich console | infra |
| 1.5 | Crear `cli/__main__.py` (python -m cli) | infra |
| 1.6 | Actualizar `pyproject.toml` entry point | config |
| 1.7 | Verificar integración con `src.modes` existente | verify |
| 1.8 | Test: `python -m cli` y `ozy --help` | verify |

---

## Files to Modify

| File | Action |
|------|--------|
| `cli/__init__.py` | CREATE |
| `cli/ozy.py` | CREATE |
| `cli/__main__.py` | CREATE |
| `src/modes/base.py` | MODIFY: agregar `cli` Click command |
| `src/modes/hunt.py` | MODIFY: exportar `cli` Click command |
| `src/modes/continuous.py` | MODIFY: exportar `cli` Click command |
| `pyproject.toml` | MODIFY: entry point si es necesario |

---

## Architecture Decision Record

| ID | Decision | Rationale | Tradeoff |
|----|----------|----------|----------|
| ADR-001 | Descubrimiento dinámico de modos | Añadir nuevos modos sin modificar CLI | Coupling loose; debugging ligeramente más complejo |
| ADR-002 | Config cargada en import time | Garantiza disponibilidad antes de cualquier comando | Startup ligeramente más lento |
| ADR-003 | Rich console en vez de logging | UX mejor; output estructurado | Dependencia obligatorias |
| ADR-004 | exception_handler personalizado | Evita tracebacks feos para users | Errores de dev ligeramente menos detallados |

---

## Dependencies

- `click>=8.1` (ya en pyproject.toml)
- `rich>=13.0` (ya en pyproject.toml)
- `src.core.config` (ya existente)
- `src.modes.*` (ya existente)

---

## Notes

- Los modos existentes (`hunt`, `continuous`, etc.) deben EXPORTAR un comando Click `cli` para ser descubiertos.
- El banner solo se muestra cuando se llama sin comando (`ozy` solo) o con `--help`.
- Verificar que `config` funciona cuando NO hay `config.yaml` (debe usar defaults).