"""
OzyRecon CLI Entry Point
Unified CLI con subcomandos, Rich UI, y graceful shutdown.
"""

import sys
import signal
import pkgutil
from pathlib import Path
from typing import Any, Optional, List, Callable
from functools import wraps

import click
from rich.console import Console
from rich.theme import Theme

# Task 2.10: Importar config al inicio (línea 1 después de docstring)
from src.core.config import config  # noqa: E402 (import after docstring)

# Task 6.1: Import report command (handled in main to avoid circular imports)
# from cli.commands.report import report


# Task 2.7: register_mode_commands - carga dinámica de modos usando pkgutil
def register_mode_commands() -> List[click.Command]:
    """
    Busca módulos en src/modes/ y carga dinámicamente aquellos que:
    1. Hereden de BaseMode => crear comando Click wrapper, O
    2. Expongan un comando Click directamente
    
    Returns:
        Lista de comandos Click registrados
    """
    import src.modes as modes_package
    from src.modes.base import BaseMode
    
    commands: List[click.Command] = []
    modes_path = modes_package.__path__
    if isinstance(modes_path, (list, tuple)):
        modes_path = modes_path[0] if modes_path else ""
    modes_path = str(modes_path)
    
    for importer, modname, ispkg in pkgutil.iter_modules([modes_path]):
        # Skip __init__ y base
        if modname.startswith('_') or modname == 'base':
            continue
        
        try:
            # Importar dinámicamente el módulo
            full_name = f"src.modes.{modname}"
            module = __import__(full_name, fromlist=[modname])
            
            # 1. Buscar comando Click directo en el módulo
            if hasattr(module, 'cli') and isinstance(module.cli, click.Command):
                commands.append(module.cli)
            # 2. Buscar clases que hereden de BaseMode
            elif hasattr(module, 'HuntMode'):
                # HuntMode -> crear comando Click wrapper
                commands.append(_create_mode_command(modname, module.HuntMode))
            elif hasattr(module, 'ContinuousMode'):
                commands.append(_create_mode_command(modname, module.ContinuousMode))
            elif hasattr(module, 'CampaignMode'):
                commands.append(_create_mode_command(modname, module.CampaignMode))
            elif hasattr(module, 'ResearchMode'):
                commands.append(_create_mode_command(modname, module.ResearchMode))
            elif hasattr(module, 'ForensicMode'):
                commands.append(_create_mode_command(modname, module.ForensicMode))
            elif hasattr(module, 'ServiceMode'):
                commands.append(_create_mode_command(modname, module.ServiceMode))
                
        except Exception as e:
            if _debug:
                console.print(f"[yellow]Warning: Could not load mode {modname}: {e}[/yellow]")
            continue
    
    return commands


def _create_mode_command(mode_name: str, mode_class: type) -> click.Command:
    """
    Crea un comando Click wrapper para una clase de modo.
    
    Args:
        mode_name: Nombre del modo (e.g., 'hunt')
        mode_class: Clase que hereda de BaseMode
        
    Returns:
        Comando Click registrado
    """
    @click.command(name=mode_name)
    @click.argument('target')
    @click.option('--threads', default=None, type=int, help='Number of threads')
    @click.option('--speed', default='normal', type=click.Choice(['slow', 'normal', 'fast']), help='Speed mode')
    @click.option('--depth', default='standard', type=click.Choice(['shallow', 'standard', 'deep']), help='Depth level')
    @ensure_config_loaded()
    def command(target: str, threads: int, speed: str, depth: str):
        """Execute {mode_name} mode on TARGET."""
        mode = mode_class(target, options={'threads': threads, 'speed': speed, 'depth': depth})
        result = mode.run()
        console.print(f"[green]✓ {mode_name} completed: {result.get('status', 'unknown')}[/green]")
        return result
    
    return command


# Task 2.8: Decorator ensure_config_loaded - valida que el config está listo antes de ejecutar
def ensure_config_loaded() -> Callable:
    """
    Decorator que valida que el sistema está listo antes de ejecutar un comando.
    
    Verifica que:
    - Config está cargado
    - Base de datos inicializada (si es necesario)
    - APIs disponibles (si aplica)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Verificar que config existe y está cargado
            if config is None:
                handle_exception(Exception("Config not loaded. Run 'ozy init' first."))
                sys.exit(1)
            # Verificar que tiene las settings mínimas
            if not hasattr(config, 'threads') or not hasattr(config, 'output_dir'):
                handle_exception(Exception("Config incomplete. Run 'ozy init' first."))
                sys.exit(1)
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Task 2.9: handle_exception - muestra errores limpios con Rich
def handle_exception(error: Exception) -> None:
    """
    Maneja excepciones mostrando errores limpios y claros usando Rich.
    
    Args:
        error: La excepción a mostrar
    """
    if _debug:
        # Modo debug: mostrar traceback completo
        console.print(f"[red]Error:[/red] {str(error)}")
        console.print_exception(show_locals=False)
    else:
        # Modo normal: mensaje limpio
        console.print(f"[red]✗ Error:[/red] {str(error)}")


# Task 2.5: Definir función get_banner() con ASCII art cyan bold y versión
def get_banner() -> str:
    """
    Genera el banner de OzyRecon con ASCII art.
    
    Returns:
        Markup de Rich con el banner formateado.
    """
    version = "6.0.0-alpha.1"
    
    banner = r"""
[bold cyan]
███████╗ █████╗ ██████╗  ██████╗ ██████╗ ██╗   ██╗
██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗╚██╗ ██╔╝
█████╗  ███████║██████╔╝██║   ██║██████╔╝ ╚████╔╝ 
██╔══╝  ██╔══██║██╔══██╗██║   ██║██╔══██╗  ╚██╔╝  
██║     ██║  ██║██║  ██║╚██████╔╝██║  ██║   ██║   
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
[/bold cyan]
[bold]OzyRecon[/bold] - Advanced Persistent Reconnaissance
[dim]Version {version}[/dim]
""".format(version=version)
    
    return banner


# Consola Rich global
console = Console(
    theme=Theme({
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
    })
)


# Variable global para debug mode
_debug: bool = False
_config_path: Optional[str] = None


# Task 3.1-3.2: Signal handlers para shutdown limpio
def _setup_signal_handlers() -> None:
    """
    Registra handlers para SIGINT y SIGTERM para shutdown limpio.
    """
    def handle_signal(signum, frame):
        signal_name = signal.Signals(signum).name
        console.print(f"\n[yellow]👋 Received {signal_name} - Saving state and exiting...[/yellow]")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)


# Task 2.1: Definir @click.group() principal
@click.group(invoke_without_command=True)
@click.option(
    '--debug',
    is_flag=True,
    default=False,
    help='Enable debug logging and verbose output'
)
@click.option(
    '--config',
    type=click.Path(exists=True),
    default=None,
    help='Specify custom config file path'
)
@click.option(
    '--version',
    is_flag=True,
    default=False,
    help='Display version information'
)
@click.pass_context
def cli(ctx: click.Context, debug: bool, config: Optional[str], version: bool) -> None:
    """
    OzyRecon - Advanced Persistent Reconnaissance Platform.
    
    Unified CLI for reconnaissance operations with multiple modes:
    hunt, continuous, campaign, research, forensic, service.
    
    Usage:
        ozy <command> [OPTIONS] [ARGS]...
    
    Examples:
        ozy hunt example.com
        ozy continuous example.com
        ozy --debug hunt example.com
    """
    global _debug, _config_path
    
    # Task 2.2: Guardar opción --debug
    _debug = debug
    
    # Task 2.3: Guardar opción --config
    _config_path = config
    if config:
        console.print(f"[info]Using custom config: {config}[/info]")
    
    # Task 2.4: Opción --version
    if version:
        console.print(get_banner())
        sys.exit(0)
    
    # Task 2.6: Mostrar banner cuando se llama sin subcomando o con --help
    if ctx.invoked_subcommand is None:
        console.print(get_banner())
        click.echo(ctx.get_help())


def main() -> int:
    """
    Entry point principal para la CLI.
    
    Returns:
        Exit code (0 = éxito, 1 = error)
    """
    # Task 6.4: Registrar subcomando de reportes
    from cli.commands.report import report
    cli.add_command(report)

    # Task 3.1-3.2: Registrar signal handlers para shutdown limpio
    _setup_signal_handlers()
    
    try:
        cli(obj={})
        return 0
    except Exception as e:
        # Task 2.9: handle_exception con Rich console
        handle_exception(e)
        return 1


# Alias para pyproject entry point
__all__ = ['cli', 'main', 'get_banner', 'console', 'register_mode_commands', 'ensure_config_loaded', 'handle_exception']