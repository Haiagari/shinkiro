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
from cli.shared import console, ensure_config_loaded, handle_exception

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
    @click.option('--depth', 'depth_level', default=1, type=int, help='Recursion depth for recon (steroids)')
    @click.option('--intent', default='balanced', type=click.Choice(['passive', 'balanced', 'aggressive']), help='Operational intent')
    @click.option('--steroids/--no-steroids', default=True, help='Enable/Disable steroids recon')
    @click.option('--ghost', is_flag=True, default=False, help='Ghost Mode: Route traffic through Tor (Idea 4)')
    @click.option('--dry-run', is_flag=True, default=False, help='Plan only, do not execute')
    @click.option('--json', 'json_output', is_flag=True, default=False, help='Output in JSON format')
    @ensure_config_loaded()
    def command(target: str, threads: int, speed: str, depth_level: int, intent: str, steroids: bool, ghost: bool, dry_run: bool, json_output: bool):
        """Execute {mode_name} mode on TARGET."""
        options = {
            'threads': threads, 
            'speed': speed, 
            'depth_level': depth_level, 
            'intent': intent,
            'steroids': steroids,
            'ghost': ghost,
            'dry_run': dry_run,
            'json': json_output
        }
        mode = mode_class(target, options=options)
        
        if dry_run:
            console.print(f"[yellow]!! DRY RUN ENABLED - Planning for {target} !![/yellow]")
            # In dry-run we just return the plan if possible, or a mock result
            result = {"status": "dry_run_completed", "target": target}
        else:
            result = mode.run()
            
        if json_output:
            import json
            click.echo(json.dumps(result, indent=2, default=str))
        else:
            console.print(f"[green]✓ {mode_name} completed: {result.get('status', 'unknown')}[/green]")
        return result
    
    return command


# Task 2.9: handle_exception - movido a cli.shared
# Task 2.8: Decorator ensure_config_loaded - movido a cli.shared


# Task 2.5: Definir función get_banner() con ASCII art cyan bold y versión
def get_banner() -> str:
    """
    Genera el banner de OzyRecon con ASCII art.
    
    Returns:
        Markup de Rich con el banner formateado.
    """
    version = "8.3.2"
    
    banner = r"""
[bold cyan]
███████╗ █████╗ ██████╗  ██████╗ ██████╗ ██╗   ██╗
██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗╚██╗ ██╔╝
█████╗  ███████║██████╔╝██║   ██║██████╔╝ ╚████╔╝ 
██╔══╝  ██╔══██║██╔══██╗██║   ██║██╔══██╗  ╚██╔╝  
██║     ██║  ██║██║  ██║╚██████╔╝██║  ██║   ██║   
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
[/bold cyan]
[bold]OzyRecon[/bold] - Advanced Persistent Reconnaissance [bold red](CLI Elite Edition v8.3.2)[/bold red]
[dim]Pure Engineering - No GUI - Intelligence First[/dim]
""".format(version=version)
    
    return banner


# Consola Rich global - movida a cli.shared


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
    from src.core.bootstrap import bootstrap_runtime_files

    bootstrap_runtime_files()
    register_runtime_commands()

    # Task 3.1-3.2: Registrar signal handlers para shutdown limpio
    _setup_signal_handlers()
    
    try:
        cli(obj={})
        return 0
    except Exception as e:
        # Task 2.9: handle_exception con Rich console
        handle_exception(e)
        return 1


def register_runtime_commands() -> None:
    """Registers dynamic modes and built-in commands on the main CLI group."""
    # Task 2.7: Cargar modos dinámicos
    try:
        mode_commands = register_mode_commands()
        for cmd in mode_commands:
            if cmd.name not in cli.commands:
                cli.add_command(cmd)
    except Exception as e:
        if _debug:
            console.print(f"[yellow]Warning: Could not load dynamic modes: {e}[/yellow]")

    # Task 6.4: Registrar subcomando de reportes
    try:
        from cli.commands.report import report

        if report.name not in cli.commands:
            cli.add_command(report)
    except ImportError:
        pass

    # Task 6.5: Registrar subcomando de verificación
    try:
        from cli.commands.verify import verify
        if verify.name not in cli.commands:
            cli.add_command(verify)
    except ImportError:
        pass

    # v8.3.2: Registrar comando inventory
    try:
        from cli.commands.inventory import inventory
        if inventory.name not in cli.commands:
            cli.add_command(inventory)
    except ImportError:
        pass

    # v8.3.2: Registrar comando analyze
    try:
        from cli.commands.analyze import analyze
        if analyze.name not in cli.commands:
            cli.add_command(analyze)
    except ImportError:
        pass

    # v8.3.2: Registrar comando export
    try:
        from cli.commands.export import export_data
        if export_data.name not in cli.commands:
            cli.add_command(export_data)
    except ImportError:
        pass

    # v8.3.2: Registrar comando paths
    try:
        from cli.commands.paths import paths
        if paths.name not in cli.commands:
            cli.add_command(paths)
    except ImportError:
        pass

    # v8.3.2: Registrar comando watch
    try:
        from cli.commands.watch import watch
        if watch.name not in cli.commands:
            cli.add_command(watch)
    except ImportError:
        pass

    # v8.3.2: Registrar comando secrets
    try:
        from cli.commands.secrets import secrets
        if secrets.name not in cli.commands:
            cli.add_command(secrets)
    except ImportError:
        pass

    # v8.3.2: Registrar comando audit
    try:
        from cli.commands.audit import audit
        if audit.name not in cli.commands:
            cli.add_command(audit)
    except ImportError:
        pass

    # v8.3.2: Registrar comando exploits
    try:
        from cli.commands.exploits import exploits
        if exploits.name not in cli.commands:
            cli.add_command(exploits)
    except ImportError:
        pass

    # v8.3.2: Registrar comando screenshot
    try:
        from cli.commands.screenshot import screenshot
        if screenshot.name not in cli.commands:
            cli.add_command(screenshot)
    except ImportError:
        pass

    # v8.3.2: Registrar comando exploits
    try:
        @click.command(name="exploits")
        @click.argument("target")
        @click.option("--tech", multiple=True, help="Manual tech stack (e.g. --tech Apache --tech PHP)")
        def exploits_cmd(target, tech):
            """Suggest 3 relevant CVEs for a TARGET or specified technologies."""
            from src.intelligence.exploit_advisor import exploit_advisor
            from cli.shared import console
            
            # Si no pasan tech, podríamos sacarlo del inventario (pero para el comando simple, usamos --tech o simulamos)
            tech_list = list(tech)
            if not tech_list:
                console.print(f"[yellow]No se especificaron tecnologías para {target}. Usando stack genérico de reconocimiento...[/yellow]")
                tech_list = ["Apache", "PHP", "MySQL"] # Placeholder
            
            results = exploit_advisor.suggest_exploits(tech_list)
            
            if not results:
                console.print("[red]No se encontraron exploits relevantes. ¡Tenés suerte, por ahora![/red]")
                return

            console.print(f"\n[bold red]🔥 Exploit Advisor Findings for {target}:[/bold red]")
            for ex in results:
                console.print(f"[bold]• {ex.get('cve')}[/bold]: {ex.get('description')}")
                console.print(f"  [dim]Impact: {ex.get('impact')}[/dim]\n")

        if exploits_cmd.name not in cli.commands:
            cli.add_command(exploits_cmd)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not load exploits command: {e}[/yellow]")



# Alias para pyproject entry point
__all__ = ['cli', 'main', 'get_banner', 'console', 'register_mode_commands', 'register_runtime_commands', 'ensure_config_loaded', 'handle_exception']
