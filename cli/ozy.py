"""
PromptWall CLI Entry Point
Unified CLI con subcomandos, Rich UI, y graceful shutdown.
"""

import sys
import signal
import pkgutil
from typing import Optional

import click
from cli import __version__
from cli.shared import console, ensure_config_loaded, handle_exception

# Task 2.10: Importar config al inicio (línea 1 después de docstring)
from src.core.config import config  # noqa: E402, F401 (deliberate startup import)


# Task 2.5: Definir función get_banner() con ASCII art cyan bold y versión
def get_banner() -> str:
    """
    Genera el banner de PromptWall con ASCII art.

    Returns:
        Markup de Rich con el banner formateado.
    """
    banner = f"""
[bold cyan]
███████╗ █████╗ ██████╗  ██████╗ ██████╗ ██╗   ██╗
██╔════╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗╚██╗ ██╔╝
█████╗  ███████║██████╔╝██║   ██║██████╔╝ ╚████╔╝
██╔══╝  ██╔══██║██╔══██╗██║   ██║██╔══██╗  ╚██╔╝
██║     ██║  ██║██║  ██║╚██████╔╝██║  ██║   ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝
[/bold cyan]
[bold]PromptWall[/bold] - Advanced Persistent Reconnaissance [bold red](CLI Elite Edition v{__version__})[/bold red]
[dim]Pure Engineering - No GUI - Intelligence First[/dim]
"""

    return banner


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
def cli(ctx: click.Context, debug: bool, config_path: Optional[str], version: bool) -> None:
    """
    PromptWall - AI Guardrail Platform.

    Unified CLI for the guardrail surface:
    serve, keys, self-test (v10 commands land in slice 5).

    Usage:
        ozy <command> [OPTIONS] [ARGS]...
    """
    global _debug, _config_path

    # Task 2.2: Guardar opción --debug
    _debug = debug

    # Task 2.3: Guardar opción --config
    _config_path = config_path
    if config_path:
        console.print(f"[info]Using custom config: {config_path}[/info]")

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


def _autodiscover_commands() -> None:
    """Discover and register all Click commands from cli/commands/ using pkgutil."""
    import cli.commands as commands_package

    commands_path = commands_package.__path__
    if isinstance(commands_path, (list, tuple)):
        commands_path = commands_path[0] if commands_path else ""
    commands_path = str(commands_path)

    for importer, modname, ispkg in pkgutil.iter_modules([commands_path]):
        if modname.startswith('_'):
            continue
        try:
            module = __import__(f"cli.commands.{modname}", fromlist=[modname])

            cmd = None
            if hasattr(module, modname):
                attr = getattr(module, modname)
                if isinstance(attr, click.Command):
                    cmd = attr

            if cmd is None:
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if isinstance(attr, click.Command):
                        cmd = attr
                        break

            if cmd is not None and cmd.name not in cli.commands:
                cli.add_command(cmd)
        except Exception as e:
            if _debug:
                console.print(f"[yellow]Warning: Could not load command {modname}: {e}[/yellow]")


def register_runtime_commands() -> None:
    """Registers the built-in commands on the main CLI group."""
    _autodiscover_commands()


# Alias para pyproject entry point
__all__ = ['cli', 'main', 'get_banner', 'console', 'register_runtime_commands', 'ensure_config_loaded', 'handle_exception']

if __name__ == '__main__':
    sys.exit(main())
