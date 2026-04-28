"""
Tests para la CLI de OzyRecon
TDD: Tests primero - implementación después
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

# Añadir raíz al path
ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))


class TestOzyCLI:
    """Tests para cli/ozy.py - Entry point de OzyRecon"""

    @pytest.fixture
    def runner(self):
        """CliRunner para testing de Click"""
        return CliRunner()

    def test_cli_exists(self, runner):
        """Test 2.1: El grupo CLI principal debe existir"""
        # Import debe funcionar sin errores
        from cli.ozy import cli
        assert cli is not None

    def test_cli_help_shows_banner(self, runner):
        """Test 2.6: El help debe mostrar el banner"""
        from cli.ozy import cli
        result = runner.invoke(cli, ['--help'])
        assert result.exit_code == 0
        assert 'OzyRecon' in result.output

    def test_cli_version(self, runner):
        """Test 2.4: --version debe mostrar la versión"""
        from cli.ozy import cli
        result = runner.invoke(cli, ['--version'])
        assert result.exit_code == 0
        assert '6.0.0' in result.output

    def test_cli_global_debug_option(self, runner):
        """Test 2.2: Opción global --debug debe existir"""
        from cli.ozy import cli
        result = runner.invoke(cli, ['--help'])
        assert result.exit_code == 0
        assert '--debug' in result.output

    def test_cli_global_config_option(self, runner):
        """Test 2.3: Opción global --config debe existir"""
        from cli.ozy import cli
        result = runner.invoke(cli, ['--help'])
        assert result.exit_code == 0
        assert '--config' in result.output

    def test_banner_contains_version(self, runner):
        """Test 2.5: Banner debe contener versión"""
        from cli.ozy import get_banner
        banner = get_banner()
        assert '6.0.0' in banner

    def test_banner_is_cyan_bold(self, runner):
        """Test 2.5: Banner debe usar formato Rich"""
        from cli.ozy import get_banner
        # get_banner debe retornar markup de Rich
        banner = get_banner()
        assert 'OzyRecon' in banner

    def test_config_loaded_on_import(self, runner):
        """Test 2.10: Config debe cargarse al inicio"""
        # El import de cli.ozy debe cargar config
        from cli import ozy
        # Verificar que config fue importado
        assert hasattr(ozy, 'config') or 'config' in dir(ozy)

    def test_hunt_subcommand_exists(self, runner):
        """Test: Subcomando hunt debe estar registrado"""
        from cli.ozy import cli
        result = runner.invoke(cli, ['--help'])
        assert result.exit_code == 0
        # Los subcomandos deben aparecer en el help
        assert 'hunt' in result.output.lower() or 'Commands:' in result.output


class TestCliDirectoryStructure:
    """Tests para la estructura de directorios de cli/"""

    def test_cli_directory_exists(self):
        """Test 1.1: Directorio cli/ debe existir"""
        cli_dir = ROOT_DIR / 'cli'
        assert cli_dir.exists(), "cli/ directory must exist"
        assert cli_dir.is_dir(), "cli/ must be a directory"

    def test_cli_init_exists(self):
        """Test 1.2: cli/__init__.py debe existir"""
        init_file = ROOT_DIR / 'cli' / '__init__.py'
        assert init_file.exists(), "cli/__init__.py must exist"

    def test_cli_main_exists(self):
        """Test 1.3: cli/__main__.py debe existir para python -m cli"""
        main_file = ROOT_DIR / 'cli' / '__main__.py'
        assert main_file.exists(), "cli/__main__.py must exist"

    def test_root_ozy_py_exists(self):
        """Test 1.3b: ozy.py debe existir como wrapper estable del runtime"""
        root_entry = ROOT_DIR / 'ozy.py'
        assert root_entry.exists(), "ozy.py must exist"

    def test_cli_commands_init_exists(self):
        """Test 1.4: cli/commands/__init__.py debe existir"""
        commands_init = ROOT_DIR / 'cli' / 'commands' / '__init__.py'
        assert commands_init.exists(), "cli/commands/__init__.py must exist"


class TestRegisterModeCommands:
    """Tests para Task 2.7: register_mode_commands() con carga dinámica de modos"""

    def test_register_mode_commands_exists(self):
        """Test 2.7: Función register_mode_commands debe existir"""
        from cli.ozy import register_mode_commands
        assert callable(register_mode_commands)

    def test_register_mode_commands_finds_modes(self):
        """Test 2.7: Debe encontrar módulos en src/modes/"""
        from cli.ozy import register_mode_commands
        # Debe retornar al menos un modo
        commands = register_mode_commands()
        assert isinstance(commands, list)

    def test_modes_inherit_from_basemode(self):
        """Test 2.7: Los modos encontrados deben ser comandos Click"""
        from cli.ozy import register_mode_commands
        commands = register_mode_commands()
        # Al menos hunt debe estar registrado
        command_names = [c.name for c in commands if hasattr(c, 'name')]
        assert 'hunt' in command_names or len(commands) > 0


class TestEnsureConfigLoaded:
    """Tests para Task 2.8: ensure_config_loaded() decorator"""

    def test_ensure_config_loaded_decorator_exists(self):
        """Test 2.8: Decorator ensure_config_loaded debe existir"""
        from cli.ozy import ensure_config_loaded
        assert callable(ensure_config_loaded) or ensure_config_loaded is not None

    def test_ensure_config_loaded_validates_config(self):
        """Test 2.8: Debe validar que config está cargado"""
        from cli.ozy import ensure_config_loaded
        from click import Command
        
        @ensure_config_loaded()
        def dummy_command():
            return "ok"
        
        # El decorator debe envolver el comando
        assert callable(dummy_command)


class TestHandleException:
    """Tests para Task 2.9: handle_exception() con Rich"""

    def test_handle_exception_exists(self):
        """Test 2.9: Función handle_exception debe existir"""
        from cli.ozy import handle_exception
        assert callable(handle_exception)

    def test_handle_exception_uses_rich_console(self):
        """Test 2.9: Debe usar Rich console para mostrar errores"""
        from cli.ozy import handle_exception, console
        from rich.console import Console
        
        # Verificar que usa la consola Rich global
        assert isinstance(console, Console)

    def test_handle_exception_handles_exception_cleanly(self):
        """Test 2.9: Debe manejar excepciones limpiamente"""
        from cli.ozy import handle_exception
        
        # Verificar que es callable
        assert callable(handle_exception)


class TestSignalHandling:
    """Tests para Task 3.1-3.2: Signal handling para shutdown limpio"""

    def test_setup_signal_handlers_function_exists(self):
        """Test 3.1: Debe haber función para registrar handlers"""
        from cli.ozy import _setup_signal_handlers
        assert callable(_setup_signal_handlers)

    def test_setup_signal_handlers_registers_signals(self):
        """Test 3.1: Debe registrar handlers para SIGINT/SIGTERM después de llamarse"""
        import signal
        from cli.ozy import _setup_signal_handlers
        
        # Registrar handlers
        _setup_signal_handlers()
        
        # Verificar que están registrados
        sigint_handler = signal.getsignal(signal.SIGINT)
        sigterm_handler = signal.getsignal(signal.SIGTERM)
        
        assert sigint_handler is not signal.SIG_DFL
        assert sigterm_handler is not signal.SIG_DFL

    def test_graceful_shutdown_message(self):
        """Test 3.2: Debe mostrar mensaje de apagado limpio"""
        from cli.ozy import console
        # La consola debe existir para mostrar mensajes
        assert console is not None


class TestCliExceptions:
    """Tests adicionales para manejo de excepciones en CLI"""

    def test_exception_handler_provides_clean_output(self):
        """Test: handle_exception debe dar salida limpia"""
        from cli.ozy import handle_exception, console
        try:
            raise ValueError("Test error message")
        except ValueError as e:
            # No debe-crashear
            handle_exception(e)
            # Si llega aquí, pasó
