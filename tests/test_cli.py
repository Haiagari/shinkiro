"""
Tests for PromptWall CLI - v9.0.1 Alignment
"""

import pytest
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

# Add root to path
ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

@pytest.fixture
def runner():
    return CliRunner()

class TestOzyCLI:
    """Tests for cli/ozy.py - v9.0.1 Entry point"""

    def test_cli_exists(self, runner):
        from cli.ozy import cli
        assert cli is not None

    def test_cli_help_shows_banner(self, runner):
        from cli.ozy import cli
        result = runner.invoke(cli, ['--help'])
        assert result.exit_code == 0
        assert 'PromptWall' in result.output

    def test_cli_version(self, runner):
        """Validates version 9.0.1 as per definitive baseline."""
        from cli.ozy import cli
        result = runner.invoke(cli, ['--version'])
        assert result.exit_code == 0
        assert '9.0.1' in result.output

    def test_banner_contains_version(self, runner):
        from cli.ozy import get_banner
        banner = get_banner()
        assert '9.0.1' in banner

    def test_hunt_subcommand_exists(self, runner):
        from cli.ozy import cli
        result = runner.invoke(cli, ['--help'])
        assert result.exit_code == 0
        assert 'hunt' in result.output.lower()

class TestCliVerifyCommand:
    """Tests for the hardened v9.0.1 verify command."""

    def test_verify_command_exists(self, runner):
        from cli.ozy import cli, register_runtime_commands
        register_runtime_commands()
        result = runner.invoke(cli, ["verify", "--help"])
        assert result.exit_code == 0
        assert "verify" in result.output.lower()

    def test_verify_system_integrity(self, runner):
        """Verifies that the command runs and performs audit."""
        from cli.ozy import cli, register_runtime_commands
        register_runtime_commands()
        
        # We mock external checks to ensure it doesn't fail due to environment in unit tests
        with patch("cli.commands.verify.check_binaries", return_value=True), \
             patch("cli.commands.verify.check_folders", return_value=True), \
             patch("cli.commands.verify.check_intelligence_engines", return_value=True), \
             patch("cli.commands.verify.check_api_contract", return_value=True):
            
            result = runner.invoke(cli, ["verify"])
            assert result.exit_code == 0
            assert "SYSTEM INTEGRITY AUDIT" in result.output
