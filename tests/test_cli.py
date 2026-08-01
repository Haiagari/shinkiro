"""
Tests for PromptWall CLI - v0.1.0 Alignment
"""

import pytest
import sys
from pathlib import Path
from click.testing import CliRunner

# Add root to path
ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

@pytest.fixture
def runner():
    return CliRunner()

class TestOzyCLI:
    """Tests for cli/ozy.py - v0.1.0 Entry point"""

    def test_cli_exists(self, runner):
        from cli.ozy import cli
        assert cli is not None

    def test_cli_help_shows_banner(self, runner):
        from cli.ozy import cli
        result = runner.invoke(cli, ['--help'])
        assert result.exit_code == 0
        assert 'PromptWall' in result.output

    def test_cli_version(self, runner):
        """Validates version 0.1.0 as per definitive baseline."""
        from cli.ozy import cli
        result = runner.invoke(cli, ['--version'])
        assert result.exit_code == 0
        assert '0.1.0' in result.output

    def test_banner_contains_version(self, runner):
        from cli.ozy import get_banner
        banner = get_banner()
        assert '0.1.0' in banner
