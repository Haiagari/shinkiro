from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from cli.ozy import cli, register_runtime_commands

@pytest.fixture
def runner():
    return CliRunner()

@pytest.fixture
def temp_scope_file(tmp_path):
    scope_dir = tmp_path / "config"
    scope_dir.mkdir()
    scope_file = scope_dir / "scope.yaml"
    initial_content = {
        "target": "example.com",
        "allowed_domains": ["example.com", "*.example.com"],
        "forbidden_patterns": ["test", "internal"],
        "profiles_allowed": ["passive"],
        "authorization": {
            "type": "academic",
            "reference": "TDD Test",
            "date": "2026-05-06",
            "authorized_by": "TDD"
        }
    }
    with open(scope_file, "w") as f:
        yaml.dump(initial_content, f)
    return scope_file

class TestScopeCLI:
    """
    TDD for scope CLI commands.
    """

    def test_scope_list(self, runner, temp_scope_file, monkeypatch):
        from cli.commands import scope
        monkeypatch.setattr(scope, "SCOPE_FILE_PATH", temp_scope_file)
        
        register_runtime_commands()
        result = runner.invoke(cli, ["scope", "list"])
        
        assert result.exit_code == 0
        assert "example.com" in result.output

    def test_scope_add_single(self, runner, temp_scope_file, monkeypatch):
        from cli.commands import scope
        monkeypatch.setattr(scope, "SCOPE_FILE_PATH", temp_scope_file)
        
        register_runtime_commands()
        result = runner.invoke(cli, ["scope", "add", "newtarget.com"])
        assert result.exit_code == 0
        
        with open(temp_scope_file, "r") as f:
            data = yaml.safe_load(f)
            assert "newtarget.com" in data["allowed_domains"]

    def test_scope_add_multiple(self, runner, temp_scope_file, monkeypatch):
        from cli.commands import scope
        monkeypatch.setattr(scope, "SCOPE_FILE_PATH", temp_scope_file)

        register_runtime_commands()
        result = runner.invoke(cli, ["scope", "add", "alpha.com", "beta.com"])

        assert result.exit_code == 0
        with open(temp_scope_file, "r") as f:
            data = yaml.safe_load(f)
            assert "alpha.com" in data["allowed_domains"]
            assert "beta.com" in data["allowed_domains"]

    def test_scope_remove_single(self, runner, temp_scope_file, monkeypatch):
        from cli.commands import scope
        monkeypatch.setattr(scope, "SCOPE_FILE_PATH", temp_scope_file)
        
        register_runtime_commands()
        result = runner.invoke(cli, ["scope", "remove", "example.com"])
        assert result.exit_code == 0
        
        with open(temp_scope_file, "r") as f:
            data = yaml.safe_load(f)
            assert "example.com" not in data["allowed_domains"]

    def test_scope_remove_multiple(self, runner, temp_scope_file, monkeypatch):
        from cli.commands import scope
        monkeypatch.setattr(scope, "SCOPE_FILE_PATH", temp_scope_file)

        register_runtime_commands()
        result = runner.invoke(cli, ["scope", "remove", "example.com", "*.example.com"])

        assert result.exit_code == 0
        with open(temp_scope_file, "r") as f:
            data = yaml.safe_load(f)
            assert "example.com" not in data["allowed_domains"]
            assert "*.example.com" not in data["allowed_domains"]

    def test_scope_import_file(self, runner, temp_scope_file, tmp_path, monkeypatch):
        from cli.commands import scope
        monkeypatch.setattr(scope, "SCOPE_FILE_PATH", temp_scope_file)
        
        # Create a file to import
        import_file = tmp_path / "targets.txt"
        import_file.write_text("imported1.com\nimported2.com\n")
        
        register_runtime_commands()
        result = runner.invoke(cli, ["scope", "import", str(import_file)])
        assert result.exit_code == 0
        assert "Imported 2 target" in result.output
        
        with open(temp_scope_file, "r") as f:
            data = yaml.safe_load(f)
            assert "imported1.com" in data["allowed_domains"]
            assert "imported2.com" in data["allowed_domains"]

    def test_scope_list_json(self, runner, temp_scope_file, monkeypatch):
        from cli.commands import scope
        monkeypatch.setattr(scope, "SCOPE_FILE_PATH", temp_scope_file)

        register_runtime_commands()
        result = runner.invoke(cli, ["scope", "list", "--json"])

        assert result.exit_code == 0
        assert "allowed_domains" in result.output

    def test_scope_authorization_persistence(self, runner, temp_scope_file, monkeypatch):
        from cli.commands import scope
        monkeypatch.setattr(scope, "SCOPE_FILE_PATH", temp_scope_file)
        
        # Read initial auth
        with open(temp_scope_file, "r") as f:
            initial_data = yaml.safe_load(f)
            initial_auth = initial_data["authorization"]
        
        register_runtime_commands()
        # Perform an action
        runner.invoke(cli, ["scope", "add", "persistent.com"])
        
        # Verify auth is still there
        with open(temp_scope_file, "r") as f:
            new_data = yaml.safe_load(f)
            assert new_data["authorization"] == initial_auth
            assert new_data["target"] == initial_data["target"]
