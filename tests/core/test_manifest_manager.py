import pytest
import yaml
from pydantic import ValidationError
from src.core.manifest_manager import ToolEntry, ToolManifest, ManifestManager
import os
from unittest.mock import patch

def test_tool_entry_validation_valid():
    """RED: ToolEntry should validate correct data."""
    data = {
        "name": "subfinder",
        "executable": "subfinder",
        "adapter": "SubfinderProvider",
        "categories": ["asset_discovery"]
    }
    entry = ToolEntry(**data)
    assert entry.name == "subfinder"
    assert entry.enabled is True

def test_tool_entry_validation_invalid_missing_fields():
    """RED: ToolEntry should fail if required fields are missing."""
    with pytest.raises(ValidationError):
        ToolEntry(name="missing_fields")

def test_tool_manifest_load_valid(tmp_path):
    """RED: ManifestManager should load a valid YAML file."""
    manifest_file = tmp_path / "valid_manifest.yaml"
    content = {
        "tools": [
            {
                "name": "subfinder",
                "executable": "subfinder",
                "adapter": "SubfinderProvider",
                "categories": ["asset_discovery"]
            }
        ]
    }
    manifest_file.write_text(yaml.dump(content))
    
    manager = ManifestManager()
    manifest = manager.load(str(manifest_file))
    
    assert len(manifest.tools) == 1
    assert manifest.tools[0].name == "subfinder"

def test_tool_manifest_load_invalid_yaml(tmp_path):
    """RED: ManifestManager should raise error on invalid YAML syntax."""
    manifest_file = tmp_path / "invalid.yaml"
    manifest_file.write_text("tools:\n  - name: subfinder\n  invalid_syntax")
    
    manager = ManifestManager()
    with pytest.raises(yaml.YAMLError):
        manager.load(str(manifest_file))

def test_tool_manifest_validation_error(tmp_path):
    """TRIANGULATE: ManifestManager should raise Pydantic ValidationError on invalid structure."""
    manifest_file = tmp_path / "invalid_struct.yaml"
    # Missing 'executable' and 'adapter'
    content = {
        "tools": [
            {
                "name": "incomplete",
                "categories": ["test"]
            }
        ]
    }
    manifest_file.write_text(yaml.dump(content))
    
    manager = ManifestManager()
    with pytest.raises(ValidationError):
        manager.load(str(manifest_file))

def test_manifest_not_found():
    """TRIANGULATE: ManifestManager should raise FileNotFoundError if path is wrong."""
    manager = ManifestManager()
    with pytest.raises(FileNotFoundError):
        manager.load("non_existent.yaml")

def test_validate_binaries_existing_in_path():
    """RED: validate_binaries should keep tool enabled if executable exists."""
    entry = ToolEntry(
        name="test_tool",
        executable="ls",  # 'ls' definitely exists in PATH on linux
        adapter="SomeProvider",
        categories=["test"]
    )
    manifest = ToolManifest(tools=[entry])
    manager = ManifestManager()
    
    # Mocking shutil.which to return a path
    with patch("shutil.which", return_value="/usr/bin/ls"):
        manager.validate_binaries(manifest)
    
    assert manifest.tools[0].enabled is True

def test_validate_binaries_missing_in_path():
    """RED: validate_binaries should disable tool if executable NOT in PATH."""
    entry = ToolEntry(
        name="fake_tool",
        executable="non_existent_binary_xyz",
        adapter="SomeProvider",
        categories=["test"]
    )
    manifest = ToolManifest(tools=[entry])
    manager = ManifestManager()
    
    # Mocking shutil.which to return None
    with patch("shutil.which", return_value=None):
        manager.validate_binaries(manifest)
    
    assert manifest.tools[0].enabled is False

def test_get_provider_class_valid():
    """RED: get_provider_class should return the correct class from src.core.providers."""
    manager = ManifestManager()
    # SubfinderProvider exists in src.core.providers
    klass = manager.get_provider_class("SubfinderProvider")
    assert klass.__name__ == "SubfinderProvider"

def test_get_provider_class_invalid():
    """RED: get_provider_class should raise ImportError or AttributeError for invalid provider."""
    manager = ManifestManager()
    with pytest.raises((ImportError, AttributeError)):
        manager.get_provider_class("NonExistentProvider")
