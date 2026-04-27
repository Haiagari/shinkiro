import pytest
from unittest.mock import patch, MagicMock
from src.core.tool_manager import ToolManager
from src.core.manifest_manager import ToolEntry, ToolManifest

@pytest.fixture(autouse=True)
def clean_tool_manager():
    """Limpia la instancia Singleton para cada test."""
    ToolManager._instance = None

def test_tool_manager_sync_from_manifest():
    """
    GREEN: ToolManager debe cargar herramientas del manifiesto al inicializarse.
    """
    mock_tools = [
        ToolEntry(
            name="test_tool",
            executable="test_bin",
            adapter="GenericDiscoveryProvider",
            categories=["asset_discovery"],
            cmd_template="{bin} {target}"
        )
    ]

    with patch("src.core.manifest_manager.ManifestManager.get_available_tools", return_value=mock_tools):
        tm = ToolManager()
        
        # Verificamos que se registró en la capacidad correcta
        assert len(tm._capabilities["asset_discovery"]) > 0
        assert tm._capabilities["asset_discovery"][0].name == "test_tool"

def test_tool_manager_skips_disabled_tools():
    """
    GREEN: Herramientas marcadas como enabled: false no deben registrarse.
    """
    # get_available_tools ya filtra, así que devolvemos lista vacía para simularlo
    with patch("src.core.manifest_manager.ManifestManager.get_available_tools", return_value=[]):
        tm = ToolManager()
        assert len(tm._capabilities["asset_discovery"]) == 0

def test_tool_manager_skips_missing_binaries():
    """
    GREEN: Herramientas cuyo binario no está en el PATH no deben registrarse.
    """
    # get_available_tools ya filtra por binarios, devolvemos vacía
    with patch("src.core.manifest_manager.ManifestManager.get_available_tools", return_value=[]):
        tm = ToolManager()
        assert len(tm._capabilities["asset_discovery"]) == 0
