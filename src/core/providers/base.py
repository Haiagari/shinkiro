"""
Base Provider Interface
Define la interfaz para todos los adaptadores de herramientas.
"""

import abc
from pathlib import Path
from typing import Any, Optional

class BaseProvider(abc.ABC):
    """Clase base para un proveedor de herramientas (herramienta concreta)."""
    
    def __init__(self, name: str, binary: str):
        self.name = name
        self.binary = binary
        self.path = self._find_binary()

    def _find_binary(self) -> str:
        import shutil
        path = shutil.which(self.binary)
        if not path:
            # Check local tools path
            local_path = Path("tools/go/bin") / self.binary
            if local_path.exists():
                return str(local_path.absolute())
        return path if path else ""

    def is_available(self) -> bool:
        return bool(self.path)

    def _get_stealth_flags(self) -> List[str]:
        """Obtiene los flags de Chameleon para esta herramienta."""
        from src.opsec.chameleon import chameleon
        return chameleon.get_stealth_flags(self.name)

    @abc.abstractmethod
    def execute(self, target: Any, **kwargs) -> Any:
        pass
