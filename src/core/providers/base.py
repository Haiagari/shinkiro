"""
Base Provider Interface
Define la interfaz para todos los adaptadores de herramientas.
"""

import abc
import subprocess
from pathlib import Path
from typing import Any, Optional, List

from src.core.context import get_context
from src.utils import run_cmd

class BaseProvider(abc.ABC):
    """Clase base para un proveedor de herramientas (herramienta concreta)."""
    
    def __init__(self, name: str, binary: str):
        self.name = name
        self.binary = binary
        self.path = self._find_binary()

    def _find_binary(self) -> str:
        from src.core.path_resolver import path_resolver
        return path_resolver.resolve(self.binary)

    def is_available(self) -> bool:
        return bool(self.path)

    def _get_stealth_flags(self) -> List[str]:
        """Obtiene los flags de Chameleon para esta herramienta."""
        from src.opsec.chameleon import chameleon
        return chameleon.get_stealth_flags(self.name)

    def _run_tool(self, cmd: list[str], *, timeout: int = 30, capability: str | None = None, capture: bool = True, check: bool = False, retries: int = 0, backoff: float = 1.5, stdout=None, stderr=None) -> subprocess.CompletedProcess:
        """Run an external tool with timeout retry behavior."""
        ctx = get_context()
        if ctx and ctx.timeout_policy:
            timeout = ctx.timeout_policy.get(capability or self.name, ctx.timeout_policy.get("default", timeout))
        return run_cmd(cmd, timeout=timeout, capture=capture, check=check, retries=retries, backoff=backoff, stdout=stdout, stderr=stderr)

    @abc.abstractmethod
    def execute(self, target: Any, **kwargs) -> Any:
        pass
