"""
PromptWall Path Resolver (v8.3.2)
Ensures the correct tool binaries are used and verified.
"""

import os
import shutil
import subprocess
import logging
from pathlib import Path
from typing import Optional

from src.core.config import config

logger = logging.getLogger("core.path")

class PathResolver:
    """
    Resolves and validates tool paths with priority for local binaries.
    """
    
    def __init__(self):
        self.local_tools_path = Path(config.tools_path or "tools/go/bin")
        self.resolved_cache = {}

    def resolve(self, binary_name: str) -> str:
        """
        Finds the absolute path for a binary.
        Priority: Local Tools Path > System PATH.
        """
        if binary_name in self.resolved_cache:
            return self.resolved_cache[binary_name]

        # 1. Try local tools directory (The "Safe" path)
        local_bin = self.local_tools_path / binary_name
        if local_bin.exists():
            abs_path = str(local_bin.absolute())
            logger.debug(f"Resolved {binary_name} to local path: {abs_path}")
            self.resolved_cache[binary_name] = abs_path
            return abs_path

        # 2. Try System PATH (The "System" path)
        system_bin = shutil.which(binary_name)
        if system_bin:
            logger.debug(f"Resolved {binary_name} to system path: {system_bin}")
            self.resolved_cache[binary_name] = system_bin
            return system_bin

        logger.error(f"Binary '{binary_name}' could not be resolved anywhere.")
        return ""

    def verify_version(self, binary_name: str, expected_snippet: str) -> bool:
        """
        Verifies if the binary is the correct one by checking version output.
        """
        path = self.resolve(binary_name)
        if not path:
            return False
            
        try:
            # Most projectdiscovery tools support -version
            result = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=5)
            output = result.stdout + result.stderr
            return expected_snippet.lower() in output.lower()
        except:
            return False

# Global Instance
path_resolver = PathResolver()
