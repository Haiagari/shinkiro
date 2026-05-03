"""
Fuzzer Provider para OzyRecon v8.3.2
Fuzzing inteligente basado en el stack tecnológico.
"""

import subprocess
import os
from pathlib import Path
from typing import List, Any, Dict
from src.core.providers.base import BaseProvider
from src.core.logging import get_logger
from src.core.runtime_paths import get_temp_dir

logger = get_logger('provider.fuzzer')

class FuzzerProvider(BaseProvider):
    def __init__(self):
        # Usamos ffuf por defecto, que es el estándar de la industria.
        super().__init__("ffuf", "ffuf")
        self.wordlists_base = Path("resources/wordlists")

    def _get_context_wordlist(self, tech_stack: List[str]) -> str:
        """
        Selecciona el wordlist más adecuado según las tecnologías detectadas.
        """
        # Mapeo simple de tech -> wordlist específico
        tech_map = {
            "php": "php_discovery.txt",
            "asp": "asp_net_discovery.txt",
            "jsp": "java_discovery.txt",
            "node": "node_discovery.txt",
            "python": "python_discovery.txt",
            "wordpress": "wp_plugins.txt"
        }
        
        for tech in tech_stack:
            tech_lower = tech.lower()
            for key, wordlist in tech_map.items():
                if key in tech_lower:
                    wp = self.wordlists_base / wordlist
                    if wp.exists():
                        logger.info(f"Fuzzing inteligente: Detectado {key}, usando {wordlist}")
                        return str(wp)
        
        # Default
        return str(self.wordlists_base / "common.txt")

    def execute(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        if not self.is_available():
            logger.error("ffuf not found. ¡Meté el binario en tools/go/bin!")
            return []

        tech_stack = kwargs.get("tech_stack", [])
        wordlist = self._get_context_wordlist(tech_stack)
        
        output_file = get_temp_dir() / "fuzz_results.json"
        
        # Comando ffuf
        # FUZZ es el keyword que usa ffuf para la posición del fuzzing
        url = target if "FUZZ" in target else f"{target}/FUZZ"
        
        cmd = [
            self.path,
            "-u", url,
            "-w", wordlist,
            "-o", str(output_file),
            "-of", "json",
            "-silent"
        ]
        
        # Stealth flags
        cmd.extend(self._get_stealth_flags())

        logger.info(f"Fuzzing target: {target} (Wordlist: {Path(wordlist).name})")
        try:
            subprocess.run(cmd, check=False) # ffuf suele devolver non-zero si encuentra algo
            
            if output_file.exists():
                import json
                with open(output_file) as f:
                    data = json.load(f)
                    return data.get("results", [])
        except Exception as e:
            logger.error(f"Fuzzing falló: {e}")
            
        return []
