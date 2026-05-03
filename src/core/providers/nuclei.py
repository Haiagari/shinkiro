"""
Nuclei Provider para Template-based Scanning
"""

import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any
from src.core.providers.base import BaseProvider
from src.core.logging import get_logger
from src.core.runtime_paths import get_temp_dir

logger = get_logger('provider.nuclei')

class NucleiProvider(BaseProvider):
    def __init__(self):
        super().__init__("nuclei", "nuclei")

    def execute(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        if not self.is_available():
            logger.error("Nuclei binary not found")
            return []
        
        output_file = get_temp_dir() / "nuclei_results.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Mapeo de intención operativa
        speed = kwargs.get("speed", "normal")
        noise = kwargs.get("noise", "medium")
        depth = kwargs.get("depth", "standard")
        
        rate_limit = kwargs.get("rate_limit", 50)
        if speed == "fast": rate_limit = max(rate_limit, 150)
        elif speed == "slow": rate_limit = min(rate_limit, 10)
        
        severity = kwargs.get("severity", "critical,high,medium")
        if noise == "low":
            severity = "critical,high"
        
        # v8.3.2 Fix: Detect if target is a file or a single domain
        target_flag = "-l" if Path(target).exists() else "-u"
        
        cmd = [
            self.path, 
            target_flag, target, 
            "-severity", severity, 
            "-o", str(output_file), 
            "-json", "-silent", 
            "-rate-limit", str(rate_limit),
            "-bulk-size", str(max(1, rate_limit // 5))
        ]
        
        # Inyectar Chameleon Stealth Flags v7.2
        cmd.extend(self._get_stealth_flags())
        
        # --- FILTRADO DE FALSOS POSITIVOS ---
        from src.intelligence.false_positive_memory import false_positive_memory
        avoid_templates = false_positive_memory.get_avoid_list(tool="nuclei")
        if avoid_templates:
            logger.info(f"Filtering {len(avoid_templates)} known false positive templates")
            cmd.extend(["-exclude-templates", ",".join(avoid_templates)])
        
        # Tags específicos del modo RESEARCH
        tags = kwargs.get("tags", [])
        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        
        # Si depth es deep, incluimos templates que podrían ser lentos o pesados
        if depth == "deep":
            cmd.append("-as") # Automatic Scan
        
        # Opcionales
        if kwargs.get("update_templates", False):
            logger.info("Updating nuclei templates...")
            subprocess.run([self.path, "-update-templates", "-silent"])

        logger.info(f"Running nuclei on {target}")
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            results = []
            if output_file.exists():
                with open(output_file) as f:
                    for line in f:
                        if line.strip():
                            try:
                                results.append(json.loads(line))
                            except: continue
            logger.debug(f"Nuclei found {len(results)} potential findings")
            return results
        except Exception as e:
            logger.error(f"Nuclei execution failed: {e}")
            
        return []
