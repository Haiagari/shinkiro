"""
PromptWall v6.0 — Surgical Exploitation Engine
Valida vulnerabilidades mediante sondas mínimas e indetectables.
"""

from typing import Dict, Any, Optional
from src.core.providers.http_clients import http_client
from src.core.logging import get_logger

logger = get_logger('surgical')

class SurgicalProber:
    """
    v6.0 — Ejecuta validaciones quirúrgicas basadas en evidencia.
    """
    
    @staticmethod
    def validate_env_exposure(url: str) -> Dict[str, Any]:
        """Sonda mínima para confirmar archivos .env expuestos."""
        logger.info(f"Surgical probe: Checking .env exposure on {url}")
        try:
            # Sonda de 100 bytes máximo para no disparar alertas de exfiltración
            headers = {"Range": "bytes=0-100"}
            response = http_client.get(url, headers=headers, timeout=5)
            
            content = response.text.upper()
            patterns = ["DB_", "APP_KEY", "AWS_", "SECRET", "PASSWORD", "PORT="]
            
            is_valid = any(p in content for p in patterns)
            
            return {
                "valid": is_valid,
                "evidence_sample": content[:30] if is_valid else None,
                "status": "confirmed" if is_valid else "false_positive"
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    @staticmethod
    def validate_git_exposure(url: str) -> Dict[str, Any]:
        """Sonda para confirmar exposición de carpeta .git/config."""
        target_url = url.rstrip('/') + '/config'
        try:
            response = http_client.get(target_url, timeout=5)
            is_valid = "[core]" in response.text.lower() and "repositoryformatversion" in response.text.lower()
            
            return {
                "valid": is_valid,
                "status": "confirmed" if is_valid else "false_positive"
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    @staticmethod
    def validate_path_traversal(url: str, payload: str) -> Dict[str, Any]:
        """Sonda quirúrgica para Path Traversal leyendo /etc/passwd."""
        try:
            response = http_client.get(url + payload, timeout=5)
            # Buscamos el patrón clásico de linux
            is_valid = "root:x:0:0" in response.text
            
            return {
                "valid": is_valid,
                "status": "confirmed" if is_valid else "false_positive"
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

# Instancia global v6.0
surgical_prober = SurgicalProber()
