"""
HTTP Validator - Validación de hipótesis a nivel protocolo v5.0
"""

from typing import Dict, Any
from src.core.providers.http_clients import http_client
from src.core.errors import StealthSSLError, StealthRequestError
from src.validation.base import BaseValidator, ValidationResult
from src.core.logging import get_logger

logger = get_logger('validation.http')

class HTTPValidator(BaseValidator):
    def validate(self, hypothesis: Dict[str, Any]) -> ValidationResult:
        hypo_id = hypothesis.get("id")
        url = hypothesis.get("url")
        
        logger.info(f"Validating HTTP hypothesis {hypo_id} on {url}")
        
        evidence = []
        status = "inconclusive"
        confidence = hypothesis.get("confidence", 0.0)
        notes = ""

        try:
            # Simulación de validación controlada usando el cliente unificado
            response = http_client.get(url, timeout=10)
            
            # Evidencia: Metadata de la respuesta
            evidence.append(self.create_evidence(
                "http_metadata", 
                f"Status: {response.status_code}", 
                {"headers": dict(response.headers)}
            ))

            # Lógica de validación según el tipo
            h_type = hypothesis.get("type", "").upper()
            
            if h_type == "EXPOSED_VERSION":
                server_header = response.headers.get("Server", "")
                if server_header:
                    status = "confirmed"
                    confidence = 0.95
                    notes = f"Version disclosure confirmed in Server header: {server_header}"
                    evidence.append(self.create_evidence("header_match", server_header))
            
            elif h_type == "SENSITIVE_FILE":
                if response.status_code == 200:
                    status = "confirmed"
                    confidence = 0.90
                    notes = f"Sensitive file access confirmed: {url}"
                    evidence.append(self.create_evidence("file_access", f"HTTP 200 on {url}"))
            
            # --- SCREENSHOT LOGIC v5.7 ---
            if status == "confirmed":
                try:
                    from src.utils.visual import capture_screenshot
                    # Intentamos captura asincrónica (placeholder por ahora)
                    screenshot_path = capture_screenshot(url, hypo_id)
                    if screenshot_path:
                        evidence.append(self.create_evidence("screenshot", screenshot_path))
                except ImportError:
                    logger.warning("Visual utility not found, skipping screenshot.")
                except Exception as ex:
                    logger.error(f"Screenshot failed: {str(ex)}")

        except (StealthSSLError, StealthRequestError) as e:
            logger.error(f"Stealth validation error: {str(e)}")
            notes = f"Error during validation: {str(e)}"
            status = "refuted"
            confidence = 0.1

        except Exception as e:
            logger.error(f"General validation error: {str(e)}")
            notes = f"Unexpected error: {str(e)}"
            status = "refuted"
            confidence = 0.1

        return ValidationResult(hypo_id, status, confidence, evidence, notes)
