"""
Advanced Auth Validator - Validación de credenciales por defecto v5.7
"""

from typing import Dict, Any, List
from src.core.providers.http_clients import http_client
from src.core.errors import StealthSSLError, StealthRequestError
from src.validation.base import BaseValidator, ValidationResult
from src.validation.policy import validation_policy
from src.core.logging import get_logger

logger = get_logger('validation.auth')

class AuthValidator(BaseValidator):
    """
    Validador especializado en detectar paneles de administración 
    y probar credenciales por defecto de forma no intrusiva.
    """
    
    DEFAULT_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("guest", "guest"),
        ("user", "user")
    ]

    def validate(self, hypothesis: Dict[str, Any]) -> ValidationResult:
        hypo_id = hypothesis.get("id")
        url = hypothesis.get("url")
        h_type = hypothesis.get("type", "").upper()
        policy_decision = validation_policy.classify(hypothesis)
        
        if h_type != "DEFAULT_AUTH":
            return ValidationResult(hypo_id, "inconclusive", 0.0, [], "Not an auth hypothesis")

        if policy_decision.is_blocked:
            return ValidationResult(hypo_id, "inconclusive", 0.0, [], f"Blocked by policy: {policy_decision.reason}")

        if policy_decision.requires_gate and not hypothesis.get("approved", False):
            return ValidationResult(
                hypo_id,
                "inconclusive",
                0.0,
                [],
                f"Gate required before auth validation: {policy_decision.reason}"
            )

        logger.info(f"Validating default auth on {url}")
        
        evidence = []
        status = "inconclusive"
        confidence = 0.5
        notes = "Starting stealthy auth check..."

        try:
            # 1. Identificar el tipo de panel (Simple check)
            res = http_client.get(url, timeout=10)
            evidence.append(self.create_evidence("panel_detection", f"HTTP {res.status_code}", {"headers": dict(res.headers)}))

            # 2. Probar combinaciones básicas (solo las primeras 2 para mantener OPSEC)
            # En una versión real, esto sería más específico según la tecnología detectada.
            for user, pwd in self.DEFAULT_CREDS[:2]:
                # Intentamos un login genérico (esto es un ejemplo, variaría por app)
                # OzyRecon v5.7 prioriza la detección de la respuesta ante el intento
                auth_res = http_client.post(url, data={"user": user, "pass": pwd}, timeout=5)
                
                # Si cambia el comportamiento drásticamente o entramos...
                if auth_res.status_code in [200, 302] and len(auth_res.content) != len(res.content):
                    # Podría ser un falso positivo, pero es una señal fuerte
                    status = "confirmed"
                    confidence = 0.85
                    notes = f"Potential default credentials found: {user}:{pwd}"
                    evidence.append(self.create_evidence("auth_match", notes))
                    break
            
            if status == "inconclusive":
                status = "refuted"
                confidence = 0.1
                notes = "Default credentials rejected."

        except (StealthSSLError, StealthRequestError) as e:
            logger.error(f"Stealth Auth validation error: {str(e)}")
            notes = f"Validation failed due to network/SSL error: {str(e)}"
            status = "failed_validation"

        except Exception as e:
            logger.error(f"General Auth validation error: {str(e)}")
            notes = f"Validation failed: {str(e)}"
            status = "failed_validation"

        return ValidationResult(hypo_id, status, confidence, evidence, notes)
