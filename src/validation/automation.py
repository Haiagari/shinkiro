"""
Automation Validator - Validación de n8n y herramientas de orquestación v5.4
"""

import requests
import urllib3
from typing import Dict, Any
from src.validation.base import BaseValidator, ValidationResult
from src.core.logging import get_logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = get_logger('validation.automation')

class AutomationValidator(BaseValidator):
    def validate(self, hypothesis: Dict[str, Any]) -> ValidationResult:
        hypo_id = hypothesis.get("id")
        url = hypothesis.get("url")
        
        logger.info(f"Validating Automation Panel on {url}")
        
        evidence = []
        status = "inconclusive"
        confidence = hypothesis.get("confidence", 0.0)
        notes = ""

        try:
            # 1. Verificar acceso al panel y detectar n8n
            response = requests.get(url, timeout=10, verify=False)
            evidence.append(self.create_evidence("http_response", f"Status: {response.status_code}", {"url": url}))
            
            # 2. Check Setup Wizard (Critical Exposure)
            setup_url = f"{url}/setup"
            setup_res = requests.get(setup_url, timeout=10, verify=False)
            
            if setup_res.status_code == 200 and "setup" in setup_res.text.lower():
                evidence.append(self.create_evidence("automation_config", "n8n Setup Wizard EXPOSED", {"path": "/setup"}))
                status = "confirmed"
                confidence = 0.99
                notes = "🔴 CRITICAL: n8n Setup Wizard is exposed. Anyone can claim administrative rights."
            
            # 3. Check for API settings (Information Disclosure)
            settings_url = f"{url}/rest/settings"
            settings_res = requests.get(settings_url, timeout=10, verify=False)
            if settings_res.status_code == 200:
                evidence.append(self.create_evidence("automation_config", "n8n Internal Settings Accessible", {"path": "/rest/settings"}))
                if status != "confirmed":
                    status = "confirmed"
                    confidence = 0.90
                    notes = "n8n panel is exposed and internal settings are accessible without auth."

        except Exception as e:
            logger.error(f"Automation validation error: {str(e)}")
            status = "refuted"
            notes = f"Error during validation: {str(e)}"

        return ValidationResult(hypo_id, status, confidence, evidence, notes)
