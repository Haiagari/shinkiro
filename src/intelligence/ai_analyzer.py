"""
AI Analyst Layer (OzyRecon v8.0)
Narrative explanation and contextualization for discovered assets.
Rule: Engine decides, LLM explains, Human approves.
"""

import logging
import json
import re
from typing import Dict, Any, List
from src.core.config import config

try:
    import google.generativeai as genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

logger = logging.getLogger("ai_analyst")

class AIAnalyst:
    """
    Narrative analyst that contextualizes engine findings.
    """

    def __init__(self):
        self.enabled = config.get("ai.enabled", False)
        self.provider = config.get("ai.provider", "gemini")
        self.api_key = config.gemini_api_key
        
        if self.enabled and self.provider == "gemini" and self.api_key and HAS_GENAI:
            try:
                genai.configure(api_key=self.api_key)
                self.model = genai.GenerativeModel('gemini-1.5-flash')
                logger.info("Gemini AI model initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize Gemini: {e}")
                self.model = None
        else:
            self.model = None

    def verify_secrets(self, secrets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Uses AI to filter out false positives from the secret finder results.
        """
        if not self.model or not secrets:
            return secrets

        # Group secrets to save tokens (send max 30 at a time)
        batch = secrets[:30]
        context = json.dumps([{ "idx": i, "type": s['type'], "match": s['match'], "context": s['raw_context'] } for i, s in enumerate(batch)])
        
        prompt = f"""
        Actúa como analista senior de seguridad. Analiza estos hallazgos de secretos.
        Determina cuáles son FALSOS POSITIVOS (ej: traducciones, nombres de variables comunes, strings de UI) 
        y cuáles son SECRETOS REALES o sensibles (ej: API Keys, credenciales, tokens).
        
        HALLAZGOS:
        {context}
        
        REGLAS:
        1. Evalúa el contexto (context) y el tipo (type).
        2. Si el contexto parece una lista de traducciones (ej: i18n), es FALSO POSITIVO.
        3. Si el match es muy corto o común, es FALSO POSITIVO.
        
        Responde ÚNICAMENTE con un objeto JSON: {{"verified_indices": [0, 2, 5...]}}
        """
        
        try:
            response = self.model.generate_content(prompt)
            text = response.text
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                result = json.loads(match.group())
                verified_indices = result.get("verified_indices", [])
                return [batch[i] for i in verified_indices if i < len(batch)]
        except Exception as e:
            logger.error(f"AI secret verification failed: {e}")
        
        return batch # Fallback: return batch if AI fails

    def check_exploits(self, tech_stack: List[str]) -> List[Dict[str, Any]]:
        """
        Uses AI to suggest known CVEs or exploits for a given tech stack.
        """
        if not self.model or not tech_stack: 
            return []
        
        prompt = f"""
        Tech Stack: {', '.join(tech_stack)}. 
        Actúa como Pentester. Identifica 3 CVEs o vectores de ataque críticos conocidos para estas tecnologías.
        Responde en JSON: {{"exploits": [{{"cve": "...", "description": "...", "impact": "..."}}]}}
        """
        
        try:
            response = self.model.generate_content(prompt)
            match = re.search(r'\{.*\}', response.text, re.DOTALL)
            if match:
                return json.loads(match.group()).get("exploits", [])
        except:
            pass
        return []

    def _mock_llm_call(self, data: Dict) -> Dict:
        """Fallback determinístico para el prototipo v8 (Robustness fix)."""
        domain = data.get("domain", "unknown")
        labels = data.get("semantic_labels", []) or []
        
        labels_str = ", ".join(labels) if labels else "no categorizado"
        
        analysis = f"El motor Sentinel identificó {domain} como un activo de tipo {labels_str}."
        impact = "Riesgo de exposición de superficies administrativas o APIs sin protección perimetral."
        recs = [
            "Implementar MFA en todas las rutas administrativas.",
            "Restringir acceso vía ACL de IP o VPN interna.",
            "Auditar logs de acceso en busca de anomalías de fuerza bruta."
        ]
        
        if "api_surface" in labels:
            analysis = f"Se detectó una superficie de API activa en {domain}."
            impact = "Posible exposición de endpoints sensibles. Riesgo de exfiltración de datos si no hay auth robusta."
            recs = ["Validar esquemas de autenticación (JWT/OAuth).", "Implementar Rate Limiting agresivo.", "Deshabilitar documentación de API (Swagger) en producción."]
            remediation = {
                "language": "nginx",
                "code": "location /api/v1 {\n  limit_req zone=api_limit burst=5;\n  allow <INTERNAL_IP_RANGE>;\n  deny all;\n}",
                "description": "Nginx rate-limit and IP restriction for internal API."
            }
        else:
            remediation = {
                "language": "bash",
                "code": "iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute -j ACCEPT",
                "description": "Basic rate limiting via iptables for HTTP traffic."
            }

        return {
            "analysis": analysis,
            "business_impact": impact,
            "recommendations": recs,
            "remediation_snippet": remediation
        }

# Global Instance
ai_analyst = AIAnalyst()
