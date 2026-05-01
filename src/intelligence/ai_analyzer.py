"""
AI Analyst Layer (OzyRecon v8.0)
Narrative explanation and contextualization for discovered assets.
Rule: Engine decides, LLM explains, Human approves.
"""

import logging
import json
from typing import Dict, Any, List
from src.core.config import config

logger = logging.getLogger("ai_analyst")

class AIAnalyst:
    """
    Narrative analyst that contextualizes engine findings.
    """

    def __init__(self):
        self.enabled = config.get("ai.enabled", False)
        self.provider = config.get("ai.provider", "gemini")

    def generate_finding_narrative(self, asset_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes a structured asset and returns a narrative impact assessment.
        """
        if not self.enabled:
            return {"narrative": "AI Analysis disabled in config.", "recommendations": []}

        # Prompt Engineering: Contexto estricto
        prompt = f"""
        Actúa como analista senior de ciberseguridad. 
        Contextualiza el siguiente hallazgo técnico de OzyRecon.
        
        ASSET: {asset_data.get('domain')}
        ENGINE LABELS: {asset_data.get('semantic_labels')}
        ENGINE IMPACT: {asset_data.get('business_impact')}
        TECH STACK: {asset_data.get('technologies')}
        HTTP TITLE: {asset_data.get('title')}
        
        REGLAS:
        1. No inventes vulnerabilidades que no estén en las etiquetas.
        2. Explica el impacto de negocio de estas etiquetas.
        3. Da 3 recomendaciones técnicas breves.
        
        Responde en JSON con este formato:
        {{
            "analysis": "...",
            "business_impact": "...",
            "recommendations": ["...", "...", "..."]
        }}
        """
        
        # Simulación del Bridge LLM (Aquí iría la llamada a Gemini/Claude API)
        # Para el prototipo v8.0a, generamos una respuesta estructurada de alta calidad
        # basada en los templates de inteligencia del motor.
        return self._mock_llm_call(asset_data)

    def _mock_llm_call(self, data: Dict) -> Dict:
        """Fallback determinístico para el prototipo v8."""
        domain = data.get("domain", "unknown")
        labels = data.get("semantic_labels", [])
        
        analysis = f"El motor Sentinel identificó {domain} como un activo de tipo {', '.join(labels)}."
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

        return {
            "analysis": analysis,
            "business_impact": impact,
            "recommendations": recs
        }

# Global Instance
ai_analyst = AIAnalyst()
