"""
AI Analyst Layer (PromptWall v8.0)
Narrative explanation and contextualization for discovered assets.
Rule: Engine decides, LLM explains, Human approves.
"""

import logging
import json
import re
from typing import Dict, Any, List, Optional

from src.core.config import config
from src.adapters.llms.provider_base import (  # noqa: F401 (re-exported for v9 callers until deletion)
    AIProvider,
    GeminiProvider,
    MockProvider,
    OllamaProvider,
    OpenAIProvider,
)

logger = logging.getLogger(__name__)

class AIAnalyst:
    """
    Narrative analyst that contextualizes engine findings.
    Unified provider architecture (v8.3.3).
    """

    _provider_registry: Dict[str, type[AIProvider]] = {
        "mock": MockProvider,
        "gemini": GeminiProvider,
        "openai": OpenAIProvider,
        "ollama": OllamaProvider,
    }

    @classmethod
    def register_provider(cls, name: str, provider_cls: type[AIProvider]) -> None:
        cls._provider_registry[name] = provider_cls

    def __init__(self, provider_name: str | None = None, api_key: str | None = None):
        self.enabled = config.get("ai.enabled", False)
        self.provider_name = provider_name or config.get("ai.provider", "gemini")
        self.api_key = api_key or config.gemini_api_key
        self.provider = self._init_provider()

    def _init_provider(self) -> Optional[AIProvider]:
        provider_cls = self._provider_registry.get(self.provider_name)

        if provider_cls is None:
            logger.info("Unknown provider '%s', using mock fallback", self.provider_name)
            return MockProvider(self.api_key)

        if self.provider_name == "mock":
            return provider_cls(self.api_key)

        if self.provider_name in {"gemini", "openai", "ollama"} and not self.enabled:
            logger.info("AI disabled, using mock fallback")
            return MockProvider(self.api_key)

        if self.provider_name in {"gemini", "openai"} and not self.api_key:
            logger.info("Missing API key for %s, using mock fallback", self.provider_name)
            return MockProvider(self.api_key)

        try:
            return provider_cls(self.api_key)
        except Exception as e:
            logger.warning("Provider initialization failed for %s: %s", self.provider_name, e)
            return MockProvider(self.api_key)

    def analyze(self, task_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Unified entrypoint for AI analysis."""
        if task_type == "finding":
            return self.generate_finding_narrative(data)
        if task_type == "secrets":
            return {"verified": self.verify_secrets(data.get("secrets", []))}
        return self._mock_llm_call(data)

    def verify_secrets(self, secrets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Uses AI to filter out false positives from the secret finder results.
        """
        if not self.provider or not secrets:
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
            text = self.provider.generate_content(prompt)
            if not text: return batch
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
        if not self.provider or not tech_stack: 
            return []
        
        prompt = f"""
        Tech Stack: {', '.join(tech_stack)}. 
        Actúa como Pentester. Identifica 3 CVEs o vectores de ataque críticos conocidos para estas tecnologías.
        Responde en JSON: {{"exploits": [{{"cve": "...", "description": "...", "impact": "..."}}]}}
        """
        
        try:
            text = self.provider.generate_content(prompt)
            if not text: return []
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                return json.loads(match.group()).get("exploits", [])
        except:
            pass
        return []

    def generate_finding_narrative(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a narrative explanation for a discovered asset or finding.

        Falls back to a deterministic local summary when the LLM is unavailable.
        """
        if not self.provider:
            return self._mock_llm_call(data)

        domain = data.get("domain", "unknown")
        labels = data.get("semantic_labels", []) or []
        techs = data.get("technologies", []) or []
        title = data.get("title", "")
        impact = data.get("business_impact", "LOW")

        prompt = f"""
        Actúa como analista senior de seguridad.
        Genera un JSON compacto para este activo.

        DOMINIO: {domain}
        TITULO: {title}
        ETIQUETAS: {labels}
        TECNOLOGIAS: {techs}
        IMPACTO: {impact}

        Devuelve solo JSON con las claves:
        analysis, business_impact, recommendations, remediation_snippet
        """

        try:
            text = self.provider.generate_content(prompt)
            if not text: return self._mock_llm_call(data)
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                parsed = json.loads(match.group())
                fallback = self._mock_llm_call(data)
                fallback.update({k: v for k, v in parsed.items() if k in fallback or k in {"analysis", "business_impact", "recommendations", "remediation_snippet"}})
                return fallback
        except Exception as e:
            logger.error(f"AI narrative generation failed: {e}")

        return self._mock_llm_call(data)

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
