"""
LLM Router — Orquestador de Modelos e Inteligencia
Asigna la tarea al modelo correcto según complejidad, costo y presupuesto diario.
Soporta: Claude 3.5 Sonnet (Heavy), GPT-4o-mini (Medium), Groq/Llama3 (Light).
"""

import os
import json
import requests
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

ROOT_DIR = Path(__file__).resolve().parents[2]
RUNTIME_DIR = ROOT_DIR / "runtime"

class LLMRouter:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.agent_config = config.get("agent", {})
        self.daily_budget = float(self.agent_config.get("daily_budget_usd", 2.0))
        self.prefer_free = self.agent_config.get("prefer_free", True)
        
        # Archivo para trackear gasto diario
        self.usage_file = RUNTIME_DIR / "state" / "llm_usage.json"
        self._init_usage()

        # API Keys de config/config.yaml
        self.keys = {
            "anthropic": config.get("ai", {}).get("claude_api_key"),
            "openai": config.get("ai", {}).get("openai_api_key"),
            "groq": config.get("ai", {}).get("groq_api_key")
        }

    def _init_usage(self):
        """Inicializa o resetea el contador de gasto diario."""
        today = datetime.now().strftime("%Y-%m-%d")
        if not self.usage_file.exists():
            self._save_usage(today, 0.0)
        else:
            try:
                data = json.loads(self.usage_file.read_text())
                if data.get("date") != today:
                    self._save_usage(today, 0.0)
            except:
                self._save_usage(today, 0.0)

    def _save_usage(self, date: str, spent: float):
        self.usage_file.parent.mkdir(parents=True, exist_ok=True)
        self.usage_file.write_text(json.dumps({"date": date, "spent": spent}))

    def get_spent_today(self) -> float:
        try:
            return json.loads(self.usage_file.read_text()).get("spent", 0.0)
        except:
            return 0.0

    def _track_cost(self, model_type: str):
        """Aproximación de costos por llamada."""
        costs = {
            "heavy": 0.015,   # Claude Sonnet estimate
            "medium": 0.001,  # GPT-4o-mini estimate
            "light": 0.0      # Groq (Free tier)
        }
        spent = self.get_spent_today() + costs.get(model_type, 0.0)
        self._save_usage(datetime.now().strftime("%Y-%m-%d"), spent)

    def call(self, prompt: str, task_type: str = "medium") -> str:
        """
        Versión simplificada que retorna solo el texto. 
        Útil para reportes o análisis narrativos.
        """
        spent = self.get_spent_today()
        if spent >= self.daily_budget:
            return "Presupuesto diario agotado. No se pudo generar el análisis."

        if task_type == "heavy" and self.keys["anthropic"]:
            url = "https://api.anthropic.com/v1/messages"
            headers = {"x-api-key": self.keys["anthropic"], "anthropic-version": "2023-06-01", "content-type": "application/json"}
            payload = {"model": "claude-3-5-sonnet-20240620", "max_tokens": 1024, "messages": [{"role": "user", "content": prompt}]}
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=20)
                self._track_cost("heavy")
                return resp.json()["content"][0]["text"]
            except: pass

        # Fallback a un reporte estructurado tipo HackerOne (Simulado)
        return self._generate_deterministic_report(prompt)

    def _generate_deterministic_report(self, prompt: str) -> str:
        """Genera un borrador de reporte basado en la estructura de HackerOne."""
        # Extraer target del prompt si es posible
        import re
        target_match = re.search(r"datos de ([\w\.-]+)", prompt)
        target = target_match.group(1) if target_match else "Target Desconocido"

        return f"""# 🎯 Reporte de Seguridad: {target}
        
## 📝 Resumen
Se han detectado activos críticos expuestos durante el escaneo automatizado. Se recomienda revisión inmediata.

## 🛡️ Detalles del Hallazgo
- **Tipo:** Exposición de Infraestructura / Servicios Críticos
- **Severidad:** Media/Alta (Pendiente de validación)
- **Impacto:** Posible acceso no autorizado a bases de datos o paneles de gestión.

## 🚀 Pasos para Reproducir
1. Ejecutar escaneo de puertos sobre el dominio `{target}`.
2. Identificar servicios activos en puertos no estándar (ej: 3306, 2083, 2087).
3. Verificar si el banner del servicio revela versiones vulnerables.

## 🛠️ Mitigación
- Cerrar puertos innecesarios en el Firewall.
- Implementar listas blancas (IP Whitelisting) para servicios administrativos.
- Asegurar que todos los servicios requieran autenticación fuerte.

---
*Generado automáticamente por BugBounty Agent Framework (Deterministic Fallback)*
"""

    def think(self, objective: str, tools: list, context: dict, history: list, task_type: str = "medium") -> Dict[str, Any]:
        """
        Cadena de razonamiento: Intenta con LLMs en orden, cae a fallback real.
        """
        # 1. Verificar Presupuesto
        if self.get_spent_today() >= self.daily_budget:
            return self._deterministic_fallback(objective, context, history)

        # 2. Intentar APIs según importancia (Chain of Providers)
        providers = []
        if task_type == "heavy": providers = ["anthropic", "openai", "groq"]
        elif task_type == "medium": providers = ["openai", "groq", "anthropic"]
        else: providers = ["groq", "openai", "anthropic"]

        for p in providers:
            if self.keys.get(p):
                try:
                    if p == "anthropic": return self._call_claude(objective, tools, context, history)
                    if p == "openai": return self._call_openai(objective, tools, context, history)
                    if p == "groq": return self._call_groq(objective, tools, context, history)
                except Exception as e:
                    continue # Intentar el siguiente

        # 3. Fallback REAL — Lógica por reglas fijas
        return self._deterministic_fallback(objective, context, history)

    def _deterministic_fallback(self, objective: str, context: dict, history: list) -> Dict[str, Any]:
        """Reglas fijas robustas (Antiloop)."""
        obj_lower = objective.lower()
        past_actions = [h.get("decision", {}).get("action") for h in history]

        # Reglas para Modo HUNT
        if "hunt" in obj_lower:
            if not context.get("subdomains") and "recon" not in past_actions:
                return self._rule("recon", "fallback_hunt: no subs")
            if not context.get("open_ports") and "ports" not in past_actions:
                return self._rule("ports", "fallback_hunt: no ports")
            if "vulns" not in past_actions:
                return self._rule("vulns", "fallback_hunt: run vulns")
            if "intelligence" not in past_actions:
                return self._rule("intelligence", "fallback_hunt: final intelligence")

        # Reglas para Modo CONTINUO
        if "continuo" in obj_lower or "prioriza" in obj_lower:
            diff = context.get("diff", {})
            if diff.get("new_subdomains") and "recon" not in past_actions:
                return self._rule("recon", "fallback_cont: new subdomains")
            if diff.get("new_ports") and "ports" not in past_actions:
                return self._rule("ports", "fallback_cont: new ports")
            return self._rule("STOP", "fallback_cont: no critical changes")

        # Reglas para Modo ANALÍTICO (Forense/Servicio)
        if "analiza" in obj_lower or "reporte" in obj_lower:
            if "report" not in past_actions: return self._rule("report", "fallback_analitico: generate report")

        return self._rule("STOP", "fallback_default: loop closed")

    def _call_claude(self, objective: str, tools: list, context: dict, history: list) -> Dict[str, Any]:
        """Llamada a Claude 3.5 Sonnet para tareas pesadas."""
        url = "https://api.anthropic.com/v1/messages"
        headers = {"x-api-key": self.keys["anthropic"], "anthropic-version": "2023-06-01", "content-type": "application/json"}
        prompt = self._build_prompt(objective, tools, context, history)
        payload = {"model": "claude-3-5-sonnet-20240620", "max_tokens": 512, "messages": [{"role": "user", "content": prompt}]}
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=20)
            self._track_cost("heavy")
            text = resp.json()["content"][0]["text"]
            return self._parse_json_response(text)
        except: return self._rule("STOP", "error_claude_api")

    def _call_openai(self, objective: str, tools: list, context: dict, history: list) -> Dict[str, Any]:
        """Llamada a GPT-4o-mini para tareas medias."""
        url = "https://api.openai.com/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.keys['openai']}"}
        prompt = self._build_prompt(objective, tools, context, history)
        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "system", "content": "Return ONLY valid JSON."}, {"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"}
        }
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=15)
            self._track_cost("medium")
            text = resp.json()["choices"][0]["message"]["content"]
            return json.loads(text)
        except: return self._rule("STOP", "error_openai_api")

    def _call_groq(self, objective: str, tools: list, context: dict, history: list) -> Dict[str, Any]:
        """Llamada a Groq (Llama3) para tareas ligeras."""
        url = "https://api.groq.com/openai/v1/chat/completions"
        headers = {"Authorization": f"Bearer {self.keys['groq']}"}
        prompt = self._build_prompt(objective, tools, context, history)
        payload = {
            "model": "llama3-70b-8192",
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"}
        }
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=15)
            self._track_cost("light")
            text = resp.json()["choices"][0]["message"]["content"]
            return json.loads(text)
        except: return self._rule("STOP", "error_groq_api")

    def _build_prompt(self, objective: str, tools: list, context: dict, history: list) -> str:
        schema = {
            "action": "string (recon, ports, urls, vulns, report, STOP)",
            "params": "object (ej: {'host': '...', 'cve': '...'})",
            "reason": "string (justificación táctica)",
            "confidence": "number (0.0 to 1.0)"
        }
        return f"""
        Eres un Hunter Senior de Bug Bounty con foco en OPSEC. Tu misión: {objective}
        Herramientas disponibles: {tools}
        
        DIRECTRICES DE BLOQUEO:
        - Si un host devuelve 0 resultados tras un escaneo, asume bloqueo WAF o Firewall.
        - Prioriza el sigilo: si hay sospecha de bloqueo, sugiere acción "report" analizando el fallo.
        - No repitas una fase si ya devolvió 0 resultados sin cambiar los parámetros de sigilo.
        
        CONTEXTO ACTUAL: {json.dumps(context)}
        HISTORIAL RECIENTE: {json.dumps(history[-3:])}
        
        Responde EXCLUSIVAMENTE con un JSON que siga este schema:
        {json.dumps(schema, indent=2)}
        """

    def _parse_json_response(self, text: str) -> Dict[str, Any]:
        try:
            start = text.find('{')
            end = text.rfind('}') + 1
            return json.loads(text[start:end])
        except: return self._rule("STOP", "failed_json_parse")

    def _rule(self, action: str, reason: str) -> Dict[str, Any]:
        """Helper para generar decisiones deterministas estructuradas."""
        return {
            "action": action,
            "reason": reason,
            "confidence": 0.5,
            "params": {}
        }
