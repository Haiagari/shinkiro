"""
Módulo de Notificaciones Inteligentes
Solo alerta cuando encuentra algo crítico o alto.
Niveles:
- CRITICAL: Alerta inmediata (takeover, IDOR, SQLi, RCE)
- HIGH: Resumen al final del scan
- MEDIUM: Solo si modo verboso está activo
"""

from .utils import log, send_telegram, load_config
from .utils import save_json

#严重 - solo estos disparan alerta inmediata
CRITICAL_PATTERNS = [
    "takeover", "subdomain takeover", "nosuchbucket",
    "idor", "broken authentication", "sql injection", "sqli",
    "rce", "remote code execution", "command injection",
    "xss", "cross-site scripting", "stored xss",
    "csrf", "cross-site request forgery",
    "path traversal", "lfi", "local file inclusion",
    "jwt", "json web token", "weak crypto",
    "hardcoded", "api key", "secret token",
]

#重要 pero no critico
HIGH_PATTERNS = [
    "information disclosure", "info leak",
    "missing security header", "csp", "hsts",
    "xxe", "xml external entity",
    "deserialization",
    "ssrf", "server-side request forgery",
    "open redirect",
]


def analyze_severity(finding: dict) -> str:
    """
    Analiza un finding y devuelve su nivel de severidad.
    """
    severity = finding.get("severity", "").lower()
    name = finding.get("name", "").lower()
    raw = str(finding.get("raw", "")).lower()
    finding_type = finding.get("type", "").lower()
    
    # Verificar severity de nucleI
    if severity in ["critical"]:
        return "CRITICAL"
    if severity in ["high"]:
        return "HIGH"
    if severity in ["medium", "low"]:
        return "MEDIUM"
    
    # Buscar patrones críticos
    combined = f"{name} {raw} {finding_type}"
    for pattern in CRITICAL_PATTERNS:
        if pattern in combined:
            return "CRITICAL"
    
    # Buscar patrones altos
    for pattern in HIGH_PATTERNS:
        if pattern in combined:
            return "HIGH"
    
    return "MEDIUM"


def check_critical_findings(vulns: list, takeovers: list = [], secrets: list = [], alert_level: str = "medium") -> dict:
    """
    Analiza TODOS los hallazgos y retorna según alert_level.
    Niveles: critical, high, medium, low, all
    """
    # Mapear niveles a severidades incluidas
    level_map = {
        "critical": ["CRITICAL"],
        "high": ["CRITICAL", "HIGH"],
        "medium": ["CRITICAL", "HIGH", "MEDIUM"],
        "low": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "all": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"],
    }
    allowed = level_map.get(alert_level, ["CRITICAL", "HIGH", "MEDIUM"])
    
    critical = {
        "takeovers": [],
        "vulns": [],
        "secrets": [],
    }
    
    # Takeovers siempre son críticos
    for t in takeovers:
        critical["takeovers"].append({
            "url": t,
            "type": "Takeover",
            "severity": "CRITICAL",
        })
    
    # Vulnerabilidades - filtrar por alert_level
    for v in vulns:
        sev = analyze_severity(v)
        if sev in allowed:
            critical["vulns"].append({
                "name": v.get("name", v.get("type", "Unknown")),
                "url": v.get("url", ""),
                "severity": sev,
                "details": v,
            })
    
    # Secrets en JS siempre críticos
    for s in secrets:
        critical["secrets"].append({
            "type": s.get("type", "Unknown"),
            "value": s.get("value", "")[:20] + "***",
            "source": s.get("source", ""),
            "severity": "CRITICAL",
        })
    
    return critical


def format_telegram_alert(target: str, critical: dict, full_report: dict = None) -> str:
    """
    Formatea mensaje para Telegram con emojis apropiados.
    """
    lines = [f"🎯 *{target}* - *ALERTA CRÍTICA ENCONTRADA*"]
    
    # Takeovers
    if critical.get("takeovers"):
        lines.append(f"\n🔴 *SUBDOMAIN TAKEOVER* ({len(critical['takeovers'])})")
        for t in critical["takeovers"][:3]:
            lines.append(f"  • {t['url']}")
    
    # Vulns críticas/altas
    high_vulns = [v for v in critical["vulns"] if v["severity"] == "CRITICAL"]
    if high_vulns:
        lines.append(f"\n🔥 *VULNERABILIDADES CRÍTICAS* ({len(high_vulns)})")
        for v in high_vulns[:5]:
            name = v.get("name", "Unknown")[:40]
            url = v.get("url", "")[:50]
            lines.append(f"  • {name}")
            if url:
                lines.append(f"    └ {url}")
    
    # Secrets
    if critical.get("secrets"):
        lines.append(f"\n🔑 *SECRETS EN JS* ({len(critical['secrets'])})")
        for s in critical["secrets"][:3]:
            lines.append(f"  • {s['type']} en {s['source'].split('/')[-1]}")
    
    # Resumen
    total_critical = len(high_vulns) + len(critical.get("takeovers", [])) + len(critical.get("secrets", []))
    if total_critical == 0:
        lines.append(f"\n✅ *Sin hallazgos críticos*")
        lines.append(f"Scan completado. Revisá el dashboard para ver el reporte completo.")
    else:
        lines.append(f"\n⚡ Total críticos: {total_critical}")
        if full_report:
            lines.append(f"📊 Dashboard: {full_report.get('dashboard_url', 'N/A')}")
    
    return "\n".join(lines)


def send_immediate_alert(target: str, message: str, config: dict):
    """
    Envía alerta inmediata a Telegram.
    """
    token = config.get("notifications", {}).get("telegram_token")
    chat_id = config.get("notifications", {}).get("telegram_chat_id")
    
    if not token or not chat_id:
        log("Telegram no configurado - saltando alerta", "warn")
        return
    
    from .utils import send_telegram
    send_telegram(message, config)
    log(f"🚨 Alerta enviada a Telegram: {message[:100]}...", "warn")


def run_notifier(target: str, context: dict, config: dict):
    """
    Analiza hallazgos y envía alertas.
    Usa alert_level de config.yaml: critical, high, medium, low, all
    """
    # Extraer nivel de alerts desde config
    alert_level = config.get("notifications", {}).get("alert_level", "medium")
    
    # Extraer findings de todas las fases
    recon = context.get("phases", {}).get("recon", {})
    vulns = context.get("phases", {}).get("vulns", {}).get("findings", [])
    js_analysis = context.get("phases", {}).get("js_analysis", {})
    
    takeovers = recon.get("takeovers", [])
    secrets = js_analysis.get("secrets", [])
    
    # Analizar severidad con alert_level
    critical = check_critical_findings(vulns, takeovers, secrets, alert_level)
    
    # Guardar análisis para referencia
    analysis_result = {
        "target": target,
        "critical": critical,
        "total_critical": sum([
            len(critical.get("takeovers", [])),
            len([v for v in critical["vulns"] if v["severity"] == "CRITICAL"]),
            len(critical.get("secrets", [])),
        ]),
    }
    out_dir = context.get("phases", {}).get("recon", {}).get("out_dir", "output")
    if out_dir:
        from pathlib import Path
        save_json(Path(out_dir).parent / "alert_analysis.json", analysis_result)
    
    # LOG: mostrar qué se encontró antes de enviar alerta
    total_critical = analysis_result["total_critical"]
    level_label = alert_level.upper()
    
    if total_critical > 0:
        log(f"🚨 {total_critical} hallazgos ({level_label}+) detectados", "warn")
        
        # MOSTRAR EN CONSOLA los críticos (para que usuario vea mientras corre)
        for t in critical.get("takeovers", [])[:2]:
            log(f"  🔴 TAKEOVER: {t['url']}", "error")
        
        for v in critical["vulns"][:3]:
            if v["severity"] == "CRITICAL":
                log(f"  🔥 {v['name'][:50]} -> {v['url'][:60]}", "error")
        
        for s in critical.get("secrets", [])[:2]:
            log(f"  🔑 {s['type']} en {s['source'][:50]}", "error")
    
    # Enviar ALERTA INMEDIATA solo si hay críticos
    if total_critical > 0:
        alert_msg = format_telegram_alert(target, critical)
        send_immediate_alert(target, alert_msg, config)
        log(f"Alerta crítica enviada a Telegram", "success")
    
    return critical