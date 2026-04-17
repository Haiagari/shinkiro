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


def format_telegram_alert(target: str, critical: dict, diff: dict = None) -> str:
    """
    Formatea mensaje para Telegram con emojis apropiados y datos de diff.
    """
    is_first = diff.get("is_first_run", False) if diff else False
    
    header = "🚀 *NUEVA SESIÓN INICIADA*" if is_first else f"🎯 *{target}* - *REPORTE DE SCAN*"
    lines = [header]
    
    # ══════════════════════════════════════════════════════════════════════════════
    # HALLAZGOS POR SEVERIDAD
    # ══════════════════════════════════════════════════════════════════════════════
    total_findings = 0
    
    # 🔴 CRITICAL
    critical_vulns = [v for v in critical.get("vulns", []) if v["severity"] == "CRITICAL"]
    takeovers = critical.get("takeovers", [])
    secrets = critical.get("secrets", [])
    
    if critical_vulns or takeovers or secrets:
        count = len(critical_vulns) + len(takeovers) + len(secrets)
        total_findings += count
        lines.append(f"\n🔥 *CRÍTICOS* ({count})")
        for t in takeovers[:2]: lines.append(f"  • `[Takeover]` {t['url']}")
        for s in secrets[:2]:   lines.append(f"  • `[Secret]` {s['type']} en {s['source'].split('/')[-1]}")
        for v in critical_vulns[:3]:
            lines.append(f"  • {v.get('name', 'Unknown')[:40]}")
            if v.get('url'): lines.append(f"    └ {v['url']}")

    # 🟠 HIGH
    high_vulns = [v for v in critical.get("vulns", []) if v["severity"] == "HIGH"]
    if high_vulns:
        total_findings += len(high_vulns)
        lines.append(f"\n🟠 *HIGH* ({len(high_vulns)})")
        for v in high_vulns[:5]:
            lines.append(f"  • {v.get('name', 'Unknown')[:40]}")

    # 🟡 MEDIUM
    medium_vulns = [v for v in critical.get("vulns", []) if v["severity"] == "MEDIUM"]
    if medium_vulns:
        total_findings += len(medium_vulns)
        lines.append(f"\n🟡 *MEDIUM* ({len(medium_vulns)})")
        for v in medium_vulns[:5]:
            lines.append(f"  • {v.get('name', 'Unknown')[:40]}")

    # ══════════════════════════════════════════════════════════════════════════════
    # DESCUBRIMIENTOS (DIFF ENGINE)
    # ══════════════════════════════════════════════════════════════════════════════
    if diff and not is_first:
        new_subs = diff.get("new_subdomains", [])
        new_ports = diff.get("new_ports", [])
        
        if new_subs or new_ports:
            lines.append("\n✨ *NUEVOS DESCUBRIMIENTOS*")
            if new_subs:
                lines.append(f"  • Subdominios: `{len(new_subs)}` nuevos")
            if new_ports:
                lines.append(f"  • Puertos: `{len(new_ports)}` abiertos")

    # ══════════════════════════════════════════════════════════════════════════════
    # RESUMEN FINAL
    # ══════════════════════════════════════════════════════════════════════════════
    if total_findings == 0:
        if is_first:
            lines.append(f"\n✅ Primera ejecución completada.")
            lines.append(f"Se establecieron las bases de datos para futuros diffs.")
        else:
            lines.append(f"\n✅ *Scan completado sin hallazgos relevantes*")
    else:
        lines.append(f"\n⚡ *Total hallazgos (Medium+): {total_findings}*")
    
    # Footer
    lines.append(f"\n📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    return "\n".join(lines)


from datetime import datetime


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
    Optimizado para Pilar #2: Notificaciones Inteligentes.
    """
    alert_level = config.get("notifications", {}).get("alert_level", "medium")
    
    # Extraer findings
    vulns = context.get("phases", {}).get("vulns", {}).get("findings", [])
    recon = context.get("phases", {}).get("recon", {})
    js_analysis = context.get("phases", {}).get("js_analysis", {})
    diff_data = context.get("phases", {}).get("diff", {}) # Datos del Diff Engine
    
    takeovers = recon.get("takeovers", [])
    secrets = js_analysis.get("secrets", [])
    
    # Analizar severidad
    critical = check_critical_findings(vulns, takeovers, secrets, alert_level)
    
    total_relevant = sum([
        len(critical.get("takeovers", [])),
        len(critical.get("vulns", [])), # Ahora incluye todos los permitidos por alert_level
        len(critical.get("secrets", [])),
    ])

    # LOG en consola
    if total_relevant > 0:
        log(f"🚨 {total_relevant} hallazgos detectados!", "warn")
    
    # Formatear mensaje incluyendo el DIFF
    alert_msg = format_telegram_alert(target, critical, diff_data)
    
    # Lógica de envío inteligente:
    # 1. Si hay hallazgos relevantes -> Enviar siempre
    # 2. Si hay descubrimientos nuevos -> Enviar siempre
    # 3. Si no hay nada -> Enviar solo si "always_notify" es True en config
    
    has_discoveries = diff_data.get("new_subdomains") or diff_data.get("new_ports")
    always_notify = config.get("notifications", {}).get("always_notify", True)
    
    if total_relevant > 0 or has_discoveries or always_notify:
        send_immediate_alert(target, alert_msg, config)
        log(f"Reporte enviado a Telegram", "success")
    
    return critical
