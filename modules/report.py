"""
Módulo de Generación de Reportes
- Reporte Markdown (resumen)
- Reporte listo para HackerOne (formato exacto)
- JSON consolidado
"""

import json
from pathlib import Path
from datetime import datetime
from .utils import log, write_lines, save_json

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
    "unknown":  "❓",
}

CVSS_SCORES = {
    "critical": "9.0 – 10.0",
    "high":     "7.0 – 8.9", 
    "medium":   "4.0 – 6.9",
    "low":      "0.1 – 3.9",
    "info":     "0.0",
}

# Impactos predefinidos por tipo de vuln
IMPACTS = {
    "idor": "Un atacante puede acceder, modificar o eliminar datos de otros usuarios sin autorización.",
    "xss": "Un atacante puede ejecutar código JavaScript arbitrario en el navegador de las víctimas.",
    "sqli": "Un atacante puede extraer, modificar o eliminar datos de la base de datos.",
    "rce": "Un atacante puede ejecutar comandos arbitrarios en el servidor.",
    "ssrf": "Un atacante puede acceder a servicios internos o cloud metadata.",
    "csrf": "Un atacante puede realizar acciones no autorizadas en nombre de la víctima.",
    "path": "Un atacante puede leer archivos sensibles del sistema.",
}


def generate_hackerone_report(target: str, finding: dict) -> str:
    """
    Genera reporte EXACTO en formato de HackerOne.
    """
    severity = finding.get("severity", "medium").lower()
    name = finding.get("name", "Vulnerability")
    url = finding.get("url", "")
    cvss = finding.get("cvss", {})
    
    # Obtener impacto basado en tipo
    finding_type = finding.get("type", "").lower()
    impact = "El impacto específico depende del contexto y la naturaleza de la vulnerabilidad."
    for key, imp in IMPACTS.items():
        if key in finding_type:
            impact = imp
            break
    
    report = f"""# {name} en {target}

## Severidad
{severity.upper()}

## Descripción
Se identificó una vulnerabilidad de tipo **{name}** en el endpoint `{url}`.

La aplicación no implements correctamente la validación de acceso/entradas lo que permite a un atacante realizar acciones no autorizadas o acceder a información sensible.

## Pasos para reproducir

1. Navegar a `{url}`
2. [Realizar acción específica]
3. Observar comportamiento inesperado

**Request original:**
```
GET {url} HTTP/1.1
Host: {target}
User-Agent: BugBounty-Framework/1.0
```

**Response:**
```
HTTP/1.1 200 OK
[respuesta relevante]
```

## Impacto
{impact}

## Remedio / Recomendación
- Implementar validación de acceso adecuada
- Sanitizar todas las entradas de usuario
- Usar parameterized queries para bases de datos
- Implementar autenticación y autorización correcta

## Referencias
- OWASP Top 10: https://owasp.org/Top10/
- CWE-{finding.get("cwe", "Unknown")}: https://cwe.mitre.org/

## CVSS
{f"Vector: {cvss.get('vector', 'N/A')}" if cvss else 'CVSS:3.1 sin calcular'}
Score: {cvss.get('base_score', 'N/A')}/10

---
*Reporte generado por BugBounty Framework • {datetime.now().strftime('%Y-%m-%d %H:%M')}*"""
    
    return report


def generate_report(target: str, results: dict, out_dir: Path, ts: str, context: dict = {}):
    """
    Genera todos los tipos de reporte.
    """
    out_dir.mkdir(parents=True, exist_ok=True)

    recon  = results.get("recon",  {})
    ports  = results.get("ports",  {})
    urls   = results.get("urls",   {})
    vulns  = results.get("vulns",  {})
    intel = results.get("intelligence", {})
    js    = results.get("js_analysis", {})

    findings = vulns.get("findings", [])
    
    # Agrupar por severidad
    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": [], "unknown": []}
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        if sev not in by_severity:
            sev = "unknown"
        by_severity[sev].append(f)

    # ── REPORTE MARKDOWN ────────────────────────────────────
    md = [
        f"# 📊 Bug Bounty Report — {target}",
        f"**Fecha:** {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"**Target:** {target}",
        "",
        "---",
        "## 🎯 Resumen Ejecutivo",
        "",
        f"| Métrica | Valor |",
        f"|---------|-------|",
        f"| Subdominios | {len(recon.get('all_subdomains', []))} |",
        f"| Hosts vivos | {len(recon.get('live_hosts', []))} |",
        f"| Puertos abiertos | {len(ports.get('open_ports', []))} |",
        f"| URLs | {len(urls.get('all_urls', []))} |",
        f"| 🔴 Críticos | {len(by_severity['critical'])} |",
        f"| 🟠 Altos | {len(by_severity['high'])} |",
        f"| 🟡 Medios | {len(by_severity['medium'])} |",
        "",
    ]

    # ══════════════════════════════════════════════════════════════════════════════
    # NUEVOS DESCUBRIMIENTOS (DIFF ENGINE)
    # ══════════════════════════════════════════════════════════════════════════════
    diff_data = results.get("diff", {})
    if diff_data and not diff_data.get("is_first_run"):
        new_subs = diff_data.get("new_subdomains", [])
        new_ports = diff_data.get("new_ports", [])
        
        if new_subs or new_ports:
            md.append("## ✨ Novedades desde el último scan")
            if new_subs:
                md.append("### 🌐 Subdominios nuevos")
                for s in new_subs[:10]:
                    domain = s.get("domain") if isinstance(s, dict) else s
                    md.append(f"- `{domain}`")
                if len(new_subs) > 10: md.append(f"*...y {len(new_subs)-10} más.*")
            
            if new_ports:
                md.append("### 🚪 Puertos abiertos nuevos")
                for p in new_ports[:10]:
                    md.append(f"- `{p.get('host')}:{p.get('port')}` ({p.get('service') or 'unknown'})")
            md.append("")

    # ══════════════════════════════════════════════════════════════════════════════
    # INTELIGENCIA Y PRIORIZACIÓN
    # ══════════════════════════════════════════════════════════════════════════════
    prio_targets = intel.get("priority_targets", [])
    if prio_targets:
        md.append("## 🔥 Objetivos de Alta Prioridad")
        md.append("| Target | Score | Razones |")
        md.append("|--------|-------|---------|")
        for t in prio_targets[:5]:
            reasons = ", ".join(t.get("reasons", []))
            md.append(f"| `{t['target']}` | **{t['score']}** | {reasons} |")
        md.append("")

    # ══════════════════════════════════════════════════════════════════════════════
    # INVENTARIO DE SERVICIOS (PUERTOS)
    # ══════════════════════════════════════════════════════════════════════════════
    open_ports = ports.get("open_ports", [])
    if open_ports:
        md.append("## 🛡️ Inventario de Puertos y Servicios")
        md.append("| Host | Puerto | Protocolo | Servicio | Versión |")
        md.append("|------|--------|-----------|----------|---------|")
        for p in open_ports[:20]:
            if isinstance(p, dict):
                md.append(f"| {p.get('host')} | {p.get('port')} | {p.get('protocol')} | {p.get('service')} | {p.get('version')} |")
            else:
                md.append(f"| {target} | {p} | tcp | unknown | N/A |")
        if len(open_ports) > 20: md.append(f"*...y {len(open_ports)-20} puertos más.*")
        md.append("")

    # Hallazgos críticos primero
    for sev in ["critical", "high", "medium", "low"]:
        group = by_severity.get(sev, [])
        if not group:
            continue
        
        emoji = SEVERITY_EMOJI.get(sev, "")
        
        if sev == "critical":
            md.append(f"## 🚨 {emoji} VULNERABILIDADES CRÍTICAS ENCONTRADAS ({len(group)})")
        else:
            md.append(f"## {emoji} {sev.upper()} ({len(group)})")
        
        for i, f in enumerate(group, 1):
            name = f.get("name") or f.get("type", "Hallazgo")
            url_or_raw = f.get("url") or f.get("raw", "")[:80]
            
            md.append(f"### {i}. {name}")
            md.append(f"**URL:** `{url_or_raw}`")
            
            if f.get("cvss"):
                md.append(f"**CVSS:** {f['cvss'].get('base_score', 'N/A')}/10 ({f['cvss'].get('severity', '')})")
            
            if f.get("poc"):
                md.append(f"**PoC:**\n```\n{f['poc']}\n```")
            elif f.get("verification", {}).get("exploitable"):
                md.append(f"**Verificado:** ✅ {f['verification'].get('reason', 'Explotable')}")
            
            md.append("")
        
        md.append("")

    # Hypotheses
    if intel.get("hypotheses"):
        md.append("## 💡 Hipótesis de Ataque Generadas")
        for h in intel["hypotheses"][:5]:
            md.append(f"- **[{h.get('type', '')}]** {h.get('description', '')[:70]}")
        md.append("")

    # Secrets en JS
    if js.get("secrets"):
        md.append("## 🔑 Secrets Detectados en JS")
        for s in js["secrets"][:5]:
            md.append(f"- `{s}`")
        md.append("")

    # Takeovers
    if recon.get("takeovers"):
        md.append("## ⚠️ Subdomain Takeover Candidates")
        for t in recon["takeovers"][:5]:
            md.append(f"- `{t}`")
        md.append("")

    # Footer
    md.append("---")
    md.append(f"*Generado por BugBounty Framework • {datetime.now().strftime('%Y-%m-%d %H:%M')}*")

    report_md = out_dir / "report.md"
    write_lines(report_md, md)
    log(f"📄 Reporte generado: {report_md}", "success")

    # ── REPORTES INDIVIDUALES PARA CADA VULN CRÍTICA ───
    critical_findings = [f for f in findings if f.get("severity", "").lower() in ["critical", "high"]]
    h1_reports = []
    
    for i, f in enumerate(critical_findings, 1):
        h1_report = generate_hackerone_report(target, f)
        h1_file = out_dir / f"hackerone_{i}_{f.get('type', 'vuln').replace(' ', '_')[:20]}.md"
        h1_file.write_text(h1_report)
        h1_reports.append(str(h1_file))
        log(f"  📝 Reporte H1 listo: {h1_file.name}", "success")

    # ── JSON CONSOLIDADO ────────────────────────────────────
    final_json = {
        "target": target,
        "timestamp": ts,
        "summary": {
            "subdomains": len(recon.get("all_subdomains", [])),
            "live_hosts": len(recon.get("live_hosts", [])),
            "open_ports": len(ports.get("open_ports", [])),
            "urls": len(urls.get("all_urls", [])),
            "findings": len(findings),
            "critical": len(by_severity["critical"]),
            "high": len(by_severity["high"]),
        },
        "findings": findings,
        "by_severity": by_severity,
        "hypotheses": intel.get("hypotheses", []),
        "hackerone_reports": h1_reports,
    }
    
    save_json(out_dir / "full_results.json", final_json)
    log(f"📊 JSON consolidado generado", "success")

    return {
        "report_md": str(report_md),
        "h1_reports": h1_reports,
        "findings_count": len(findings),
        "critical_count": len(by_severity["critical"]),
    }