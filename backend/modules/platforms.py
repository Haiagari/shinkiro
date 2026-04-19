"""
Report Generator para múltiples plataformas de Bug Bounty.
- HackerOne
- Bugcrowd
- OpenBB
- Immunefi
"""

import json
from datetime import datetime
from pathlib import Path
from .utils import log, load_config

def generate_hackerone_report(vuln: dict) -> str:
    """
    Genera reporte listo para HackerOne (formato exacto).
    """
    severity = vuln.get("severity", "medium").upper()
    name = vuln.get("name", "Vulnerability")
    url = vuln.get("url", "")
    cvss = vuln.get("cvss", {})
    
    report = f"""# {name} en [TARGET]

## Severidad
{severity}

## Descripción
Se identificó una vulnerabilidad de tipo **{name}** en el endpoint `{url}`.

La aplicación no implementa correctamente la validación de acceso/entradas.

## Pasos para reproducir
1. Navegar a `{url}`
2. [Realizar acción específica]
3. Observar comportamiento inesperado

## Impacto
[Describir impacto concreto]

## Remedio
[Recomendación de corrección]

## Referencias
- OWASP Top 10
- CWE: [N/A]

---
*Report generado por BugBounty Framework • {datetime.now().strftime('%Y-%m-%d')}*"""
    return report

def generate_bugcrowd_report(vuln: dict) -> str:
    """
    Generates report ready for Bugcrowd.
    """
    severity = vuln.get("severity", "medium").upper()
    name = vuln.get("name", "Vulnerability")
    url = vuln.get("url", "")
    
    # Bugcrowd usa un formato diferente
    report = f"""**Vulnerability:** {name}
**Severity:** {severity}
**URL:** {url}

### Description
[Description of the vulnerability]

### Steps to Reproduce
1. Go to {url}
2. [Action]
3. [Observe]

### Impact
[Business impact]

### Remediation
[How to fix]"""
    return report

def generate_immunefi_report(vuln: dict) -> str:
    """
    Generates report ready for Immunefi.
    """
    severity = vuln.get("severity", "medium").upper()
    name = vuln.get("name", "Vulnerability")
    url = vuln.get("url", "")
    
    report = f"""# {name}

**Severity:** {severity}

## Vulnerability Details
- **Type:** {name}
- **Target:** {url}

## Description
[Description]

## Proof of Concept
```
[POC]
```

## Impact
[Impact]

## Remediation
[Fix]"""
    return report

def generate_openbb_report(vuln: dict) -> str:
    """
    Genera reporte para OpenBB (formato markdown).
    """
    severity = vuln.get("severity", "medium").upper()
    name = vuln.get("name", "Vulnerability")
    url = vuln.get("url", "")
    
    return f"""# {name}

| Campo | Valor |
|-------|-------|
| Severidad | {severity} |
| URL | {url} |
| Tipo | {name} |

## Descripción
[Descripción]

## PoC
```
[POC]
```

## Impacto
[Impacto]

## Fix
[Solución]"""

def get_platform_format(platform: str, vuln: dict) -> str:
    """
    Obtiene el formato correcto según la plataforma.
    """
    formats = {
        "hackerone": generate_hackerone_report,
        "bugcrowd": generate_bugcrowd_report,
        "immunefi": generate_immunefi_report,
        "openbb": generate_openbb_report,
    }
    
    generator = formats.get(platform.lower(), generate_hackerone_report)
    return generator(vuln)

def export_all_platforms(target: str, findings: list, out_dir: Path) -> dict:
    """
    Exporta reportes para TODAS las plataformas.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    
    platforms = ["hackerone", "bugcrowd", "immunefi", "openbb"]
    
    results = {}
    
    critical_findings = [f for f in findings if f.get("severity", "").lower() in ["critical", "high"]]
    
    if not critical_findings:
        log("No hay hallazgos críticos para exportar", "warn")
        return {}
    
    for platform in platforms:
        platform_dir = out_dir / platform
        platform_dir.mkdir(exist_ok=True)
        
        for i, vuln in enumerate(critical_findings, 1):
            content = get_platform_format(platform, vuln)
            
            filename = f"{i}_{vuln.get('type', 'vuln')[:20]}.md"
            (platform_dir / filename).write_text(content)
        
        results[platform] = str(platform_dir)
        log(f"✓ Reportes {platform}: {len(critical_findings)} archivos", "success")
    
    return results

def submit_to_hackerone(program: str, report_content: str, api_key: str) -> dict:
    """
    Envía reporte a HackerOne vía API.
    NOTA: Requiere API key de programa específico.
    """
    log(f"Submitiendo a HackerOne (program: {program})...", "info")
    
    # Placeholder - implementar con la API real de H1
    # https://api.hackerone.com/v1/reports
    
    return {
        "status": "not_implemented",
        "message": "Implementar con API key de programa H1",
    }

def run_platform_exporter(target: str, findings: list, out_dir: Path) -> dict:
    """
    Orquestador de exportación multi-plataforma.
    """
    results = export_all_platforms(target, findings, out_dir)
    
    # También generar JSON consolidado por plataforma
    save_json = out_dir / "platforms_summary.json"
    
    summary = {
        "target": target,
        "findings_count": len(findings),
        "platforms": list(results.keys()),
        "exported": datetime.now().isoformat(),
    }
    
    save_json.write_text(json.dumps(summary, indent=4))
    
    return results