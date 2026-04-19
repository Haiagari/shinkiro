"""
Módulo de Exportación
Genera archivos compatibles con Burp Suite, CSV, JSON, y otros formatos.
"""

import json
import csv
from datetime import datetime
from pathlib import Path
from src.utils import log

def generate_burp_scope(targets: list, out_file: Path):
    """
    Genera un archivo XML de Scope para Burp Suite.
    """
    import xml.etree.ElementTree as ET
    
    root = ET.Element("target")
    scope = ET.SubElement(root, "scope")
    
    for t in targets:
        host = t.replace("https://", "").replace("http://", "").split("/")[0]
        
        include = ET.SubElement(scope, "include")
        ET.SubElement(include, "host").text = f"^{host.replace('.', r'\.')}$"
        ET.SubElement(include, "protocol").text = "any"
    
    tree = ET.ElementTree(root)
    with open(out_file, "wb") as f:
        tree.write(f, encoding="UTF-8", xml_declaration=True)
    
    log(f"Burp Scope generado: {out_file}", "success")

def generate_burp_sar(findings: list, out_file: Path):
    """
    Genera archivo SAR (Serialized Audit Report) de Burp.
    Formato XML que Burp Suite Professional puede importar.
    """
    import xml.etree.ElementTree as ET
    from xml.dom import minidom
    
    SEVERITY_MAP = {
        "critical": "High",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Information",
        "unknown": "Information",
    }
    
    # Crear estructura SAR
    issues = ET.Element("issues")
    
    for i, f in enumerate(findings, 1):
        issue = ET.SubElement(issues, "issue")
        
        # Tipo
        type_elem = ET.SubElement(issue, "type")
        type_elem.text = str(f.get("type", "Unknown"))
        
        # Nombre
        name_elem = ET.SubElement(issue, "name")
        name_elem.text = f.get("name", f.get("type", "Vulnerability"))
        
        # Severidad
        sev = SEVERITY_MAP.get(f.get("severity", "medium").lower(), "Medium")
        severity = ET.SubElement(issue, "severity")
        severity.text = sev
        
        # Confianza
        confidence = ET.SubElement(issue, "confidence")
        confidence.text = "Certain" if f.get("verification", {}).get("exploitable") else "Firm"
        
        # Host
        url = f.get("url", "")
        host = url.split("/")[2] if "//" in url else url
        host_elem = ET.SubElement(issue, "host")
        host_elem.text = host
        host_elem.set("handler", host)
        
        # Path
        path_elem = ET.SubElement(issue, "path")
        path_elem.text = url.split(host)[1] if host in url else url
        
        # URL completa
        url_elem = ET.SubElement(issue, "url")
        url_elem.text = url
        
        # Description
        desc_elem = ET.SubElement(issue, "description")
        desc_elem.text = f.get("raw", f.get("name", ""))[:500]
        
        # Background
        bg_elem = ET.SubElement(issue, "background")
        bg_elem.text = f"Found by BugBounty Framework on {datetime.now().isoformat()}"
        
        # Remedie
        rem_elem = ET.SubElement(issue, "remediation")
        rem_elem.text = f.get("poc", "N/A")[:200]
        
        # Request/Response (si hay)
        req_elem = ET.SubElement(issue, "requestbaselines")
        req_elem.text = ""
        
        res_elem = ET.SubElement(issue, "responsebaselines")
        res_elem.text = ""
    
    # Crear documento
    tree = ET.ElementTree(issues)
    
    # Pretty print
    xml_str = minidom.parseString(ET.tostring(issues, encoding="unicode")).toprettyxml(indent="  ")
    
    out_file.write_text(xml_str)
    log(f"Burp SAR generado: {out_file}", "success")

def generate_csv(findings: list, out_file: Path):
    """
    Genera CSV para Excel/Google Sheets.
    """
    if not findings:
        out_file.write_text("No findings")
        return
    
    fieldnames = ["severity", "name", "url", "type", "cvss", "poc"]
    
    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for f in findings:
            cvss = f.get("cvss", {}).get("base_score", "") if f.get("cvss") else ""
            writer.writerow({
                "severity": f.get("severity", "").upper(),
                "name": f.get("name", ""),
                "url": f.get("url", ""),
                "type": f.get("type", ""),
                "cvss": cvss,
                "poc": (f.get("poc") or "")[:100],
            })
    
    log(f"CSV generado: {out_file}", "success")

def generate_json_report(findings: list, out_file: Path):
    """
    Genera JSON estructurado para integrar con otras herramientas.
    """
    report = {
        "generated": datetime.now().isoformat(),
        "total_findings": len(findings),
        "by_severity": {},
        "findings": [],
    }
    
    # Agrupar por severidad
    by_sev = {}
    for f in findings:
        sev = f.get("severity", "unknown").lower()
        by_sev[sev] = by_sev.get(sev, 0) + 1
    report["by_severity"] = by_sev
    
    # Agregar findings
    for f in findings:
        report["findings"].append({
            "severity": f.get("severity", "").upper(),
            "name": f.get("name", ""),
            "url": f.get("url", ""),
            "type": f.get("type", ""),
            "cvss": f.get("cvss", {}).get("base_score") if f.get("cvss") else None,
            "vector": f.get("cvss", {}).get("vector") if f.get("cvss") else None,
            "poc": f.get("poc"),
            "verified": f.get("verification", {}).get("exploitable") if f.get("verification") else False,
        })
    
    out_file.write_text(json.dumps(report, indent=4))
    log(f"JSON consolidado generado: {out_file}", "success")

def generate_newline_list(urls: list, out_file: Path):
    """
    Genera lista simple (una URL por línea) para usar con otras herramientas.
    """
    out_file.write_text("\n".join(urls))
    log(f"Lista de URLs generada: {out_file} ({len(urls)} URLs)", "success")

def run_exporter(target: str, out_dir: Path, context: dict):
    """
    Orquestador de exportación - todos los formatos.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    
    # Extraer datos
    recon = context.get("phases", {}).get("recon", {})
    vulns = context.get("phases", {}).get("vulns", {})
    urls = context.get("phases", {}).get("urls", {})
    
    live_hosts = recon.get("live_hosts", [target])
    findings = vulns.get("findings", [])
    all_urls = urls.get("all_urls", [])
    
    results = {}
    
    # 1. Burp Scope XML
    generate_burp_scope(live_hosts, out_dir / "burp_scope.xml")
    results["burp_scope"] = str(out_dir / "burp_scope.xml")
    
    # 2. Burp SAR (importante!)
    if findings:
        generate_burp_sar(findings, out_dir / "burp_findings.sar")
        results["burp_sar"] = str(out_dir / "burp_findings.sar")
        log(f"📂 Importar en Burp: {out_dir / 'burp_findings.sar'}", "success")
    
    # 3. CSV
    if findings:
        generate_csv(findings, out_dir / "findings.csv")
        results["csv"] = str(out_dir / "findings.csv")
    
    # 4. JSON
    generate_json_report(findings, out_dir / "all_findings.json")
    results["json"] = str(out_dir / "all_findings.json")
    
    # 5. Lista de URLs
    if all_urls:
        generate_newline_list(all_urls, out_dir / "all_urls.txt")
        results["urls"] = str(out_dir / "all_urls.txt")
    
    # 6. Live hosts
    generate_newline_list(live_hosts, out_dir / "live_hosts.txt")
    results["hosts"] = str(out_dir / "live_hosts.txt")
    
    log(f"Exportación completa: {len(results)} archivos", "success")
    return results