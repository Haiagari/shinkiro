"""
Módulo de Inteligencia y Correlación
- Scoring CVSS automático
- Correlación entre fases
- Generación de hipótesis de ataque
- Priorización inteligente de objetivos
"""

from pathlib import Path
from src.utils import log, save_json, load_json
from .ai_analyzer import ai_analyst

# Mapeo CVSS: vulnerabilidades known a scores
CVSS_MAPPINGS = {
    # Crítico (9.0-10.0)
    "rce": 9.8,
    "remote code execution": 9.8,
    "sql injection": 9.8,
    "sqli": 9.8,
    "subdomain takeover": 8.1,
    "idor": 8.1,
    "broken authentication": 8.1,
    "jwt": 7.5,
    "hardcoded credentials": 9.8,
    "api key": 7.5,
    
    # Alto (7.0-8.9)
    "xss": 7.3,
    "stored xss": 8.1,
    "reflected xss": 7.3,
    "ssrf": 8.2,
    "csrf": 6.5,
    "path traversal": 7.5,
    "lfi": 7.5,
    
    # Medio (4.0-6.9)
    "information disclosure": 5.3,
    "info leak": 5.3,
    "missing security header": 5.3,
    "missing csp": 5.3,
    "open redirect": 5.3,
    "xxe": 6.5,
    
    # Bajo (0.1-3.9)
    "low": 3.9,
}

# Puertos críticos que aumentan score
CRITICAL_PORTS = [3000, 5000, 5678, 6379, 27017, 3306, 5432, 9200, 11211]


def calculate_cvss(vulnerability: str, context: dict = {}) -> dict:
    """
    Calcula score CVSSv3.1 básico para una vulnerabilidad.
    """
    vuln_lower = vulnerability.lower()
    
    # Buscar en mappings conocidos
    base_score = 5.0  # Default medio
    for pattern, score in CVSS_MAPPINGS.items():
        if pattern in vuln_lower:
            base_score = score
            break
    
    #si es target con datos financieros, aumentar
    if context.get("is_fintech"):
        base_score = min(10.0, base_score + 0.5)
    
    # Convertir a vector string simplificado
    if base_score >= 9.0:
        severity = "CRITICAL"
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    elif base_score >= 7.0:
        severity = "HIGH"
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    elif base_score >= 4.0:
        severity = "MEDIUM"
        vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    else:
        severity = "LOW"
        vector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:N"
    
    return {
        "base_score": round(base_score, 1),
        "severity": severity,
        "vector": vector,
    }


def detect_idor_patterns(urls: list) -> list:
    """
    Detecta URLs con potencial IDOR basándose en parámetros numéricos.
    """
    idor_patterns = [
        r"[\?&]id=\d+",
        r"[\?&]user_id=\d+",
        r"[\?&]account=\d+",
        r"[\?&]uid=\d+",
        r"[\?&]order_id=\d+",
        r"[\?&]ref=\w+",
        r"[\?&]token=\w+",
        r"/api/v\d+/users/\d+",
        r"/api/v\d+/accounts/\d+",
        r"/api/v\d+/profile",
    ]
    
    import re
    candidates = []
    
    for url in urls:
        for pattern in idor_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                candidates.append({
                    "url": url,
                    "pattern": pattern,
                    "type": "IDOR_CANDIDATE",
                })
                break  # Solo un match por URL
    
    return candidates


def score_target(target_info: dict, open_ports: list = [], findings: list = []) -> dict:
    """
    Calcula score de prioridad para un target.
    """
    score = 0.0
    reasons = []
    
    # Puertos críticos
    for port_entry in open_ports:
        # Soporte para objetos PortResult (v5.0) y strings (legacy)
        if hasattr(port_entry, 'port'):
            port_num = port_entry.port
        elif isinstance(port_entry, str):
            port_num = int(port_entry.split(":")[-1]) if ":" in port_entry else (int(port_entry) if port_entry.isdigit() else 0)
        else:
            continue

        if port_num in CRITICAL_PORTS:
            score += 1.0
            reasons.append(f"Puerto crítico: {port_num}")
        
        # Puerto 3000 = API backend (alta prioridad)
        if port_num == 3000:
            score += 1.5
            reasons.append("Puerto 3000 = API backend")
    
    # Hallazgos
    for f in findings:
        sev = f.get("severity", "").lower()
        if sev in ["critical", "high"]:
            score += 2.0
            reasons.append(f"Finding {sev}: {f.get('name', '')[:30]}")
    
    # Tecnología
    tech = target_info.get("tech", "").lower()
    if "node" in tech or "api" in tech:
        score += 0.5
        reasons.append(f"Tecnología: {tech}")
    
    return {
        "total_score": round(score, 1),
        "reasons": reasons,
    }


def correlate_findings(context: dict) -> dict:
    """
    Cruza datos de todas las fases para encontrar correlaciones.
    """
    recon = context.get("phases", {}).get("recon", {})
    ports = context.get("phases", {}).get("ports", {})
    urls = context.get("phases", {}).get("urls", {})
    vulns = context.get("phases", {}).get("vulns", {})
    js_analysis = context.get("phases", {}).get("js_analysis", {})
    
    correlations = []
    
    # 1. IDs de puertos con URLs de API
    open_ports = ports.get("open_ports", [])
    all_urls = urls.get("all_urls", [])
    
    api_hosts = []
    for port_entry in open_ports:
        # Soporte para objetos PortResult (v5.0) y strings (legacy)
        if hasattr(port_entry, 'host'):
            host = port_entry.host
            port_num = port_entry.port
        elif isinstance(port_entry, str):
            host = port_entry.split(":")[0] if ":" in port_entry else port_entry
            port_num = int(port_entry.split(":")[-1]) if ":" in port_entry else 0
        else:
            continue

        if port_num in [3000, 5000]:
            # Buscar URLs que pertenezcan a este host
            for url in all_urls:
                if host in url:
                    api_hosts.append({
                        "host": host,
                        "urls": [url for url in all_urls if host in url],
                    })
    
    if api_hosts:
        correlations.append({
            "type": "API_BACKEND",
            "description": "Hosts con puerto API (3000/5000) encontrados",
            "details": api_hosts,
        })
    
    # 2. IDOR candidates
    idor_urls = detect_idor_patterns(all_urls)
    if idor_urls:
        correlations.append({
            "type": "IDOR_CANDIDATES",
            "description": f"{len(idor_urls)} URLs con parámetros sensibles",
            "details": idor_urls[:10],
        })
    
    # 3. Links entre JS endpoints y vulnerabilidades
    js_endpoints = js_analysis.get("endpoints", [])
    if js_endpoints and vulns.get("findings"):
        correlations.append({
            "type": "JS_VULN_LINK",
            "description": "Endpoints en JS pueden estar relacionados con vulns",
            "count": len(js_endpoints),
        })
    
    # 4. Puertos nuevos vs anteriores
    diff = context.get("phases", {}).get("diff", {})
    if diff.get("new_ports"):
        correlations.append({
            "type": "NEW_PORTS",
            "description": f"{len(diff['new_ports'])} puertos nuevos",
            "details": diff["new_ports"],
        })
    
    # 5. INTEGRACIÓN v5.2: Detección de Infraestructura Crítica (DBs, Caches, Automation)
    db_ports = [p for p in open_ports if (hasattr(p, 'port') and p.port in [5432, 6379, 3306, 27017, 5678])]
    if db_ports:
        # Serializamos los objetos PortResult a dicts para que sean JSON serializable
        db_details = [
            {"host": p.host, "port": p.port, "service": p.service} if hasattr(p, 'host') else p 
            for p in db_ports
        ]
        correlations.append({
            "type": "INTERNAL_DB_EXPOSURE",
            "description": f"{len(db_ports)} servicios de datos expuestos",
            "details": db_details
        })
    
    return {
        "correlations": correlations,
        "api_hosts_count": len(api_hosts),
        "idor_candidates_count": len(idor_urls),
        "db_exposure_count": len(db_ports)
    }


def generate_hypotheses(correlations: dict, target: str) -> list:
    """
    Genera hipótesis de ataque automáticas basadas en correlaciones.
    """
    hypotheses = []
    
    for corr in correlations.get("correlations", []):
        corr_type = corr.get("type", "")
        
        if corr_type == "IDOR_CANDIDATES":
            for detail in corr.get("details", [])[:3]:
                hypotheses.append({
                    "type": "IDOR",
                    "url": detail.get("url", ""),
                    "description": f"Parámetro {detail.get('pattern', '')} puede ser vulnerable a IDOR",
                    "severity": "HIGH",
                    "cvss": calculate_cvss("idor"),
                    "verification": f"Cambiar el valor numérico y verificar acceso no autorizado",
                })
        
        elif corr_type == "API_BACKEND":
            for host in corr.get("details", [])[:2]:
                hypotheses.append({
                    "type": "API_EXPOSED",
                    "url": host.get("host", ""),
                    "description": "API expuesta en puerto sin autenticación visible",
                    "severity": "HIGH",
                    "cvss": calculate_cvss("idor"),
                    "verification": "Probar endpoints /api/v1/users, /api/v1/profile sin token",
                })
        
        elif corr_type == "INTERNAL_DB_EXPOSURE":
            for port_obj in corr.get("details", []):
                # Extraer solo el número de puerto (v5.2 fix)
                p_num = port_obj.get('port') if isinstance(port_obj, dict) else (port_obj.port if hasattr(port_obj, 'port') else port_obj)
                
                if p_num == 5678:
                    hypotheses.append({
                        "type": "AUTOMATION_PANEL",
                        "url": f"http://{target}:{p_num}",
                        "description": f"Panel de automatización (n8n) expuesto en puerto {p_num}. Acceso no autorizado podría permitir ejecución de flujos de trabajo críticos.",
                        "severity": "CRITICAL",
                        "cvss": 9.8,
                        "verification": "Verificar si el panel requiere autenticación o permite acceso directo."
                    })
                else:
                    hypotheses.append({
                        "type": "EXPOSED_DATABASE",
                        "url": f"{target}:{p_num}",
                        "description": f"Servicio de datos expuesto en puerto {p_num}. Posible falta de autenticación o acceso desde red no autorizada.",
                        "severity": "CRITICAL" if p_num != 6379 else "HIGH",
                        "cvss": 9.5 if p_num != 6379 else 8.0,
                        "verification": f"Intentar conexión básica (nmap --script redis-info o pg_isready) para confirmar exposición."
                    })
        
        elif corr_type == "JS_VULN_LINK":
            hypotheses.append({
                "type": "ENDPOINT_HIDDEN",
                "description": "Endpoints descubiertos en JS pueden no estar documentados",
                "severity": "MEDIUM",
                "cvss": calculate_cvss("information disclosure"),
                "verification": "Probar todos los endpoints encontrados en JS",
            })
    
    return hypotheses


def run_intelligence(target: str, out_dir: Path, args, context: dict = {}) -> dict:
    """
    Fase de Inteligencia: Scoring, correlación y hipótesis.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    log("Iniciando análisis de inteligencia...", "info")
    
    # Fase 1: Correlacionar hallazgos
    correlations = correlate_findings(context)
    log(f"  • {len(correlations.get('correlations', []))} correlaciones encontradas", "success")
    
    # Fase 2: Generar hipótesis
    hypotheses = generate_hypotheses(correlations, target)
    log(f"  • {len(hypotheses)} hipótesis generadas", "success")
    
    # Fase 3: Scoring de todos los targets
    recon = context.get("phases", {}).get("recon", {})
    ports = context.get("phases", {}).get("ports", {})
    vulns = context.get("phases", {}).get("vulns", {})
    
    live_hosts = recon.get("live_hosts", [])
    open_ports = ports.get("open_ports", [])
    findings = vulns.get("findings", [])
    
    # Calcular scores
    top_targets = []
    for host in live_hosts[:20]:
        target_info = {"host": host, "tech": ""}  # httpx ya detecto tech
        scored = score_target(target_info, open_ports, findings)
        top_targets.append({
            "host": host,
            "score": scored["total_score"],
            "reasons": scored["reasons"],
        })
    
    # Ordenar por score
    top_targets.sort(key=lambda x: x["score"], reverse=True)
    
    # Fase 4: Análisis de IA (si está configurado)
    ai_analysis = {}
    config = context.get("config", {})
    if config.get("ai", {}).get("gemini_api_key") or config.get("ai", {}).get("claude_api_key"):
        log("  • Ejecutando análisis con IA...", "info")
        # v8.0 Update: Use the new Analyst class
        ai_analysis = ai_analyst.generate_finding_narrative(context)
    
    # Resultados
    results = {
        "target": target,
        "correlations": correlations,
        "hypotheses": hypotheses,
        "top_targets": top_targets[:10],
        "total_attack_surface": len(live_hosts),
        "ai_analysis": ai_analysis,
    }
    
    # Scoring CVSS para cada finding
    scored_findings = []
    for f in findings:
        cvss = calculate_cvss(f.get("name", ""), {"is_fintech": "fintech" in target.lower()})
        scored_findings.append({
            **f,
            "cvss": cvss,
        })
    results["scored_findings"] = scored_findings
    
    # Persistencia
    save_json(out_dir / "results.json", results)
    
    # Loguear top
    log(f"Inteligencia completada.", "success")
    if top_targets:
        top = top_targets[0]
        log(f"🎯 Objetivo prioritario: {top['host']} (Score: {top['score']})", "warn")
        for reason in top.get("reasons", [])[:2]:
            log(f"   └ {reason}", "info")
    
    if hypotheses:
        log(f"💡 Hipótesis principal: {hypotheses[0].get('description', '')[:60]}", "info")
    
    # ══════════════════════════════════════════════════════════════════════════════
    # INTEGRACIÓN v5.0: Persistencia de Hipótesis y Workflow
    # ══════════════════════════════════════════════════════════════════════════════
    from src.storage.database import SessionLocal
    from src.storage.models import Hypothesis, Target
    from src.core.target_normalizer import normalize_lookup_target
    from src.workflow.engine import workflow_engine
    from src.workflow.states import WorkflowState
    import uuid

    db = SessionLocal()
    try:
        # Obtener target_id
        target_obj = db.query(Target).filter(Target.domain == normalize_lookup_target(target)).first()
        t_id = target_obj.id if target_obj else None
        
        for h_data in hypotheses:
            h_id = f"hyp_{uuid.uuid4().hex[:8]}"
            
            # Cálculo robusto de confianza (v5.2 fix)
            cvss_data = h_data.get("cvss", 0.0)
            if isinstance(cvss_data, dict):
                confidence = cvss_data.get("base_score", 0.0) / 10.0
            else:
                confidence = float(cvss_data) / 10.0

            # v6.0 Autopilot Logic: Auto-approve high confidence hypotheses
            AUTOPILOT_THRESHOLD = 0.95
            status = WorkflowState.PENDING_APPROVAL
            notes_prefix = ""
            
            if confidence >= AUTOPILOT_THRESHOLD:
                status = WorkflowState.APPROVED
                notes_prefix = "AUTOPILOT: Auto-approved due to high confidence. "
                log(f"🚀 {notes_prefix} ({h_id})", "warn")

            new_hypo = Hypothesis(
                id=h_id,
                target_id=t_id,
                type=h_data.get("type"),
                description=h_data.get("description"),
                url=h_data.get("url"),
                severity=h_data.get("severity"),
                confidence=confidence,
                status=status,
                signals={"correlations": results.get("correlations")},
                validation_method=h_data.get("verification")
            )
            db.add(new_hypo)
            # Registrar en el workflow
            workflow_engine.add_step(t_id, WorkflowState.HYPOTHESIZED, notes=f"{notes_prefix}Hypothesis {h_id} generated")
        
        db.commit()
        log(f"✅ {len(hypotheses)} hipótesis persistidas para revisión humana.", "success")
    except Exception as e:
        db.rollback()
        log(f"❌ Error persistiendo hipótesis: {str(e)}", "error")
    finally:
        db.close()

    return results
