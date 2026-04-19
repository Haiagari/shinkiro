"""
Enrichment de IPs con Shodan, Censys, y otras fuentes.
Obtiene info adicional: puertos, tecnologías, vulnerabilidades.
"""

import requests
from pathlib import Path
from .utils import log, load_config, save_json

# API Keys desde config
def get_api_keys() -> dict:
    config = load_config()
    return config.get("api_keys", {})

def query_shodan(ip: str, api_key: str = None) -> dict:
    """
    Consulta Shodan para una IP.
    Retorna: puertos, servicios, vulnerabilidades, organización.
    """
    if not api_key:
        api_keys = get_api_keys()
        api_key = api_keys.get("shodan", "")
    
    if not api_key:
        return {"error": "Shodan API key no configurada"}
    
    log(f"Consultando Shodan: {ip}", "info")
    
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        r = requests.get(url, timeout=15)
        
        if r.status_code == 200:
            data = r.json()
            return {
                "ip": ip,
                "org": data.get("org", ""),
                "os": data.get("os", ""),
                "ports": data.get("ports", []),
                "services": [
                    {"product": s.get("product"), "version": s.get("version")}
                    for s in data.get("data", [])
                ],
                "vulns": data.get("vulns", []),
                "tags": data.get("tags", []),
                "asn": data.get("asn", ""),
                "isp": data.get("isp", ""),
            }
        elif r.status_code == 429:
            return {"error": "Shodan rate limit excedido"}
        else:
            return {"error": f"Shodan error {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def query_censys(ip: str, api_id: str = None, api_secret: str = None) -> dict:
    """
    Consulta Censys para una IP.
    Retorna: certificados, servicios detallados, banner grab.
    """
    if not api_id or not api_secret:
        api_keys = get_api_keys()
        api_id = api_keys.get("censys_id", "")
        api_secret = api_keys.get("censys_secret", "")
    
    if not api_id or not api_secret:
        return {"error": "Censys API keys no configuradas"}
    
    log(f"Consultando Censys: {ip}", "info")
    
    try:
        from base64 import b64encode
        
        auth = b64encode(f"{api_id}:{api_secret}".encode()).decode()
        
        url = f"https://censys.io/api/v1/search/ipv4"
        r = requests.post(
            url,
            json={"query": ip, "page": 1, "page_size": 5},
            headers={"Authorization": f"Basic {auth}"},
            timeout=15
        )
        
        if r.status_code == 200:
            data = r.json()
            results = data.get("results", [])
            if results:
                return {
                    "ip": ip,
                    "protocols": results[0].get("protocols", []),
                    "services": results[0].get("services", []),
                    "certificates": [
                        c.get("parsed.subject_dn", "")
                        for c in results[0].get(" certificates", [])
                    ],
                }
        return {"error": f"Censys error {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def query_crtsh(cert_domain: str) -> dict:
    """
    Consulta crt.sh para certificados de un dominio.
    """
    log(f"Consultando crt.sh: {cert_domain}", "info")
    
    try:
        url = f"https://crt.sh/?q={cert_domain}&output=json"
        r = requests.get(url, timeout=30)
        
        if r.status_code == 200:
            import json
            certs = json.loads(r.text)
            
            return {
                "domain": cert_domain,
                "certificates": [
                    {
                        "issuer": c.get("issuer_name", ""),
                        "date": c.get("not_before", ""),
                        "id": c.get("id", ""),
                    }
                    for c in certs[:10]  # Máximo 10
                ],
            }
    except Exception as e:
        return {"error": str(e)}

def enrich_hosts(hosts: list, config: dict = None) -> dict:
    """
    Enriquece una lista de hosts con datos de Shodan/Censys.
    """
    from .utils import save_json
    
    cfg = config or {}
    results = {
        "shodan": {},
        "censys": {},
        "crt_sh": {},
    }
    
    shodan_key = cfg.get("api_keys", {}).get("shodan", "")
    censys_id = cfg.get("api_keys", {}).get("censys_id", "")
    censys_secret = cfg.get("api_keys", {}).get("censys_secret", "")
    
    # extraer IPs de los hosts
    ips = []
    for h in hosts[:10]:  # Max 10 para no quem ar API
        # Limpiar host
        host = h.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        
        # Intentar resolver IP (básico)
        try:
            import socket
            ip = socket.gethostbyname(host)
            ips.append((host, ip))
        except:
            continue
    
    log(f"Enriqueciendo {len(ips)} hosts...", "info")
    
    # Shodan
    if shodan_key:
        for host, ip in ips:
            result = query_shodan(ip, shodan_key)
            if "error" not in result:
                results["shodan"][host] = result
                log(f"  ✓ {host}: {len(result.get('ports', []))} puertos", "success")
    
    # Censys
    if censys_id and censys_secret:
        for host, ip in ips:
            result = query_censys(ip, censys_id, censys_secret)
            if "error" not in result:
                results["censys"][host] = result
    
    # crt.sh para los primeros 3
    for host, ip in ips[:3]:
        result = query_crtsh(host)
        if result.get("certificates"):
            results["crt_sh"][host] = result
    
    return results

def run_enrichment(target: str, out_dir: Path, context: dict) -> dict:
    """
    Orquestador de enrichment.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    
    recon = context.get("phases", {}).get("recon", {})
    live_hosts = recon.get("live_hosts", [])
    
    if not live_hosts:
        log("Sin live hosts para enriquecer", "warn")
        return {"out_dir": str(out_dir)}
    
    log(f"Enriqueciendo {len(live_hosts[:10])} hosts...", "info")
    
    results = enrich_hosts(live_hosts, context.get("config", {}))
    
    # Guardar
    save_json(out_dir / "enrichment.json", results)
    
    # Resumen
    total_shodan = len(results.get("shodan", {}))
    total_censys = len(results.get("censys", {}))
    
    log(f"Enrichment completado: {total_shodan} Shodan, {total_censys} Censys", "success")
    
    # Agregar a context para otras fases
    context["phases"]["enrichment"] = results
    
    return {
        "shodan": total_shodan,
        "censys": total_censys,
        "out_dir": str(out_dir),
    }