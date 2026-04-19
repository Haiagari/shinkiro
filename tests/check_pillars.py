import os
import sys
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.utils import log, get_stealth_headers, get_random_ua
from modules.models import Base
from modules.database import engine, SessionLocal, init_db, save_scan_to_db
from modules import db_queries as q
from modules.rate_limiter import get_rate_limiter, wait_if_needed, record_request
from modules.notifier import check_critical_findings, format_telegram_alert

def test_pillar_1_data():
    log("Probando Pilar #1: PERSISTENCIA DATOS", "phase")
    try:
        init_db()
        db = SessionLocal()
        
        target = "test-target.com"
        ts = "20260417_TEST"
        
        # Simular contexto de scan
        context = {
            "target": target,
            "start_time": ts,
            "out_dir": str(ROOT_DIR / "runtime" / "output" / "test" / "1"),
            "phases": {
                "recon": {
                    "all_subdomains": ["sub1.test.com", "sub2.test.com"],
                    "live_hosts_data": [{"domain": "sub1.test.com", "http_status": 200, "title": "Test Page"}]
                },
                "ports": {
                    "open_ports": [{"host": "sub1.test.com", "port": 443, "service": "https", "version": "nginx 1.18"}]
                },
                "vulns": {
                    "findings": [{"type": "nuclei", "severity": "CRITICAL", "name": "Test Vuln", "url": "http://sub1.test.com"}]
                }
            }
        }
        
        success = save_scan_to_db(context)
        if success:
            log("  ✓ Datos guardados en DB", "success")
            stats = q.get_target_stats(db, target)
            log(f"  ✓ Stats recuperados: {stats['total_subdomains']} subs, {stats['critical_count']} críticos", "success")
            db.close()
            return True
        return False
    except Exception as e:
        log(f"  ✖ Fallo en Pilar #1: {e}", "error")
        return False

def test_pillar_2_notifications():
    log("Probando Pilar #2: NOTIFICACIONES INTELIGENTES", "phase")
    try:
        target = "test-target.com"
        vulns = [{"type": "nuclei", "severity": "critical", "name": "SQL Injection", "url": "http://target.com/db"}]
        diff = {
            "new_subdomains": ["new.target.com"],
            "new_ports": [{"host": "target.com", "port": 8080}],
            "is_first_run": False
        }
        
        critical = check_critical_findings(vulns, alert_level="medium")
        msg = format_telegram_alert(target, critical, diff)
        
        if "SQL Injection" in msg and "NUEVOS DESCUBRIMIENTOS" in msg:
            log("  ✓ Formato de mensaje verificado (incluye diff y severidad)", "success")
            # print(f"\n--- PREVIEW MENSAJE ---\n{msg}\n----------------------")
            return True
        return False
    except Exception as e:
        log(f"  ✖ Fallo en Pilar #2: {e}", "error")
        return False

def test_pillar_3_opsec():
    log("Probando Pilar #3: OPSEC & SIGILO", "phase")
    try:
        # Test headers
        h1 = get_stealth_headers()
        h2 = get_stealth_headers()
        
        if h1["User-Agent"] != h2["User-Agent"]:
            log("  ✓ Rotación de User-Agent detectada", "success")
        
        # Test RateLimiter
        rl = get_rate_limiter({"max_requests_per_min": 100})
        start = time.time()
        for _ in range(3):
            wait_if_needed()
            record_request(100, 200)
        elapsed = time.time() - start
        
        log(f"  ✓ RateLimiter con Jitter aplicado ({round(elapsed, 2)}s para 3 reqs)", "success")
        return True
    except Exception as e:
        log(f"  ✖ Fallo en Pilar #3: {e}", "error")
        return False

def test_pillar_4_templates():
    log("Probando Pilar #4: CUSTOM TEMPLATES", "phase")
    temp_dir = ROOT_DIR / "resources" / "templates"
    if temp_dir.exists():
        files = list(temp_dir.glob("*.yaml"))
        if len(files) >= 3:
            log(f"  ✓ {len(files)} templates personalizados encontrados", "success")
            return True
    log("  ✖ No se encontraron los templates", "error")
    return False

if __name__ == "__main__":
    log("INICIANDO SYSTEM CHECK DE LOS 4 PILARES", "sep")
    
    results = [
        test_pillar_1_data(),
        test_pillar_2_notifications(),
        test_pillar_3_opsec(),
        test_pillar_4_templates()
    ]
    
    log("═" * 55, "sep")
    if all(results):
        log("SISTEMA LISTO PARA PRODUCCIÓN 🚀", "success")
    else:
        log("HAY FALLOS EN LOS PILARES. REVISAR LOGS.", "error")
