"""
OzyRecon v6.0 — Advanced OPSEC Orchestrator
Coordina identidades sintéticas, evasión de WAF y kill-switch.
"""

from typing import Optional, Dict, Any
from src.opsec.rate_limiter import get_rate_limiter
from src.opsec.waf_detector import detect_waf, adjust_strategy
from src.opsec.kill_switch import check_kill
from src.opsec.chameleon import chameleon

class OPSECManager:
    """
    v6.0 — Orquestador de Sigilo Avanzado.
    """
    
    def __init__(self, target: str, db_session):
        self.target = target
        self.db = db_session
        self.rate_limiter = get_rate_limiter()
        self.waf_detected = None
        self.identity = chameleon.generate_identity()
    
    def refresh_identity(self):
        """Cambia la identidad completa para rotación nivel APT."""
        self.identity = chameleon.generate_identity()

    def get_stealth_params(self) -> Dict[str, Any]:
        """
        Retorna el paquete completo de sigilo para ser inyectado en los requests.
        """
        return {
            "headers": self.identity.headers,
            "tls_profile": self.identity.tls_profile,
            "rpm": self.rate_limiter.current_rpm,
            "waf_strategy": self.waf_detected.get("strategy") if self.waf_detected else None
        }

    def pre_flight_check(self) -> Dict[str, Any]:
        """
        Ejecuta verificaciones de OPSEC antes de iniciar el scan.
        Detecta WAF, ajusta estrategia, e inicializa el-rate limiter.
        """
        from src.storage.queries import DBQueries
        db = DBQueries(self.db)
        
        # 1. Revisar memoria existente del WAF
        waf_memory = db.get_agent_memory(self.target, "waf_detected")
        if waf_memory and waf_memory.value:
            self.waf_detected = waf_memory.value
            return {"waf": self.waf_detected, "source": "memory", "identity": self.identity.name}
        
        # 2. Si no hay memoria, detectar WAF en el target
        url = f"https://{self.target}"
        waf = detect_waf(url)
        
        if waf.get("detected"):
            self.waf_detected = waf
            db.set_agent_memory(self.target, "waf_detected", waf)
        
        # 3. Aplicar estrategia si hay WAF
        if self.waf_detected:
            strategy = adjust_strategy(waf)
            self.rate_limiter.current_rpm = min(strategy.get("threads", 50), 25)
            
            return {
                "waf": self.waf_detected,
                "strategy": strategy,
                "source": "detection",
                "action": "Rate reduced due to WAF protection",
                "identity": self.identity.name
            }
        
        return {"waf": None, "strategy": None, "identity": self.identity.name}
    
    def record_response(self, response_time_ms: float = 0, status_code: int = 200):
        """Registra cada response para el rate limiter adaptativo."""
        self.rate_limiter.record_request(response_time_ms, status_code)
    
    def should_continue(self) -> bool:
        """Verifica si el kill-switch fue activado."""
        return not check_kill()
    
    def apply_jitter(self):
        """Aplica una demora aleatoria para evasión."""
        from src.opsec.jitter import default_jitter
        default_jitter.sleep()
