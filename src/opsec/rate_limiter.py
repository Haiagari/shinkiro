"""
Rate Limiter Automático
Ajusta la velocidad automáticamente para no romper el target.
"""

import time
from threading import Lock
import random
from src.core.logging import get_logger

logger = get_logger('rate-limiter')

class RateLimiter:
    """
    Rate limiter adaptativo.
    Enhanced: Jitter aleatorio y detección de baneo (Kill-switch).
    """
    
    def __init__(self, config: dict = None):
        cfg = config or {}
        
        self.enabled = cfg.get("enabled", True)
        self.max_rpm = cfg.get("max_requests_per_min", 200)
        self.check_interval = cfg.get("check_interval", 10)
        self.error_threshold = cfg.get("error_threshold", 10) # Umbral para bajar velocidad
        self.ban_threshold = cfg.get("ban_threshold", 50)    # Umbral para pánico (kill-switch)
        self.slow_threshold_ms = cfg.get("slow_mode_threshold", 1000)
        
        self.jitter_range = (0.1, 0.5) # Rango de segundos aleatorios
        
        self.requests = []
        self.errors = 0
        self.consecutive_403 = 0
        self.is_banned = False
        
        self.current_rpm = self.max_rpm
        self.lock = Lock()
        
        logger.info(f"RateLimiter: max {self.max_rpm} req/min | Jitter activado")
    
    def can_request(self) -> bool:
        if self.is_banned:
            return False
        if not self.enabled:
            return True
        
        with self.lock:
            now = time.time()
            self.requests = [t for t in self.requests if now - t < 60]
            return len(self.requests) < self.current_rpm
    
    def wait_if_needed(self):
        if not self.enabled or self.is_banned:
            return
        
        # 1. Aplicar Jitter (aleatoriedad para evitar detección de patrones)
        jitter = random.uniform(*self.jitter_range)
        time.sleep(jitter)
        
        # 2. Controlar RPM
        while not self.can_request():
            if self.is_banned: break
            time.sleep(1)
    
    def record_request(self, response_time_ms: float = 0, status_code: int = 200):
        """Registrar un request y ajustar velocidad."""
        with self.lock:
            self.requests.append(time.time())
            
            # Detección de baneo (403 Forbidden o 429 Too Many Requests)
            if status_code in [403, 429]:
                self.consecutive_403 += 1
                self.errors += 1
                if self.consecutive_403 >= self.ban_threshold:
                    self._panic_kill_switch()
                else:
                    self._reduce_speed(f"status {status_code}")
            else:
                self.consecutive_403 = 0
                if self.errors > 0:
                    self.errors = max(0, self.errors - 1)
            
            # Ajuste por tiempo de respuesta
            if response_time_ms > self.slow_threshold_ms:
                self._reduce_speed("target lento")
    
    def _reduce_speed(self, reason: str):
        old_rpm = self.current_rpm
        self.current_rpm = max(5, int(self.current_rpm * 0.5))
        if old_rpm != self.current_rpm:
            logger.warning(f"OPSEC: {reason} - bajando a {self.current_rpm} RPM")
    
    def _panic_kill_switch(self):
        """Freno de mano total para evitar que sigan quemando la IP."""
        if not self.is_banned:
            self.is_banned = True
            logger.critical("!!! KILL-SWITCH ACTIVADO !!! BAN DETECTADO")
            logger.critical("Pausando escaneo para proteger la IP/Reputación.")
    
    def get_headers(self) -> dict:
        """Headers para debugging."""
        return {
            "X-Rate-Limit": str(self.current_rpm),
            "X-Errors": str(self.errors),
        }

    def get_control_summary(self) -> dict:
        """Resumen auditable del estado actual del rate limiter."""
        return {
            "enabled": self.enabled,
            "max_rpm": self.max_rpm,
            "current_rpm": self.current_rpm,
            "jitter_range": self.jitter_range,
            "errors": self.errors,
            "consecutive_403": self.consecutive_403,
            "is_banned": self.is_banned,
        }

# Instancia global
_limiter = None

def get_rate_limiter(config: dict = None) -> RateLimiter:
    """Obtiene la instancia global del rate limiter."""
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter(config)
    return _limiter

def can_request() -> bool:
    """Check rápido."""
    if _limiter:
        return _limiter.can_request()
    return True

def wait_if_needed():
    """Espera si hay饱和."""
    if _limiter:
        _limiter.wait_if_needed()

def record_request(response_time_ms: float = 0, status_code: int = 200):
    """Registrar resultado."""
    if _limiter:
        _limiter.record_request(response_time_ms, status_code)


# Instancia global
rate_limiter = RateLimiter()
