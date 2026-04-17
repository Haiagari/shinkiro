"""
Rate Limiter Automático
Ajusta la velocidad automáticamente para no romper el target.
"""

import time
from threading import Lock
from .utils import log

class RateLimiter:
    """
    Rate limiter adaptativo.
    Reduce velocidad si detecta饱和 o errores.
    """
    
    def __init__(self, config: dict = None):
        cfg = config or {}
        
        self.enabled = cfg.get("enabled", True)
        self.max_rpm = cfg.get("max_requests_per_min", 200)
        self.check_interval = cfg.get("check_interval", 10)
        self.error_threshold = cfg.get("error_threshold", 5)
        self.slow_threshold_ms = cfg.get("slow_mode_threshold", 100)
        
        self.requests = []
        self.errors = 0
        self.last_slow = None
        self.current_rpm = self.max_rpm
        
        self.lock = Lock()
        
        log(f"RateLimiter: max {self.max_rpm} req/min", "info")
    
    def can_request(self) -> bool:
        """Check si puede hacer un request."""
        if not self.enabled:
            return True
        
        with self.lock:
            now = time.time()
            # Limpiar requests viejos (1 minuto)
            self.requests = [t for t in self.requests if now - t < 60]
            
            return len(self.requests) < self.max_rpm
    
    def wait_if_needed(self):
        """Espera si hay que reducir velocidad."""
        if not self.enabled:
            return
        
        # Reducir si hay muchos errores
        if self.errors >= self.error_threshold:
            self._reduce_speed("muchos errores")
            return
        
        # Reducir si hay muchos requests recientes
        while not self.can_request():
            log(f"Rate limit: esperando... ({self.current_rpm} rpm)", "info")
            time.sleep(1)
    
    def record_request(self, response_time_ms: float = 0, is_error: bool = False):
        """Registrar un request."""
        with self.lock:
            self.requests.append(time.time())
            
            if is_error:
                self.errors += 1
            else:
                # Reset errores si hay éxito
                if self.errors > 0:
                    self.errors = max(0, self.errors - 1)
            
            # Detectar si está lento
            if response_time_ms > self.slow_threshold_ms:
                self._reduce_speed("target lento")
    
    def _reduce_speed(self, reason: str):
        """Reduce la velocidad."""
        old_rpm = self.current_rpm
        self.current_rpm = max(10, int(self.current_rpm * 0.7))
        
        if old_rpm != self.current_rpm:
            log(f"⚠️ Rate limit: {reason} - reduciendo a {self.current_rpm} rpm", "warn")
            self.last_slow = time.time()
    
    def get_headers(self) -> dict:
        """Headers para debugging."""
        return {
            "X-Rate-Limit": str(self.current_rpm),
            "X-Errors": str(self.errors),
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

def record_request(response_time_ms: float = 0, is_error: bool = False):
    """Registrar resultado."""
    if _limiter:
        _limiter.record_request(response_time_ms, is_error)