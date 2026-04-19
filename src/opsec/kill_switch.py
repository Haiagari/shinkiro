"""
Kill Switch para OzyRecon
Permite detener inmediatamente todas las operaciones.
"""

import signal
import sys
from typing import Callable, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class KillSwitch:
    """
    Kill Switch - Mecanismo de emergencia para detener operaciones.
    
    Uso:
        kill_switch = KillSwitch()
        
        # En el loop principal:
        if kill_switch.triggered:
            break
            
        # Para activar desde CLI:
        # Crear archivo .kill en runtime/
        # O enviar señal SIGINT (Ctrl+C)
    """
    
    _instance: Optional['KillSwitch'] = None
    triggered: bool = False
    triggered_at: Optional[datetime] = None
    reason: str = ""
    
    # Callbacks registrados
    callbacks: list = field(default_factory=list)
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        # Registrar signal handler para SIGINT/SIGTERM
        if not hasattr(self, '_initialized'):
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            self._initialized = True
    
    def _signal_handler(self, signum, frame):
        """Maneja señales de terminate."""
        self.trigger("Received termination signal")
    
    def trigger(self, reason: str = "Manual trigger"):
        """Activa el kill switch."""
        self.triggered = True
        self.triggered_at = datetime.now()
        self.reason = reason
        
        # Ejecutar callbacks
        for callback in self.callbacks:
            try:
                callback(reason)
            except Exception:
                pass
    
    def reset(self):
        """Resetea el kill switch."""
        self.triggered = False
        self.triggered_at = None
        self.reason = ""
    
    def register_callback(self, callback: Callable[[str], None]):
        """Registra un callback que se ejecutará al activar."""
        self.callbacks.append(callback)
    
    @classmethod
    def get_instance(cls) -> 'KillSwitch':
        """Obtiene la instancia singleton."""
        if cls._instance is None:
            cls._instance = KillSwitch()
        return cls._instance


# Instancia global
kill_switch = KillSwitch.get_instance()


def check_kill() -> bool:
    """Verifica si el kill switch fue activado."""
    return kill_switch.triggered


def wait_for_kill():
    """Espera hasta que se active el kill switch."""
    while not kill_switch.triggered:
        import time
        time.sleep(0.1)


# Decorador para funciones que respetan el kill switch
def respects_kill(func: Callable) -> Callable:
    """Decorador que verifica el kill switch antes de continuar."""
    def wrapper(*args, **kwargs):
        if kill_switch.triggered:
            return None
        return func(*args, **kwargs)
    return wrapper