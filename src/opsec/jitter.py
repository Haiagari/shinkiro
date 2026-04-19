"""
Jitter y Control de Timing para OPSEC
Agrega demoras aleatorias para evitar detección.
"""

import random
import time
from typing import Callable, Optional


class Jitter:
    """Maneja el jitter (demora aleatoria) para OPSEC."""
    
    def __init__(self, base_delay: float = 1.0, jitter_factor: float = 0.5):
        """
        Args:
            base_delay: Delay base en segundos
            jitter_factor: Factor de variación (0.0 - 1.0)
        """
        self.base_delay = base_delay
        self.jitter_factor = jitter_factor
    
    def calculate(self) -> float:
        """Calcula el delay con jitter."""
        jitter = self.base_delay * self.jitter_factor
        return max(0.1, self.base_delay + random.uniform(-jitter, jitter))
    
    def sleep(self):
        """Duerme por el tiempo calculado con jitter."""
        delay = self.calculate()
        time.sleep(delay)
    
    def sleep_between(self, min_delay: float, max_delay: float):
        """Duerme entre un rango específico."""
        delay = random.uniform(min_delay, max_delay)
        time.sleep(delay)
    
    def adaptive_sleep(self, error_count: int = 0):
        """
        Sueño adaptativo basado en errores.
        Si hay errores, aumenta el delay.
        """
        multiplier = 1 + (error_count * 0.5)
        delay = self.calculate() * multiplier
        time.sleep(delay)


class RateGate:
    """Controla la tasa de requests."""
    
    def __init__(self, max_per_minute: int = 50):
        self.max_per_minute = max_per_minute
        self.min_interval = 60.0 / max_per_minute
        self.last_request = 0.0
    
    def wait(self):
        """Espera hasta que se pueda hacer otro request."""
        elapsed = time.time() - self.last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request = time.time()
    
    def __call__(self, func: Callable) -> Callable:
        """Decorador para rate limiting."""
        def wrapper(*args, **kwargs):
            self.wait()
            return func(*args, **kwargs)
        return wrapper


def with_jitter(base_delay: float = 1.0, jitter_factor: float = 0.5):
    """Decorador para agregar jitter a una función."""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            j = Jitter(base_delay, jitter_factor)
            j.sleep()
            return func(*args, **kwargs)
        return wrapper
    return decorator


def with_rate_limit(max_per_minute: int = 50):
    """Decorador para rate limiting."""
    gate = RateGate(max_per_minute)
    return gate(func)


# Instancias globales
default_jitter = Jitter(base_delay=1.0, jitter_factor=0.5)
aggressive_jitter = Jitter(base_delay=0.5, jitter_factor=0.3)
stealth_jitter = Jitter(base_delay=2.0, jitter_factor=0.7)