"""
Excepciones Personalizadas de OzyRecon
Define errores específicos del sistema.
"""


class OzyReconError(Exception):
    """Error base de OzyRecon."""
    pass


# Errores de Configuración
class ConfigError(OzyReconError):
    """Error de configuración."""
    pass


class ConfigNotFoundError(ConfigError):
    """Archivo de configuración no encontrado."""
    pass


# Errores de Target
class TargetError(OzyReconError):
    """Error relacionado con el target."""
    pass


class InvalidTargetError(TargetError):
    """Target inválido o fuera de scope."""
    pass


class TargetNotFoundError(TargetError):
    """Target no encontrado en la base de datos."""
    pass


# Errores de Escaneo
class ScanError(OzyReconError):
    """Error durante el escaneo."""
    pass


class ScanTimeoutError(ScanError):
    """Timeout durante el escaneo."""
    pass


class ScanInterruptedError(ScanError):
    """Escaneo interrumpido por el usuario."""
    pass


# Errores de OPSEC
class OPSECError(OzyReconError):
    """Error relacionado con OPSEC."""
    pass


class RateLimitExceededError(OPSECError):
    """Rate limit excedido."""
    pass


class BanDetectedError(OPSECError):
    """Detectado ban o bloqueo."""
    pass


class KillSwitchTriggeredError(OPSECError):
    """Kill switch activado."""
    pass


# Errores de Storage
class StorageError(OzyReconError):
    """Error de almacenamiento."""
    pass


class DatabaseError(StorageError):
    """Error de base de datos."""
    pass


class SessionNotFoundError(StorageError):
    """Sesión no encontrada."""
    pass


# Errores de Herramientas
class ToolError(OzyReconError):
    """Error de herramienta externa."""
    pass


class ToolNotFoundError(ToolError):
    """Herramienta no encontrada."""
    pass


class ToolExecutionError(ToolError):
    """Error al ejecutar herramienta."""
    pass


# Errores de Export
class ExportError(OzyReconError):
    """Error al exportar resultados."""
    pass


# Errores de Notificaciones
class NotificationError(OzyReconError):
    """Error al enviar notificaciones."""
    pass


# Errores de IA
class AIError(OzyReconError):
    """Error del módulo de IA."""
    pass


class APIKeyMissingError(AIError):
    """Falta la API key."""
    pass


class APIRateLimitError(AIError):
    """Rate limit de la API de IA."""
    pass