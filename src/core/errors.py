"""
Excepciones Personalizadas de PromptWall
Define errores específicos del sistema.
"""


class PromptWallError(Exception):
    """Error base de PromptWall."""
    pass


# Errores de Configuración
class ConfigError(PromptWallError):
    """Error de configuración."""
    pass


class ConfigNotFoundError(ConfigError):
    """Archivo de configuración no encontrado."""
    pass


# Errores de Target
class TargetError(PromptWallError):
    """Error relacionado con el target."""
    pass


class InvalidTargetError(TargetError):
    """Target inválido o fuera de scope."""
    pass


class TargetNotFoundError(TargetError):
    """Target no encontrado en la base de datos."""
    pass


# Errores de Escaneo
class ScanError(PromptWallError):
    """Error durante el escaneo."""
    pass


class ScanTimeoutError(ScanError):
    """Timeout durante el escaneo."""
    pass


class ScanInterruptedError(ScanError):
    """Escaneo interrumpido por el usuario."""
    pass


# Errores de OPSEC
class OPSECError(PromptWallError):
    """Error relacionado con OPSEC."""
    pass


class StealthRequestError(PromptWallError):
    """Error general en peticiones stealth."""
    pass


class StealthSSLError(StealthRequestError):
    """Error de SSL/TLS en peticiones stealth."""
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
class StorageError(PromptWallError):
    """Error de almacenamiento."""
    pass


class DatabaseError(StorageError):
    """Error de base de datos."""
    pass


class SessionNotFoundError(StorageError):
    """Sesión no encontrada."""
    pass


# Errores de Herramientas
class ToolError(PromptWallError):
    """Error de herramienta externa."""
    pass


class ToolNotFoundError(ToolError):
    """Herramienta no encontrada."""
    pass


class ToolExecutionError(ToolError):
    """Error al ejecutar herramienta."""
    pass


# Errores de Export
class ExportError(PromptWallError):
    """Error al exportar resultados."""
    pass


# Errores de Notificaciones
class NotificationError(PromptWallError):
    """Error al enviar notificaciones."""
    pass


# Errores de IA
class AIError(PromptWallError):
    """Error del módulo de IA."""
    pass


class APIKeyMissingError(AIError):
    """Falta la API key."""
    pass


class APIRateLimitError(AIError):
    """Rate limit de la API de IA."""
    pass