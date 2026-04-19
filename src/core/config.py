"""
Configuración Centralizada de OzyRecon
Carga y provee acceso a la configuración del sistema.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


class Config:
    """Singleton para acceder a la configuración global."""
    
    _instance: Optional['Config'] = None
    _config: Dict[str, Any] = {}
    _config_path: Optional[Path] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not self._config:
            self._load()
    
    def _load(self):
        """Carga la configuración desde config.yaml"""
        # Buscar config en múltiples ubicaciones
        possible_paths = [
            Path("config/config.yaml"),
            Path(__file__).resolve().parents[2] / "config" / "config.yaml",
            Path.home() / ".ozyrecon" / "config.yaml",
        ]
        
        for path in possible_paths:
            if path.exists():
                self._config_path = path
                with open(path, 'r') as f:
                    self._config = yaml.safe_load(f) or {}
                return
        
        # Si no encuentra config.yaml, usar ejemplo
        example_path = Path("config/config.example.yaml")
        if example_path.exists():
            with open(example_path, 'r') as f:
                self._config = yaml.safe_load(f) or {}
    
    def reload(self):
        """Recarga la configuración"""
        self._config = {}
        self._load()
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Obtiene un valor de configuración.
        Soporta claves anidadas con notación de punto: 'api_keys.openai'
        """
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            
            if value is None:
                return default
        
        return value
    
    @property
    def threads(self) -> int:
        return self.get('threads', 50)
    
    @property
    def timeout(self) -> int:
        return self.get('timeout', 10)
    
    @property
    def rate_limit(self) -> int:
        return self.get('rate_limit', 50)
    
    @property
    def tools_path(self) -> str:
        return self.get('tools_path', 'tools/go/bin')
    
    @property
    def telegram_token(self) -> Optional[str]:
        return self.get('notifications.telegram_token')
    
    @property
    def telegram_chat_id(self) -> Optional[str]:
        return self.get('notifications.telegram_chat_id')
    
    @property
    def gemini_api_key(self) -> Optional[str]:
        return self.get('ai.gemini_api_key')
    
    @property
    def claude_api_key(self) -> Optional[str]:
        return self.get('ai.claude_api_key')
    
    @property
    def shodan_api_key(self) -> Optional[str]:
        return self.get('api_keys.shodan')
    
    @property
    def virustotal_api_key(self) -> Optional[str]:
        return self.get('api_keys.virustotal')
    
    @property
    def alert_level(self) -> str:
        return self.get('notifications.alert_level', 'medium')
    
    @property
    def auto_rate_limit_enabled(self) -> bool:
        return self.get('auto_rate_limit.enabled', True)
    
    @property
    def max_requests_per_min(self) -> int:
        return self.get('auto_rate_limit.max_requests_per_min', 200)
    
    def __repr__(self):
        return f"<Config loaded={bool(self._config)} path={self._config_path}>"


# Instancia global
config = Config()