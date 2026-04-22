"""
SwarmManager - Gestión de Nodos del Enjambre
Maneja la lista de nodos (VPS, Local, Docker) y su estado.
"""

import json
import requests
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
from src.core.logging import get_logger

logger = get_logger('swarm_manager')

class SwarmNode:
    """Representa un nodo individual en el enjambre."""
    def __init__(self, name: str, url: str, api_key: str = ""):
        self.name = name
        self.url = url.rstrip('/')
        self.api_key = api_key
        self.status = "unknown"
        self.last_seen = None
        self.capabilities = []

    def check_health(self) -> bool:
        """Verifica si el nodo está online y responde."""
        try:
            res = requests.get(f"{self.url}/", timeout=5)
            if res.status_code == 200:
                self.status = "online"
                self.last_seen = datetime.now().isoformat()
                return True
            else:
                self.status = "error"
                return False
        except:
            self.status = "offline"
            return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "status": self.status,
            "last_seen": self.last_seen
        }

class SwarmManager:
    """Gestiona el registro y orquestación de múltiples nodos."""
    
    def __init__(self):
        self.config_path = Path("runtime/config/swarm_nodes.json")
        self.nodes: List[SwarmNode] = []
        self._load_nodes()

    def _load_nodes(self):
        """Carga los nodos desde el archivo de configuración."""
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    data = json.load(f)
                    self.nodes = [SwarmNode(**n) for n in data.get("nodes", [])]
                logger.info(f"Loaded {len(self.nodes)} swarm nodes")
            except Exception as e:
                logger.error(f"Failed to load swarm nodes: {e}")

    def save_nodes(self):
        """Guarda la lista actual de nodos."""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump({
                "nodes": [
                    {"name": n.name, "url": n.url, "api_key": n.api_key} 
                    for n in self.nodes
                ]
            }, f, indent=2)

    def add_node(self, name: str, url: str, api_key: str = ""):
        """Agrega un nuevo nodo al enjambre."""
        # Evitar duplicados por URL
        if any(n.url == url.rstrip('/') for n in self.nodes):
            return False
        
        new_node = SwarmNode(name, url, api_key)
        self.nodes.append(new_node)
        self.save_nodes()
        return True

    def get_online_nodes(self) -> List[SwarmNode]:
        """Retorna solo los nodos que están respondiendo."""
        return [n for n in self.nodes if n.check_health()]

    def get_status_report(self) -> List[Dict[str, Any]]:
        """Genera un reporte de estado para el dashboard."""
        return [n.to_dict() for n in self.nodes]

# Instancia global
swarm_manager = SwarmManager()
