"""
OzyRecon Mode Base - Definición de Contratos Operativos
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import uuid

from src.core.config import config
from src.core.context import ScanContext, set_context
from src.storage.database import SessionLocal, init_db
from src.storage.queries import DBQueries
from src.storage.diff import DiffEngine
from src.notifications.notifier import Notifier

class BaseMode(ABC):
    """
    Contrato base para todos los modos operativos de OzyRecon.
    Define precondiciones, flujo de ejecución y estructura de salida.
    """
    
    def __init__(self, target: str, mode_name: str, options: Optional[Dict[str, Any]] = None):
        self.target = target
        self.mode_name = mode_name
        self.options = options or {}
        self.session_id = str(uuid.uuid4())
        
        # Contexto de ejecución
        self.context = ScanContext(
            session_id=self.session_id,
            target=target,
            mode=mode_name,
            threads=self.options.get('threads', config.threads)
        )
        set_context(self.context)
        
        # Componentes base
        init_db()
        self.db_session = SessionLocal()
        self.db = DBQueries(self.db_session)
        self.diff_engine = DiffEngine(self.db_session)
        self.notifier = Notifier()

    def run(self) -> Dict[str, Any]:
        """Flujo de ejecución principal con manejo de ciclo de vida."""
        self.context.mark_running()
        try:
            self.validate_preconditions()
            result = self.execute()
            self.context.mark_completed()
            return result
        except Exception as e:
            self.context.mark_failed(str(e))
            return {"status": "failed", "error": str(e)}
        finally:
            self.db_session.close()

    @abstractmethod
    def validate_preconditions(self):
        """Verifica si el entorno y los datos previos permiten ejecutar este modo."""
        pass

    @abstractmethod
    def execute(self) -> Dict[str, Any]:
        """Lógica específica del modo."""
        pass

    def get_operational_intent(self) -> Dict[str, Any]:
        """
        Retorna la intención operativa para pasar a los proveedores.
        Define agresividad, ruido y velocidad.
        """
        return {
            "mode": self.mode_name,
            "speed": self.options.get("speed", "normal"),
            "noise_level": self.options.get("noise", "medium"),
            "depth": self.options.get("depth", "standard")
        }
