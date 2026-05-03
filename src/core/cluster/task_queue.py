"""
OzyCluster Foundation - Task Queue (v8.3.2)
Mock/File-based queue para preparar la integración futura con Redis/Celery.
"""

import json
import time
import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from src.core.runtime_paths import get_runtime_root

logger = logging.getLogger("core.cluster.queue")

class TaskQueue:
    """
    Cola de tareas básica basada en archivos.
    Sencillito pero funcional para ir probando la arquitectura distribuida.
    """
    
    def __init__(self):
        self.queue_dir = get_runtime_root() / "cluster" / "queue"
        self.queue_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"OzyCluster TaskQueue inicializada en {self.queue_dir}")

    def push(self, task_type: str, payload: Dict[str, Any]) -> str:
        """Encola una nueva tarea."""
        task_id = f"task_{int(time.time() * 1000)}"
        task_file = self.queue_dir / f"{task_id}.json"
        
        task_data = {
            "id": task_id,
            "type": task_type,
            "payload": payload,
            "status": "pending",
            "created_at": time.time()
        }
        
        with open(task_file, "w") as f:
            json.dump(task_data, f)
            
        logger.debug(f"Tarea {task_id} ({task_type}) encolada.")
        return task_id

    def pop(self) -> Optional[Dict[str, Any]]:
        """Obtiene la tarea más vieja de la cola (FIFO)."""
        tasks = sorted(self.queue_dir.glob("*.json"))
        if not tasks:
            return None
            
        task_file = tasks[0]
        try:
            with open(task_file, "r") as f:
                task_data = json.load(f)
            
            # Marcamos como "processing" moviéndola o borrándola
            # Para este mock, la borramos para simular el pop
            task_file.unlink()
            return task_data
        except Exception as e:
            logger.error(f"Error procesando tarea de la cola: {e}")
            return None

    def get_status(self) -> Dict[str, int]:
        """Devuelve el estado de la cola."""
        count = len(list(self.queue_dir.glob("*.json")))
        return {"pending_tasks": count}

# Global Instance
task_queue = TaskQueue()
