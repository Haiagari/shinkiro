"""
Session Manager - OzyRecon v8.2
Tracks active scan tasks and handles global cancellation.
"""

import logging
import asyncio
from typing import Dict, Any, Optional

logger = logging.getLogger("core.session_manager")

class SessionManager:
    """
    Active session registry for runtime control.
    """
    def __init__(self):
        # active_tasks: { session_id: Task }
        self.active_tasks: Dict[str, asyncio.Task] = {}

    def register_task(self, session_id: str, task: asyncio.Task):
        self.active_tasks[session_id] = task
        logger.info(f"Session {session_id} registered in Manager.")

    def cancel_session(self, session_id: str) -> bool:
        if session_id in self.active_tasks:
            task = self.active_tasks[session_id]
            task.cancel()
            del self.active_tasks[session_id]
            logger.warning(f"Session {session_id} CANCELLED by operator.")
            return True
        return False

    def unregister_task(self, session_id: str):
        if session_id in self.active_tasks:
            del self.active_tasks[session_id]

# Global Instance
session_manager = SessionManager()
