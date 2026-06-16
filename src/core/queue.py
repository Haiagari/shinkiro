"""
Optional Redis-backed task queue for distributed scan execution.
Falls back to in-memory if Redis is unavailable.
"""

import json
import os
import logging
from typing import Optional, Callable

logger = logging.getLogger("queue")

REDIS_URL = os.environ.get("OZY_REDIS_URL", "")


class TaskQueue:
    def __init__(self):
        self._redis = None
        self._fallback_queue: list = []
        self._initialized = False

    def _ensure_redis(self) -> bool:
        if self._initialized:
            return self._redis is not None
        self._initialized = True
        if not REDIS_URL:
            logger.info("TaskQueue: no OZY_REDIS_URL set, using in-memory fallback")
            return False
        try:
            import redis as r
            self._redis = r.from_url(REDIS_URL, decode_responses=True)
            self._redis.ping()
            logger.info(f"TaskQueue: connected to Redis at {REDIS_URL}")
            return True
        except Exception as e:
            logger.warning(f"TaskQueue: Redis unavailable ({e}), using in-memory fallback")
            self._redis = None
            return False

    def enqueue(self, queue_name: str, task: dict) -> bool:
        payload = json.dumps(task, default=str)
        if self._ensure_redis():
            try:
                self._redis.rpush(queue_name, payload)
                return True
            except Exception as e:
                logger.error(f"TaskQueue: Redis enqueue failed: {e}")
        self._fallback_queue.append(payload)
        return True

    def dequeue(self, queue_name: str, timeout: int = 5) -> Optional[dict]:
        if self._ensure_redis():
            try:
                result = self._redis.blpop(queue_name, timeout=timeout)
                if result:
                    return json.loads(result[1])
            except Exception as e:
                logger.error(f"TaskQueue: Redis dequeue failed: {e}")
        if self._fallback_queue:
            return json.loads(self._fallback_queue.pop(0))
        return None

    def queue_length(self, queue_name: str) -> int:
        if self._ensure_redis():
            try:
                return self._redis.llen(queue_name)
            except Exception:
                pass
        return len(self._fallback_queue)

    def clear(self, queue_name: str) -> bool:
        if self._ensure_redis():
            try:
                self._redis.delete(queue_name)
                return True
            except Exception:
                pass
        self._fallback_queue.clear()
        return True


task_queue = TaskQueue()
