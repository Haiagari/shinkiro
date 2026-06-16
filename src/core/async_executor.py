"""
Async executor for parallel tool execution using ThreadPoolExecutor.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List, Any, Optional
import logging

logger = logging.getLogger("async-executor")


class AsyncExecutor:
    """Execute multiple tool calls in parallel with timeout control."""

    def __init__(self, max_workers: int = 5):
        self._executor = ThreadPoolExecutor(max_workers=max_workers)

    def run_parallel(self, tasks: List[Dict]) -> List[Dict]:
        """
        Execute multiple tasks in parallel.

        Each task dict must have:
            - 'fn': callable to execute
            - 'name': str identifier for logging
            - 'timeout': int seconds (default: 60)

        Returns list of result dicts with 'name', 'status', 'result', 'error'.
        """
        futures = {}
        for task in tasks:
            fut = self._executor.submit(task['fn'])
            futures[fut] = task['name']

        results = []
        for future in as_completed(futures):
            name = futures[future]
            timeout = next((t.get('timeout', 60) for t in tasks if t['name'] == name), 60)
            try:
                result = future.result(timeout=timeout)
                results.append({'name': name, 'status': 'completed', 'result': result})
            except Exception as e:
                logger.warning("Task '%s' failed: %s", name, e)
                results.append({'name': name, 'status': 'failed', 'error': str(e)})
        return results

    def run_capability_parallel(self, tool_manager, capability: str, targets: List[str], **kwargs) -> List[Dict]:
        """Run a single capability against multiple targets in parallel."""
        tasks = [
            {
                'fn': lambda t=target: tool_manager.run_capability(capability, t, **kwargs),
                'name': f"{capability}:{target}",
            }
            for target in targets
        ]
        return self.run_parallel(tasks)

    def shutdown(self, wait=True):
        self._executor.shutdown(wait=wait)


# Singleton
async_executor = AsyncExecutor()
