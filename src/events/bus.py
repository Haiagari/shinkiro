import logging
from typing import Callable, Dict, List

from src.events.events import DomainEvent

Handler = Callable[[DomainEvent], None]


class EventBus:
    def __init__(self):
        self._handlers: Dict[str, List[Handler]] = {}

    def subscribe(self, event_type: str, handler: Handler):
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    def publish(self, event: DomainEvent):
        handlers = self._handlers.get(event.event_type, [])
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                logging.getLogger("events").error(f"Handler failed for {event.event_type}: {e}")

    def unsubscribe(self, event_type: str, handler: Handler):
        handlers = self._handlers.get(event_type, [])
        if handler in handlers:
            handlers.remove(handler)


event_bus = EventBus()
