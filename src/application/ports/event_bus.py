from abc import ABC, abstractmethod
from typing import Callable, Dict, List, Type, TypeVar
from src.domain.events import DomainEvent

T = TypeVar("T", bound=DomainEvent)

class IEventBus(ABC):
    """Interface for the event bus (Port)."""
    
    @abstractmethod
    def subscribe(self, event_type: Type[T], handler: Callable[[T], None]) -> None:
        """Subscribe a handler to a specific event type."""
        pass

    @abstractmethod
    def publish(self, event: DomainEvent) -> None:
        """Publish an event to all subscribers."""
        pass

class InMemoryEventBus(IEventBus):
    """A simple in-memory implementation of the event bus."""
    
    def __init__(self):
        self._handlers: Dict[Type[DomainEvent], List[Callable]] = {}

    def subscribe(self, event_type: Type[T], handler: Callable[[T], None]) -> None:
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)

    def publish(self, event: DomainEvent) -> None:
        event_type = type(event)
        if event_type in self._handlers:
            for handler in self._handlers[event_type]:
                handler(event)
