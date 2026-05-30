import requests
import json
from dataclasses import asdict
from datetime import datetime
from src.application.event_bus import IEventBus
from src.domain.events import DomainEvent

class WebhookEventAdapter:
    """Adapter that sends events to a webhook URL."""
    
    def __init__(self, event_bus: IEventBus, webhook_url: str):
        self.webhook_url = webhook_url
        # Subscribe to all base domain events if we want, 
        # but usually we'd subscribe to specific ones.
        # For this implementation, we'll subscribe to the base class if possible
        # or just specific ones as required by the task.
        from src.domain.events import AssetDiscovered, FindingDetected
        
        event_bus.subscribe(AssetDiscovered, self.handle_event)
        event_bus.subscribe(FindingDetected, self.handle_event)

    def handle_event(self, event: DomainEvent) -> None:
        """Sends the event payload to the configured webhook."""
        try:
            payload = self._serialize_event(event)
            response = requests.post(
                self.webhook_url, 
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            response.raise_for_status()
        except Exception as e:
            # In a real system, we'd log this properly.
            # For OzyRecon, we want to avoid crashing the main execution.
            print(f"Error sending webhook: {e}")

    def _serialize_event(self, event: DomainEvent) -> dict:
        """Converts domain event to a JSON-serializable dictionary."""
        def default_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")

        # Convert dataclass to dict and then handle non-serializable fields
        data = asdict(event)
        # Manually fix datetime fields if asdict didn't (it usually doesn't for nested)
        return json.loads(json.dumps(data, default=default_serializer))
