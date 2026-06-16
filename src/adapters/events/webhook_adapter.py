import json
import logging
from dataclasses import asdict
from datetime import datetime

import requests

from src.events.bus import event_bus
from src.events.events import AssetDiscovered, DomainEvent, FindingDetected

logger = logging.getLogger("events")


class WebhookEventAdapter:
    """Adapter that sends events to a webhook URL."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

        event_bus.subscribe("asset_discovered", self.handle_event)
        event_bus.subscribe("finding_detected", self.handle_event)

    def handle_event(self, event: DomainEvent) -> None:
        """Sends the event payload to the configured webhook."""
        try:
            payload = self._serialize_event(event)
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Error sending webhook: {e}")

    def _serialize_event(self, event: DomainEvent) -> dict:
        """Converts domain event to a JSON-serializable dictionary."""
        def default_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")

        data = asdict(event)
        return json.loads(json.dumps(data, default=default_serializer))
