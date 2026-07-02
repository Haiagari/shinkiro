import logging
import httpx
import os
import datetime
import sys

# The Platform's ingest endpoint
PLATFORM_LOG_ENDPOINT = os.getenv("OZY_PLATFORM_LOG_URL", "http://127.0.0.1:9080/v1/telemetry/logs")
SCAN_ID = os.getenv("OZY_SCAN_ID", "standalone")
ENGINE_NAME = os.getenv("OZY_ENGINE_NAME", "promptwall")

class PlatformLogHandler(logging.Handler):
    """
    A logging handler that sends logs to the Ozy Platform's telemetry endpoint.
    """
    def __init__(self):
        super().__init__()
        # Use a short timeout to not block the reconnaissance flow
        self.client = httpx.Client(timeout=1.0)

    def emit(self, record: logging.LogRecord):
        try:
            log_entry = {
                "schema_version": "ozy.logline.v1",
                "scan_id": os.getenv("OZY_SCAN_ID", SCAN_ID),
                "engine": ENGINE_NAME,
                "message": self.format(record),
                "level": record.levelname,
                "timestamp": datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).isoformat()
            }
            # Fire and forget
            self.client.post(PLATFORM_LOG_ENDPOINT, json=log_entry)
        except Exception:
            pass

def setup_platform_logging():
    """
    Adds the PlatformLogHandler to the root logger if telemetry is enabled.
    """
    if os.getenv("OZY_PLATFORM_TELEMETRY", "false").lower() == "true":
        handler = PlatformLogHandler()
        # Tactical format for the HUD - just the message
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)
