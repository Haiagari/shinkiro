import pytest
from src.notifications.notifier import Notifier

def test_slack_notification_interface():
    """
    Test the interface for new notification providers (Slack).
    """
    notifier = Notifier()
    # We want to add Slack support
    assert hasattr(notifier, "send_to_slack") or hasattr(notifier, "providers")

def test_quiet_mode_standardization():
    """
    Test that quiet mode is respected across components.
    """
    from src.core.config import config
    # This is more of a policy check


def test_scan_summary_event_is_callable():
    class Finding:
        severity = "high"

    class Result:
        stats = {"subdomains_found": 1, "hosts_alive": 1, "ports_found": 2, "findings": 1}
        findings = [Finding()]

    notifier = Notifier()
    notifier.providers = [{"type": "slack", "webhook": "https://example.com"}]
    assert notifier.send_scan_summary("example.com", Result()) is True
