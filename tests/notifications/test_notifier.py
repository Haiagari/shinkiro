"""Tests for Notifier."""
from unittest.mock import patch, MagicMock

from src.notifications.notifier import Notifier, _is_placeholder


class TestIsPlaceholder:
    def test_empty_value_returns_true(self):
        assert _is_placeholder("", set()) is True

    def test_none_value_returns_true(self):
        assert _is_placeholder(None, {"PLACEHOLDER"}) is True

    def test_placeholder_value_returns_true(self):
        assert _is_placeholder("TU_TOKEN_DE_BOT", {"TU_TOKEN_DE_BOT"}) is True

    def test_placeholder_value_normalized_returns_true(self):
        assert _is_placeholder("  TU_TOKEN_DE_BOT  ", {"TU_TOKEN_DE_BOT"}) is True

    def test_tu_prefix_returns_true(self):
        assert _is_placeholder("TU_VALOR", set()) is True

    def test_your_prefix_returns_true(self):
        assert _is_placeholder("YOUR_SECRET", set()) is True

    def test_real_value_returns_false(self):
        assert _is_placeholder("123456:ABC-DEF", {"TU_TOKEN_DE_BOT"}) is False


class TestNotifier:
    def test_is_configured_false_without_providers(self):
        with patch('src.notifications.notifier.config') as mock_config:
            mock_config.telegram_token = None
            mock_config.telegram_chat_id = None
            mock_config.get.return_value = None

            n = Notifier()
            assert n.is_configured() is False
            assert len(n.providers) == 0

    def test_send_message_returns_false_without_providers(self):
        with patch('src.notifications.notifier.config') as mock_config:
            mock_config.telegram_token = None
            mock_config.telegram_chat_id = None
            mock_config.get.return_value = None

            n = Notifier()
            result = n.send_message("test message")
            assert result is False

    def test_send_alert_returns_false_without_providers(self):
        with patch('src.notifications.notifier.config') as mock_config:
            mock_config.telegram_token = None
            mock_config.telegram_chat_id = None
            mock_config.get.return_value = None

            n = Notifier()
            result = n.send_alert("Title", "Message", "info")
            assert result is False

    def test_send_alert_level_filtering(self):
        with patch('src.notifications.notifier.config') as mock_config:
            mock_config.telegram_token = None
            mock_config.telegram_chat_id = None
            mock_config.get.return_value = None

            n = Notifier()
            n.alert_level = "critical"

            assert n.send_alert("Test", "Low info", "info") is False
            assert n.send_alert("Test", "Critical", "critical") is False

    def test_send_alert_passes_filter_with_same_level(self):
        with patch('src.notifications.notifier.config') as mock_config:
            mock_config.telegram_token = None
            mock_config.telegram_chat_id = None
            mock_config.get.return_value = None

            n = Notifier()
            n.alert_level = "info"

            with patch.object(n, 'send_message', return_value=True) as mock_send:
                result = n.send_alert("Title", "Body", "info")
                assert result is True
                mock_send.assert_called_once()
                assert "Title" in mock_send.call_args[0][0]

    def test_send_finding_formats_message(self):
        with patch('src.notifications.notifier.config') as mock_config:
            mock_config.telegram_token = None
            mock_config.telegram_chat_id = None
            mock_config.get.return_value = None

            n = Notifier()
            n.alert_level = "info"

            with patch.object(n, 'send_message', return_value=True) as mock_send:
                result = n.send_finding("example.com", {
                    "name": "XSS Found",
                    "severity": "high",
                    "url": "http://example.com/xss",
                    "description": "Reflected XSS in search",
                })
                assert result is True
                assert "XSS Found" in mock_send.call_args[0][0]
                assert "HIGH" in mock_send.call_args[0][0]

    def test_send_error_formats_message(self):
        with patch('src.notifications.notifier.config') as mock_config:
            mock_config.telegram_token = None
            mock_config.telegram_chat_id = None
            mock_config.get.return_value = None

            n = Notifier()
            n.alert_level = "info"

            with patch.object(n, 'send_message', return_value=True) as mock_send:
                result = n.send_error("example.com", "Connection timeout")
                assert result is True
                assert "Connection timeout" in mock_send.call_args[0][0]

    def test_configured_with_telegram_has_providers(self):
        with patch('src.notifications.notifier.config') as mock_config:
            mock_config.telegram_token = "123456:real-token"
            mock_config.telegram_chat_id = "-100123456"
            mock_config.get.return_value = None

            n = Notifier()
            assert n.is_configured() is True
            assert len(n.providers) == 1
            assert n.providers[0]["type"] == "telegram"

    def test_configured_with_slack_has_providers(self):
        with patch('src.notifications.notifier.config') as mock_config:
            mock_config.telegram_token = None
            mock_config.telegram_chat_id = None

            def mock_get(key, default=None):
                if key == "slack.webhook_url":
                    return "https://hooks.slack.com/services/xxx"
                return default

            mock_config.get.side_effect = mock_get

            n = Notifier()
            assert n.is_configured() is True
            assert len(n.providers) == 1
            assert n.providers[0]["type"] == "slack"
