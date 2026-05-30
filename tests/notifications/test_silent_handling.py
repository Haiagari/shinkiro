import pytest
from unittest.mock import patch, MagicMock
from src.notifications.notifier import Notifier

@pytest.fixture
def mock_config():
    with patch("src.notifications.notifier.config") as m:
        # Defaults
        m.telegram_token = None
        m.telegram_chat_id = None
        m.get.side_effect = lambda k, d=None: d
        yield m

def test_telegram_placeholder_token_is_not_configured(mock_config):
    """
    If the token is the placeholder, it should be treated as unconfigured.
    """
    mock_config.telegram_token = "TU_TOKEN_DE_BOT"
    mock_config.telegram_chat_id = "TU_CHAT_ID"
    
    notifier = Notifier()
    # It should NOT be in providers if it's the placeholder
    assert not any(p["type"] == "telegram" for p in notifier.providers)
    assert notifier.is_configured() is False

def test_telegram_real_token_is_configured(mock_config):
    """
    If the token is NOT the placeholder, it should be configured.
    """
    mock_config.telegram_token = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
    mock_config.telegram_chat_id = "987654321"
    
    notifier = Notifier()
    assert any(p["type"] == "telegram" for p in notifier.providers)
    assert notifier.is_configured() is True

def test_send_message_skips_silently_when_unconfigured(mock_config, caplog):
    """
    When no providers are configured, send_message should return False 
    WITHOUT logging a warning (the current code logs a warning).
    We want it to be silent.
    """
    notifier = Notifier()
    assert notifier.is_configured() is False
    
    with caplog.at_level("WARNING"):
        result = notifier.send_message("test")
        
    assert result is False
    # Check that "No notification providers configured" is NOT in logs
    assert "No notification providers configured" not in caplog.text

def test_telegram_404_handled_silently(mock_config, caplog):
    """
    Even if configured, if Telegram returns a 404 (invalid token), 
    it should be handled quietly if it looks like a placeholder was missed 
    or just generally not noisy. 
    Actually, the requirement says placeholder token should be TREATED as unconfigured.
    But if it fails with 404, we should also avoid noisy error logs if possible.
    """
    mock_config.telegram_token = "invalid_token"
    mock_config.telegram_chat_id = "123"
    
    notifier = Notifier()
    
    with patch("requests.post") as mock_post:
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = Exception("404 Client Error")
        mock_post.return_value = mock_response
        
        with caplog.at_level("ERROR"):
            result = notifier._send_telegram(notifier.providers[0], "test", "Markdown")
            
        assert result is False
        # The specific noisy error "Telegram failed: 404 Client Error" should be gone 
        # or replaced by a debug log.
        assert "Telegram failed" not in caplog.text
