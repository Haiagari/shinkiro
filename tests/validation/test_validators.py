"""Tests for validator base classes and InfraValidator."""
from unittest.mock import patch, MagicMock
from types import SimpleNamespace

from src.validation.base import ValidationResult, BaseValidator
from src.validation.http import HTTPValidator
from src.validation.infra import InfraValidator
from src.core.errors import StealthSSLError, StealthRequestError


class TestValidationResult:
    def test_creation_sets_attributes(self):
        result = ValidationResult(
            hypothesis_id="h1",
            status="confirmed",
            confidence=0.95,
            evidence=[{"type": "http", "data": "200 OK"}],
            notes="confirmed via header",
        )
        assert result.hypothesis_id == "h1"
        assert result.status == "confirmed"
        assert result.confidence_after == 0.95
        assert len(result.evidence) == 1
        assert result.notes == "confirmed via header"
        assert result.timestamp is not None

    def test_to_dict_returns_properly_formatted_dict(self):
        result = ValidationResult(
            hypothesis_id="h2",
            status="refuted",
            confidence=0.1,
            evidence=[],
            notes="connection refused",
        )
        d = result.to_dict()
        assert d["hypothesis_id"] == "h2"
        assert d["status"] == "refuted"
        assert d["confidence_after_validation"] == 0.1
        assert d["notes"] == "connection refused"
        assert "timestamp" in d

    def test_evidence_defaults_to_empty_list(self):
        result = ValidationResult(hypothesis_id="h3", status="inconclusive", confidence=0.0)
        assert result.evidence == []


class TestBaseValidator:
    def test_create_evidence_returns_structured_dict(self):
        validator = HTTPValidator()
        evidence = validator.create_evidence("http_response", "200 OK", {"header": "Server: nginx"})
        assert evidence["type"] == "http_response"
        assert evidence["data"] == "200 OK"
        assert evidence["metadata"]["header"] == "Server: nginx"
        assert evidence["id"].startswith("ev_")
        assert "timestamp" in evidence


class TestHTTPValidator:
    def test_validate_exposed_version_confirmed(self):
        validator = HTTPValidator()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"Server": "Apache/2.4.41"}

        with patch('src.validation.http.http_client.get', return_value=mock_response):
            result = validator.validate({
                "id": "hv1",
                "url": "http://example.com",
                "type": "EXPOSED_VERSION",
            })

        assert result.status == "confirmed"
        assert result.confidence_after == 0.95
        assert "Apache/2.4.41" in result.notes
        assert len(result.evidence) >= 2

    def test_validate_sensitive_file_detected(self):
        validator = HTTPValidator()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}

        with patch('src.validation.http.http_client.get', return_value=mock_response):
            result = validator.validate({
                "id": "hv2",
                "url": "http://example.com/.env",
                "type": "SENSITIVE_FILE",
            })

        assert result.status == "confirmed"
        assert result.confidence_after == 0.90
        assert "HTTP 200" in result.evidence[-1]["data"]

    def test_validate_blocked_by_policy(self):
        validator = HTTPValidator()
        blocked = SimpleNamespace(is_blocked=True, requires_gate=False, reason="blocked by policy")

        with patch('src.validation.http.validation_policy.classify', return_value=blocked):
            result = validator.validate({
                "id": "hv3",
                "url": "http://example.com",
                "type": "RCE",
            })

        assert result.status == "inconclusive"
        assert result.confidence_after == 0.0
        assert "blocked by policy" in result.notes.lower()

    def test_validate_gate_required_without_approval(self):
        validator = HTTPValidator()
        gate = SimpleNamespace(is_blocked=False, requires_gate=True, reason="requires gate")

        with patch('src.validation.http.validation_policy.classify', return_value=gate):
            result = validator.validate({
                "id": "hv4",
                "url": "http://example.com",
                "type": "AUTH",
            })

        assert result.status == "inconclusive"
        assert "gate required" in result.notes.lower()

    def test_validate_stealth_ssl_error(self):
        validator = HTTPValidator()
        with patch('src.validation.http.http_client.get', side_effect=StealthSSLError("SSL expired")):
            result = validator.validate({
                "id": "hv5",
                "url": "https://expired.example.com",
                "type": "EXPOSED_VERSION",
            })

        assert result.status == "inconclusive"
        assert result.confidence_after == 0.1

    def test_validate_general_exception(self):
        validator = HTTPValidator()
        with patch('src.validation.http.http_client.get', side_effect=RuntimeError("unexpected")):
            result = validator.validate({
                "id": "hv6",
                "url": "http://broken.example.com",
                "type": "EXPOSED_VERSION",
            })

        assert result.status == "refuted"
        assert result.confidence_after == 0.1


class TestInfraValidator:
    def test_validate_tcp_success_for_generic_port(self):
        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock

        with patch('socket.create_connection', return_value=mock_sock) as mock_conn:
            validator = InfraValidator()
            result = validator.validate({
                "id": "iv1",
                "url": "10.0.0.1:8080",
            })

        assert result.status == "confirmed"
        assert result.confidence_after == 0.90
        mock_conn.assert_called_once_with(("10.0.0.1", 8080), timeout=5)

    def test_validate_redis_with_pong(self):
        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.recv.return_value = b"+PONG\r\n"

        with patch('socket.create_connection', return_value=mock_sock):
            validator = InfraValidator()
            result = validator.validate({
                "id": "iv2",
                "url": "10.0.0.1:6379",
            })

        assert result.status == "confirmed"
        assert result.confidence_after == 0.99
        assert "PONG" in result.notes

    def test_validate_redis_with_auth_required(self):
        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.recv.return_value = b"-NOAUTH ..."

        with patch('socket.create_connection', return_value=mock_sock):
            validator = InfraValidator()
            result = validator.validate({
                "id": "iv3",
                "url": "10.0.0.1:6379",
            })

        assert result.status == "confirmed"
        assert result.confidence_after == 0.85
        assert "requires authentication" in result.notes

    def test_validate_postgresql_ssl_detection(self):
        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.recv.return_value = b"S"

        with patch('socket.create_connection', return_value=mock_sock):
            validator = InfraValidator()
            result = validator.validate({
                "id": "iv4",
                "url": "10.0.0.1:5432",
            })

        assert result.status == "confirmed"
        assert result.confidence_after == 0.95
        assert "SSL" in result.notes

    def test_validate_mysql_banner_detection(self):
        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.recv.return_value = b"\x00\x00\x00\x00\x08MySQL 8.0.32\x00..."

        with patch('socket.create_connection', return_value=mock_sock):
            validator = InfraValidator()
            result = validator.validate({
                "id": "iv5",
                "url": "10.0.0.1:3306",
            })

        assert result.status == "confirmed"
        assert result.confidence_after == 0.98
        assert "MySQL" in result.notes

    def test_validate_connection_refused(self):
        with patch('socket.create_connection', side_effect=ConnectionRefusedError("Connection refused")):
            validator = InfraValidator()
            result = validator.validate({
                "id": "iv6",
                "url": "10.0.0.1:9999",
            })

        assert result.status == "refuted"
        assert result.confidence_after == 0.1

    def test_validate_connection_timeout(self):
        with patch('socket.create_connection', side_effect=TimeoutError("timed out")):
            validator = InfraValidator()
            result = validator.validate({
                "id": "iv7",
                "url": "10.0.0.1:9999",
            })

        assert result.status == "refuted"
        assert result.confidence_after == 0.1

    def test_validate_no_port_uses_signal_port(self):
        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock

        with patch('socket.create_connection', return_value=mock_sock):
            validator = InfraValidator()
            result = validator.validate({
                "id": "iv8",
                "url": "10.0.0.1",
                "signals": {"port": 5432},
            })

        assert result.status == "confirmed"
