"""Tests for RateLimiter."""
from unittest.mock import patch, MagicMock

from src.opsec.rate_limiter import RateLimiter


class TestRateLimiter:
    def test_can_request_returns_true_initially(self):
        limiter = RateLimiter({"enabled": True, "max_requests_per_min": 200})
        assert limiter.can_request() is True

    def test_can_request_returns_false_when_banned(self):
        limiter = RateLimiter({"enabled": True})
        limiter.is_banned = True
        assert limiter.can_request() is False

    def test_can_request_returns_true_when_disabled(self):
        limiter = RateLimiter({"enabled": False})
        assert limiter.can_request() is True

    def test_can_request_respects_current_rpm_limit(self):
        limiter = RateLimiter({"enabled": True, "max_requests_per_min": 2})
        limiter.current_rpm = 1

        with patch('time.time', return_value=1000.0):
            limiter.requests = [1000.0]
            assert limiter.can_request() is False

    def test_record_request_appends_timestamp(self):
        with patch('time.time', return_value=1000.0):
            limiter = RateLimiter({"enabled": True})
            limiter.record_request()
            assert len(limiter.requests) == 1
            assert limiter.requests[0] == 1000.0

    def test_record_request_200_resets_consecutive_403(self):
        limiter = RateLimiter({"enabled": True})
        limiter.consecutive_403 = 5
        limiter.errors = 5

        with patch('time.time', return_value=1000.0):
            limiter.record_request(status_code=200)
            assert limiter.consecutive_403 == 0
            assert limiter.errors == 4

    def test_record_request_403_increases_errors_and_reduces_speed(self):
        limiter = RateLimiter({"enabled": True, "max_requests_per_min": 200})
        initial_rpm = limiter.current_rpm

        with patch('time.time', return_value=1000.0):
            limiter.record_request(status_code=403)
            assert limiter.errors == 1
            assert limiter.consecutive_403 == 1
            assert limiter.current_rpm < initial_rpm

    def test_record_request_429_increases_errors(self):
        limiter = RateLimiter({"enabled": True})
        with patch('time.time', return_value=1000.0):
            limiter.record_request(status_code=429)
            assert limiter.consecutive_403 == 1
            assert limiter.errors == 1

    def test_consecutive_403_triggers_ban(self):
        limiter = RateLimiter({"enabled": True, "ban_threshold": 3, "max_requests_per_min": 200})
        with patch('time.time', return_value=1000.0):
            for _ in range(3):
                limiter.record_request(status_code=403)
        assert limiter.is_banned is True
        assert limiter.can_request() is False

    def test_slow_response_triggers_speed_reduction(self):
        limiter = RateLimiter({"enabled": True, "slow_mode_threshold": 1000})
        initial_rpm = limiter.current_rpm

        with patch('time.time', return_value=1000.0):
            limiter.record_request(response_time_ms=5000, status_code=200)
            assert limiter.current_rpm < initial_rpm

    def test_get_headers_returns_dict(self):
        limiter = RateLimiter({"enabled": True, "max_requests_per_min": 200})
        headers = limiter.get_headers()
        assert "X-Rate-Limit" in headers
        assert "X-Errors" in headers
        assert headers["X-Rate-Limit"] == "200"

    def test_get_control_summary_returns_current_state(self):
        limiter = RateLimiter({"enabled": True, "max_requests_per_min": 100})
        summary = limiter.get_control_summary()
        assert summary["enabled"] is True
        assert summary["max_rpm"] == 100
        assert summary["current_rpm"] == 100
        assert summary["is_banned"] is False
        assert summary["errors"] == 0

    def test_reduce_speed_halves_rpm(self):
        limiter = RateLimiter({"enabled": True, "max_requests_per_min": 200})
        limiter._reduce_speed("test")
        assert limiter.current_rpm == 100

    def test_reduce_speed_enforces_minimum(self):
        limiter = RateLimiter({"enabled": True, "max_requests_per_min": 200})
        limiter.current_rpm = 5
        limiter._reduce_speed("test")
        assert limiter.current_rpm == 5

    def test_panic_kill_switch_sets_is_banned(self):
        limiter = RateLimiter({"enabled": True})
        limiter._panic_kill_switch()
        assert limiter.is_banned is True
