"""Tests for Jitter and RateGate."""
from unittest.mock import patch

from src.opsec.jitter import Jitter, RateGate, default_jitter, aggressive_jitter, stealth_jitter


class TestJitter:
    def test_calculate_returns_value_within_expected_range(self):
        jitter = Jitter(base_delay=1.0, jitter_factor=0.5)
        with patch('random.uniform', return_value=0.3):
            result = jitter.calculate()
            assert result == 1.3

    def test_calculate_negative_jitter_reduces_delay(self):
        jitter = Jitter(base_delay=1.0, jitter_factor=0.5)
        with patch('random.uniform', return_value=-0.4):
            result = jitter.calculate()
            assert result == 0.6

    def test_calculate_clamps_to_minimum(self):
        jitter = Jitter(base_delay=0.05, jitter_factor=1.0)
        with patch('random.uniform', return_value=-0.05):
            result = jitter.calculate()
            assert result == 0.1

    def test_sleep_calls_time_sleep_with_calculated_delay(self):
        jitter = Jitter(base_delay=1.0, jitter_factor=0.5)
        with patch('random.uniform', return_value=0.2):
            with patch('time.sleep') as mock_sleep:
                jitter.sleep()
                mock_sleep.assert_called_once_with(1.2)

    def test_sleep_between_calls_time_sleep(self):
        jitter = Jitter()
        with patch('random.uniform', return_value=1.5) as mock_random:
            with patch('time.sleep') as mock_sleep:
                jitter.sleep_between(1.0, 2.0)
                mock_random.assert_called_once_with(1.0, 2.0)
                mock_sleep.assert_called_once_with(1.5)

    def test_adaptive_sleep_multiplies_delay_by_error_count(self):
        jitter = Jitter(base_delay=1.0, jitter_factor=0.0)
        with patch('random.uniform', return_value=0.0):
            with patch('time.sleep') as mock_sleep:
                jitter.adaptive_sleep(error_count=2)
                mock_sleep.assert_called_once_with(2.0)

    def test_default_jitter_constants(self):
        assert default_jitter.base_delay == 1.0
        assert default_jitter.jitter_factor == 0.5
        assert aggressive_jitter.base_delay == 0.5
        assert aggressive_jitter.jitter_factor == 0.3
        assert stealth_jitter.base_delay == 2.0
        assert stealth_jitter.jitter_factor == 0.7


class TestRateGate:
    def test_wait_does_not_sleep_when_enough_time_passed(self):
        gate = RateGate(max_per_minute=60)
        gate.last_request = 0.0
        with patch('time.time', return_value=100.0):
            with patch('time.sleep') as mock_sleep:
                gate.wait()
                mock_sleep.assert_not_called()
                assert gate.last_request == 100.0

    def test_wait_sleeps_when_too_soon(self):
        gate = RateGate(max_per_minute=60)
        gate.last_request = 99.5
        with patch('time.time', return_value=100.0):
            with patch('time.sleep') as mock_sleep:
                gate.wait()
                mock_sleep.assert_called_once()
