"""Tests for KillSwitch."""
from src.opsec.kill_switch import KillSwitch, check_kill, respects_kill


class TestKillSwitch:
    def setup_method(self):
        KillSwitch._instance = None

    def test_singleton_returns_same_instance(self):
        ks1 = KillSwitch()
        ks2 = KillSwitch()
        assert ks1 is ks2

    def test_trigger_sets_state(self):
        ks = KillSwitch()
        assert ks.triggered is False
        assert ks.reason == ""

        ks.trigger("test reason")
        assert ks.triggered is True
        assert ks.reason == "test reason"
        assert ks.triggered_at is not None

    def test_reset_clears_state(self):
        ks = KillSwitch()
        ks.trigger("test")
        assert ks.triggered is True

        ks.reset()
        assert ks.triggered is False
        assert ks.reason == ""
        assert ks.triggered_at is None

    def test_get_instance_returns_singleton(self):
        ks1 = KillSwitch.get_instance()
        ks2 = KillSwitch.get_instance()
        assert ks1 is ks2

    def test_callback_fires_on_trigger(self):
        ks = KillSwitch()
        captured = []

        def test_callback(reason):
            captured.append(reason)

        ks.register_callback(test_callback)
        ks.trigger("callback test")
        assert captured == ["callback test"]

    def test_multiple_callbacks_all_fire(self):
        ks = KillSwitch()
        results = []

        ks.register_callback(lambda r: results.append("cb1"))
        ks.register_callback(lambda r: results.append("cb2"))
        ks.trigger("multi")
        assert results == ["cb1", "cb2"]

    def test_callback_exception_does_not_propagate(self):
        ks = KillSwitch()

        def broken_callback(reason):
            raise RuntimeError("callback error")

        ks.register_callback(broken_callback)
        ks.trigger("should not raise")

    def test_check_kill_returns_correct_state(self):
        from src.opsec.kill_switch import kill_switch as global_ks
        global_ks.reset()
        assert check_kill() is False

        global_ks.trigger("emergency")
        assert check_kill() is True
        global_ks.reset()

    def test_respects_kill_decorator_returns_none_when_triggered(self):
        from src.opsec.kill_switch import kill_switch as global_ks
        global_ks.reset()

        @respects_kill
        def my_func():
            return "done"

        assert my_func() == "done"

        global_ks.trigger("stop")
        assert my_func() is None
        global_ks.reset()
