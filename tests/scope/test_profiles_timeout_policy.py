from src.scope.profiles import PROFILES, list_profiles


def test_profiles_expose_timeout_policy():
    for profile in PROFILES.values():
        assert hasattr(profile, "timeout_policy")
        assert isinstance(profile.timeout_policy, dict)
        assert "default" in profile.timeout_policy


def test_list_profiles_includes_timeout_policy():
    profiles = list_profiles()
    for data in profiles.values():
        assert "timeout_policy" in data
