import socket

from src.security.target_validator import is_safe_target


def test_validator_blocks_ipv4_mapped_ipv6_loopback():
    is_safe, reason = is_safe_target("::ffff:127.0.0.1")

    assert not is_safe
    assert "restricted" in reason


def test_validator_blocks_ipv4_mapped_ipv6_private():
    is_safe, reason = is_safe_target("::ffff:10.0.0.5")

    assert not is_safe
    assert "restricted" in reason


def test_validator_blocks_ipv6_dns_rebinding(monkeypatch):
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                6,
                "",
                ("fd00::1", 0, 0, 0),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    is_safe, reason = is_safe_target("aaaa-only.example.com")

    assert not is_safe
    assert "restricted" in reason
