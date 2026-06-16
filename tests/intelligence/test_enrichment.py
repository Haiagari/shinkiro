import socket

from src.intelligence.enrichment.enrichment import enrich_hosts


def test_enrich_hosts_normalizes_url_inputs(monkeypatch):
    seen_hosts = []

    def fake_gethostbyname(host: str) -> str:
        seen_hosts.append(host)
        return "203.0.113.10"

    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname)

    result = enrich_hosts(["https://api.example.com:8443/path?x=1", "bad value"], {})

    assert seen_hosts == ["api.example.com"]
    assert result["shodan"] == {}
    assert result["censys"] == {}
    assert result["crt_sh"] == {}
