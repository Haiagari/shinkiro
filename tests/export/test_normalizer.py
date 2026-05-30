from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.export.normalizer import NormalizedExporter
from src.storage.models import Base, Target, Scan, Subdomain, Port, Vulnerability


def _make_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_export_scan_builds_normalized_contract():
    session = _make_session()

    target = Target(domain="contract.example.com")
    session.add(target)
    session.flush()

    previous_scan = Scan(
        target_id=target.id,
        session_id="scan-prev",
        timestamp="2026-04-26T10:00:00",
        status="completed",
        mode="hunt",
        start_time=datetime.now(timezone.utc) - timedelta(minutes=15),
        end_time=datetime.now(timezone.utc) - timedelta(minutes=10),
    )
    session.add(previous_scan)
    session.flush()
    session.add(Subdomain(scan_id=previous_scan.id, domain="old.contract.example.com", is_live=0))
    session.commit()

    current_scan = Scan(
        target_id=target.id,
        session_id="scan-current",
        timestamp="2026-04-26T11:00:00",
        status="completed",
        mode="hunt",
        start_time=datetime.now(timezone.utc) - timedelta(minutes=5),
        end_time=datetime.now(timezone.utc),
        errors="timeout on port 443\n",
    )
    session.add(current_scan)
    session.flush()
    session.add_all([
        Subdomain(scan_id=current_scan.id, domain="api.contract.example.com", is_live=1, ip="0.0.0.0"),
        Port(scan_id=current_scan.id, host="api.contract.example.com", port=443, protocol="tcp", service="https", state="open"),
        Vulnerability(
            scan_id=current_scan.id,
            name="Exposed Admin Panel",
            type="exposed_panel",
            severity="high",
            host="api.contract.example.com",
            path="/admin",
            param=None,
            description="Admin panel reachable without auth",
            payload="GET /admin",
            evidence="raw evidence block",
            status="open",
            cvss=8.8,
        ),
    ])
    session.commit()

    exporter = NormalizedExporter(session)
    result = exporter.export_scan(
        session_id="scan-current",
        target="contract.example.com",
        include_diff=True,
        previous_session_id="scan-prev",
    )

    assert result.type == "scan-result"
    assert result.target == "contract.example.com"
    assert result.assets[0].value == "api.contract.example.com"
    assert result.services[0].port == 443
    assert result.findings[0].name == "Exposed Admin Panel"
    assert any(item.content == "raw evidence block" for item in result.findings[0].evidence)
    assert result.errors == ["timeout on port 443"]
    assert result.stats["subdomains_found"] == 0
    assert result.stats["findings"] == 0
    assert any(diff.category == "asset" and diff.type == "new" for diff in result.diff)
    assert any(diff.category == "finding" and diff.type == "new" for diff in result.diff)

    session.close()


def test_save_json_writes_inside_repo_runtime(tmp_path):
    session = _make_session()
    exporter = NormalizedExporter(session)
    exporter.output_dir = tmp_path / "exports"

    result = exporter.export_scan("missing-session", "contract.example.com")
    output_path = exporter.save_json(result)

    assert "exports" in str(output_path)
    assert output_path.exists()

    session.close()
