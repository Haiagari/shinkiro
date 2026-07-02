from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

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


def test_export_scan_minimal_omits_all_data():
    session = _make_session()
    target = Target(domain="minimal.example.com")
    session.add(target)
    session.flush()
    scan = Scan(
        target_id=target.id,
        session_id="minimal-scan",
        status="completed",
        mode="hunt",
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
    )
    session.add(scan)
    session.flush()
    session.add(Subdomain(scan_id=scan.id, domain="api.minimal.example.com", is_live=1, ip="1.2.3.4"))
    session.commit()

    exporter = NormalizedExporter(session)
    result = exporter.export_scan(
        session_id="minimal-scan",
        target="minimal.example.com",
        minimal=True,
    )

    assert result.assets == []
    assert result.services == []
    assert result.findings == []
    assert result.diff == []
    assert result.config.get("quiet") is True
    session.close()


def test_save_markdown_writes_file(tmp_path):
    session = _make_session()
    exporter = NormalizedExporter(session)
    exporter.output_dir = tmp_path / "exports"

    result = exporter.export_scan("missing-session", "example.com")
    md_path = exporter.save_markdown(result)

    assert md_path.exists()
    assert md_path.suffix == ".md"
    content = md_path.read_text()
    assert "example.com" in content
    assert "PromptWall Scan Report" in content
    session.close()


def test_export_scan_no_db_session_returns_empty_result():
    exporter = NormalizedExporter(db_session=None)
    result = exporter.export_scan("no-db-session", "example.com")

    assert result.session_id == "no-db-session"
    assert result.target == "example.com"
    assert result.assets == []
    assert result.services == []
    assert result.findings == []


def test_asset_from_subdomain_includes_metadata():
    subdomain = Subdomain(
        domain="api.test.example.com",
        is_live=1,
        ip="10.0.0.1",
        http_status=200,
        title="Test API",
        web_server="nginx",
        technologies=["nginx:1.21", "python"],
        asn=12345,
        asn_organization="Test Corp",
        cloud_provider="aws",
        env_tag="prod",
        semantic_labels=["api", "critical"],
        business_impact="HIGH",
        cname="elb.test.example.com",
    )
    exporter = NormalizedExporter()
    asset = exporter._asset_from_subdomain(subdomain)

    assert asset.type == "subdomain"
    assert asset.value == "api.test.example.com"
    assert asset.is_live is True
    assert asset.ip == "10.0.0.1"
    assert asset.http_status == 200
    assert asset.title == "Test API"
    assert asset.web_server == "nginx"
    assert asset.technologies == ["nginx:1.21", "python"]
    assert asset.metadata["asn"] == 12345
    assert asset.metadata["asn_organization"] == "Test Corp"
    assert asset.metadata["cloud_provider"] == "aws"
    assert asset.metadata["env_tag"] == "prod"
    assert asset.metadata["semantic_labels"] == ["api", "critical"]
    assert asset.metadata["business_impact"] == "HIGH"
    assert asset.metadata["cname"] == "elb.test.example.com"


def test_compute_diff_detects_finding_severity_change():
    class MockVuln:
        def __init__(self, name, type, host, path, param, severity, status, cvss):
            self.name = name
            self.type = type
            self.host = host
            self.path = path
            self.param = param
            self.severity = severity
            self.status = status
            self.cvss = cvss

    class MockScan:
        def __init__(self, subdomains, ports, vulnerabilities):
            self.subdomains = subdomains
            self.ports = ports
            self.vulnerabilities = vulnerabilities

    prev_scan = MockScan(
        subdomains=[SimpleNamespace(domain="api.example.com")],
        ports=[],
        vulnerabilities=[MockVuln("XSS", "xss", "api.example.com", "/search", "q", "medium", "open", 5.0)],
    )
    curr_scan = MockScan(
        subdomains=[SimpleNamespace(domain="api.example.com")],
        ports=[],
        vulnerabilities=[MockVuln("XSS", "xss", "api.example.com", "/search", "q", "high", "open", 7.5)],
    )

    exporter = NormalizedExporter()
    diffs = exporter._compute_diff(curr_scan, prev_scan)

    changed = [d for d in diffs if d.type == "changed"]
    assert len(changed) == 1
    assert changed[0].category == "finding"
    assert "XSS" in changed[0].old_value
    assert "XSS" in changed[0].new_value


def test_generate_markdown_with_findings():
    from src.export.schema import ScanResult, Finding, Asset, Diff

    result = ScanResult(
        session_id="md-test",
        target="example.com",
        timestamp="2026-06-01T00:00:00",
        stats={"subdomains_found": 5, "hosts_alive": 3, "ports_found": 10, "findings": 2},
    )
    result.assets = [Asset(type="subdomain", value="api.example.com", is_live=True)]
    result.findings = [Finding(name="SQL Injection", type="sqli", severity="critical", url="http://example.com/sqli")]
    result.diff = [Diff(type="new", category="asset", new_value="api.example.com")]

    exporter = NormalizedExporter()
    md = exporter._generate_markdown(result)

    assert "example.com" in md
    assert "SQL Injection" in md
    assert "CRITICAL" in md
    assert "api.example.com" in md
